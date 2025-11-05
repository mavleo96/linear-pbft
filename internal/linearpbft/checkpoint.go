package linearpbft

import (
	"context"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type CheckpointLog struct {
	Mutex                     sync.RWMutex
	LastCheckPointSequenceNum int64
	Log                       map[int64]map[string]*pb.SignedCheckPointMessage // s -> (id -> msg)
	Quorum                    int64                                            // 2f + 1
}

// GetStableCheckpointSequenceNum gets the stable checkpoint sequence number
func (c *CheckpointLog) GetStableCheckpointSequenceNum() int64 {
	c.Mutex.RLock()
	defer c.Mutex.RUnlock()
	stableSequenceNum := int64(0)
	for sequenceNum := range c.Log {
		if len(c.Log[sequenceNum]) == int(c.Quorum) && sequenceNum > stableSequenceNum {
			stableSequenceNum = sequenceNum
		}
	}
	return stableSequenceNum
}

// AddMessage adds a message to the log
func (c *CheckpointLog) AddMessage(sequenceNum int64, nodeID string, signedCheckPointMessage *pb.SignedCheckPointMessage) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if _, ok := c.Log[sequenceNum]; !ok {
		c.Log[sequenceNum] = make(map[string]*pb.SignedCheckPointMessage)
	}
	c.Log[sequenceNum][nodeID] = signedCheckPointMessage
}

// GetMessages gets the messages for a given sequence number
func (c *CheckpointLog) GetMessages(sequenceNum int64) []*pb.SignedCheckPointMessage {
	c.Mutex.RLock()
	defer c.Mutex.RUnlock()
	return utils.Values(c.Log[sequenceNum])
}

// GetLastCheckPointSequenceNum gets the last check point sequence number
func (c *CheckpointLog) GetLastCheckPointSequenceNum() int64 {
	c.Mutex.RLock()
	defer c.Mutex.RUnlock()
	return c.LastCheckPointSequenceNum
}

// SetLastCheckPointSequenceNum sets the last check point sequence number
func (c *CheckpointLog) SetLastCheckPointSequenceNum(sequenceNum int64) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	c.LastCheckPointSequenceNum = sequenceNum
}

// SendCheckPointRequest sends a check point request to all nodes
func (n *LinearPBFTNode) SendCheckPointRequest(ctx context.Context, sequenceNum int64) (*emptypb.Empty, error) {
	n.Mutex.RLock()
	defer n.Mutex.RUnlock()

	// Fetch log record between low and high water mark
	logRecords := make([]*LogRecord, 0)
	for i := sequenceNum - n.config.k + 1; i <= sequenceNum; i++ {
		record, exists := n.State.StateLog.Get(i)
		if !exists {
			continue
		}
		logRecords = append(logRecords, record)
	}

	// Create checkpoint Digest
	checkpointDigest := crypto.DigestAny(logRecords)

	// Create check point message and sign it
	checkPointMessage := &pb.CheckPointMessage{
		SequenceNum: sequenceNum,
		Digest:      checkpointDigest,
		NodeID:      n.ID,
	}
	signedCheckPointMessage := &pb.SignedCheckPointMessage{
		Message:   checkPointMessage,
		Signature: crypto.Sign(checkPointMessage, n.PrivateKey),
	}

	// Add check point message to check point message log
	n.CheckPointLog.AddMessage(sequenceNum, n.ID, signedCheckPointMessage)
	log.Infof("Added check point message to check point message log for sequence number %d from node %s", sequenceNum, n.ID)

	// Multicast check point message to all nodes
	log.Infof("Sending check point message for sequence number %d to all nodes", sequenceNum)
	for _, peer := range n.Peers {
		go (*peer.Client).CheckPointRequest(context.Background(), signedCheckPointMessage)
	}

	return &emptypb.Empty{}, nil
}

// CheckPointRequest handles incoming check point requests from nodes
func (n *LinearPBFTNode) CheckPointRequest(ctx context.Context, signedCheckPointMessage *pb.SignedCheckPointMessage) (*emptypb.Empty, error) {
	checkPointMessage := signedCheckPointMessage.Message

	// Verify signature
	ok := crypto.Verify(checkPointMessage, n.GetPublicKey(checkPointMessage.NodeID), signedCheckPointMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(checkPointMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Add check point message to check point message log
	n.CheckPointLog.AddMessage(checkPointMessage.SequenceNum, checkPointMessage.NodeID, signedCheckPointMessage)

	// Signal the checkpoint routine if 2f + 1 check point messages are collected
	if len(n.CheckPointLog.GetMessages(checkPointMessage.SequenceNum)) == int(n.N-n.F) {
		log.Infof("Received 2f + 1 check point messages for sequence number %d", checkPointMessage.SequenceNum)
		n.CheckPointRoutineCh <- true
	}

	return &emptypb.Empty{}, nil
}

func (n *LinearPBFTNode) CheckPointRoutine(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Infof("Checkpoint routine received exit signal")
			return
		case <-n.CheckPointRoutineCh:
			log.Infof("Received signal to start checkpoint routine")

			// Send check point request to all nodes
			lastCheckPointSequenceNum := n.CheckPointLog.GetLastCheckPointSequenceNum()
			if lastCheckPointSequenceNum+n.config.k <= n.State.GetLastExecutedSequenceNum() {
				n.SendCheckPointRequest(context.Background(), lastCheckPointSequenceNum+n.config.k)
				n.CheckPointLog.SetLastCheckPointSequenceNum(lastCheckPointSequenceNum + n.config.k)
			}

			// Check if 2f + 1 check point messages are collected
			if len(n.CheckPointLog.GetMessages(n.config.lowWaterMark+n.config.k)) >= int(n.N-n.F) {
				// Create checkpoint Digest
				n.Mutex.RLock()
				records := make([]*LogRecord, 0)
				for i := n.config.lowWaterMark + 1; i <= n.config.lowWaterMark+n.config.k; i++ {
					record, exists := n.State.StateLog.Get(i)
					if !exists {
						continue
					}
					records = append(records, record)
				}
				n.Mutex.RUnlock()
				checkpointDigest := crypto.DigestAny(records)

				// Verify the digest on check point messages
				verifiedCount := 0
				for _, checkPointMessage := range n.CheckPointLog.GetMessages(n.config.lowWaterMark + n.config.k) {
					if cmp.Equal(checkPointMessage.Message.Digest, checkpointDigest) {
						verifiedCount++
					}
				}
				if verifiedCount < int(n.N-n.F) {
					log.Warnf("Check point digest not verified for sequence number %d", n.config.lowWaterMark+n.config.k)
					continue
				}
			} else {
				log.Warnf("Not enough check point messages collected for sequence number %d", n.config.lowWaterMark+n.config.k)
				continue
			}

			// Update low and high water mark and purge log records
			log.Infof("Updating low and high water mark and purging log records for sequence number %d", n.config.lowWaterMark+n.config.k)
			n.config.lowWaterMark += n.config.k
			n.config.highWaterMark += n.config.k
			n.Mutex.Lock()
			// TODO: modify this to check between l-k and l
			for i := range n.State.StateLog.log {
				if i <= n.config.lowWaterMark {
					n.State.StateLog.Delete(i)
				}
			}
			n.Mutex.Unlock()
		}
	}
}
