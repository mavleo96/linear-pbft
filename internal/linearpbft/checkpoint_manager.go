package linearpbft

import (
	"context"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// CheckPointManager is responsible for managing check point messages
type CheckPointManager struct {
	mutex     sync.RWMutex
	log       map[int64]map[string]*pb.SignedCheckPointMessage // s -> (id -> msg)
	digestMap map[int64][]byte                                 // s -> digest

	state  *ServerState
	config *ServerConfig

	// Channels
	checkPointCreateCh  chan int64
	checkPointRequestCh chan int64
}

// GetCheckPointCreateChannel returns the channel to create check point messages
func (c *CheckPointManager) GetCheckPointCreateChannel() chan int64 {
	return c.checkPointCreateCh
}

// AddMessage adds a signed check point message to the log
func (c *CheckPointManager) AddMessage(sequenceNum int64, nodeID string, signedCheckPointMessage *pb.SignedCheckPointMessage) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, ok := c.log[sequenceNum]; !ok {
		c.log[sequenceNum] = make(map[string]*pb.SignedCheckPointMessage)
	}
	c.log[sequenceNum][nodeID] = signedCheckPointMessage
}

// GetMessages gets the signed check point messages for a given sequence number
func (c *CheckPointManager) GetMessages(sequenceNum int64) []*pb.SignedCheckPointMessage {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return utils.Values(c.log[sequenceNum])
}

// DeleteMessages deletes the signed check point messages for a given sequence number
func (c *CheckPointManager) DeleteMessages(sequenceNum int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.log, sequenceNum)
}

// AddDigest adds a digest for a given sequence number to the digest map
func (c *CheckPointManager) AddDigest(sequenceNum int64, digest []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.digestMap[sequenceNum] = digest
}

// GetDigest gets the digest for a given sequence number
func (c *CheckPointManager) GetDigest(sequenceNum int64) []byte {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.digestMap[sequenceNum]
}

// DeleteDigests deletes the digests for a given sequence number
func (c *CheckPointManager) DeleteDigests(sequenceNum int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.digestMap, sequenceNum)
}

// CheckPointRoutine is the routine that handles check point messages
func (c *CheckPointManager) CheckPointRoutine(ctx context.Context) {
checkPointingLoop:
	for {
		select {
		case <-ctx.Done():
			log.Infof("Checkpoint routine received exit signal")
			return

		case sequenceNum := <-c.checkPointRequestCh:
			log.Infof("Received signal to start check point routine for sequence number %d", sequenceNum)

			// Create checkpoint digest and verify the digest on check point messages
			checkpointDigest := c.GetDigest(sequenceNum)
			verifiedCount := 0
			for _, checkPointMessage := range c.GetMessages(sequenceNum) {
				if cmp.Equal(checkPointMessage.Message.Digest, checkpointDigest) {
					verifiedCount++
				}
			}
			if verifiedCount < int(2*c.config.F+1) {
				log.Warnf("Check point digest not verified for sequence number %d", sequenceNum)
				continue checkPointingLoop
			}

			// Update low and high water mark and purge log records
			log.Infof("Purging logs for sequence number %d", sequenceNum)
			for i := c.config.LowWaterMark; i <= sequenceNum; i++ {
				c.state.StateLog.Delete(i)
			}
			delta := sequenceNum - c.config.LowWaterMark
			c.config.LowWaterMark += delta
			c.config.HighWaterMark += delta
			log.Infof("Updated low and high water mark to %d and %d", c.config.LowWaterMark, c.config.HighWaterMark)

			// Delete check point messages, digests, and snapshots older than low water mark
			for i := range c.log {
				if i < c.config.LowWaterMark {
					c.DeleteMessages(i)
				}
			}
			for i := range c.digestMap {
				if i < c.config.LowWaterMark {
					c.DeleteDigests(i)
				}
			}
		}
	}
}
