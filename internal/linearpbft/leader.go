package linearpbft

import (
	"context"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// SendPrePrepare sends a preprepare message to all nodes
func (n *LinearPBFTNode) SendPrePrepare(signedPreprepare *pb.SignedPrePrepareMessage, sequenceNum int64) ([]*pb.SignedPrepareMessage, error) {
	preprepare := signedPreprepare.Message

	// Add preprepare message to log record
	record := n.LogRecords[sequenceNum]
	if record == nil {
		log.Fatal("Leader tried to preprepare a sequence number that is not in the log record")
	}
	request := record.Request

	// Multicast preprepare message to all nodes
	responseCh := make(chan *pb.SignedPrepareMessage, len(n.Peers))
	log.Infof("Sending preprepare (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(request))
	wg := sync.WaitGroup{}
	for _, peer := range n.Peers {
		wg.Go(func() {
			signedPrepareMsg, err := (*peer.Client).PrePrepareRequest(context.Background(), signedPreprepare)
			if err != nil {
				// log.Fatal(err)
				return
			}
			responseCh <- signedPrepareMsg
		})
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Add leader's own prepare message
	signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  preprepare.ViewNumber,
		SequenceNum: preprepare.SequenceNum,
		Digest:      preprepare.Digest,
		NodeID:      n.ID,
	}
	signedPrepareMsgs = append(signedPrepareMsgs, &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: crypto.Sign(prepareMessage, n.PrivateKey),
	})

	// Collect 2f + 1 matching prepare messages including self
	// Note: leader is attaching his own prepare message to comply with TSS
	for range len(n.Peers) {
		signedPrepareMsg := <-responseCh
		if signedPrepareMsg == nil || signedPrepareMsg.Message == nil {
			continue
		}

		// Verify signature
		ok := crypto.Verify(signedPrepareMsg.Message, n.Peers[signedPrepareMsg.Message.NodeID].PublicKey, signedPrepareMsg.Signature)
		if !ok {
			continue
		}

		// Check if the prepare message matches preprepare message
		if signedPrepareMsg.Message.ViewNumber != preprepare.ViewNumber ||
			signedPrepareMsg.Message.SequenceNum != preprepare.SequenceNum ||
			!cmp.Equal(signedPrepareMsg.Message.Digest, preprepare.Digest) {
			continue
		}

		// Add to signed prepare messages
		signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMsg)

		// If 2f + 1 (n - f) matching prepare messages are collected, then return the signed prepare messages
		if len(signedPrepareMsgs) == int(n.N-n.F) {
			log.Infof("Verified prepare messages for sequence number %d", sequenceNum)
			log.Infof("Prepare messages collected for sequence number %d", sequenceNum)
			record.AddPrepareMessages(signedPrepareMsgs)
			return signedPrepareMsgs, nil
		}
	}
	log.Infof("Prepare messages not collected for sequence number %d", sequenceNum)
	return nil, nil
}

// SendPrepare sends a prepare message to all nodes
func (n *LinearPBFTNode) SendPrepare(signedPrepareMessages []*pb.SignedPrepareMessage, sequenceNum int64) ([]*pb.SignedCommitMessage, error) {
	// Get record from log record
	n.Mutex.Lock()
	record := n.LogRecords[sequenceNum]
	if record == nil || !record.IsPrePrepared() {
		log.Fatal("Log record is not preprepared")
	}

	// Add to prepared log
	record.AddPrepareMessages(signedPrepareMessages)
	n.Mutex.Unlock()

	// Create collected signed prepare message
	collectedSignedPrepareMessage := &pb.CollectedSignedPrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		Messages:    signedPrepareMessages,
	}

	// Multicast prepare message to all nodes
	responseCh := make(chan *pb.SignedCommitMessage, len(n.Peers))
	log.Infof("Sending prepare message for sequence number %d", sequenceNum)
	wg := sync.WaitGroup{}
	for _, peer := range n.Peers {
		wg.Go(func() {
			if (peer.ID == "n2" && sequenceNum == 2) || (peer.ID == "n3" && sequenceNum == 6) || (peer.ID == "n4" && sequenceNum == 7) {
				time.Sleep(2 * time.Second)
			}
			signedCommitMsg, err := (*peer.Client).PrepareRequest(context.Background(), collectedSignedPrepareMessage)
			if err != nil {
				// log.Fatal(err)
				return
			}
			responseCh <- signedCommitMsg
		})
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Create signed commit messages including self
	signedCommitMsgs := make([]*pb.SignedCommitMessage, 0)
	commitMessage := &pb.CommitMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		NodeID:      n.ID,
	}
	signedCommitMsgs = append(signedCommitMsgs, &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: crypto.Sign(commitMessage, n.PrivateKey),
	})

	// Collect 2f + 1 matching commit messages including self
	for range len(n.Peers) {
		signedCommitMsg := <-responseCh
		if signedCommitMsg == nil || signedCommitMsg.Message == nil {
			continue
		}

		// Verify signature
		// log.Infof("Signed commit message: %s", signedCommitMsg.Message.String())
		ok := crypto.Verify(signedCommitMsg.Message, n.Peers[signedCommitMsg.Message.NodeID].PublicKey, signedCommitMsg.Signature)
		if !ok {
			continue
		}

		// Check if the commit message matches prepare message
		if signedCommitMsg.Message.ViewNumber != record.ViewNumber ||
			signedCommitMsg.Message.SequenceNum != record.SequenceNum ||
			!cmp.Equal(signedCommitMsg.Message.Digest, record.Digest) {
			continue
		}

		// Add to signed commit messages
		signedCommitMsgs = append(signedCommitMsgs, signedCommitMsg)

		// If 2f + 1 (n - f) matching commit messages are collected, then return the signed commit messages
		if len(signedCommitMsgs) == int(n.N-n.F) {
			log.Infof("Verified commit messages for sequence number %d", sequenceNum)
			log.Infof("Collected commit message for sequence number %d", sequenceNum)
			return signedCommitMsgs, nil
		}
	}
	log.Infof("Commit messages not collected for sequence number %d", sequenceNum)
	return nil, nil
}

// SendCommit sends a commit message to all nodes
func (n *LinearPBFTNode) SendCommit(signedCommitMessages []*pb.SignedCommitMessage, sequenceNum int64) error {
	// Get record from log record
	n.Mutex.Lock()
	record := n.LogRecords[sequenceNum]
	if record == nil || !record.IsPrepared() {
		log.Fatal("Log record is not prepared")
	}

	// Add to committed log
	record.AddCommitMessages(signedCommitMessages)
	n.Mutex.Unlock()

	// Create collected signed commit message
	collectedSignedCommitMessage := &pb.CollectedSignedCommitMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		Messages:    signedCommitMessages,
	}

	// Multicast commit message to all nodes
	log.Infof("Sending commit message for sequence number %d", sequenceNum)
	for _, peer := range n.Peers {
		go func() {
			_, err := (*peer.Client).CommitRequest(context.Background(), collectedSignedCommitMessage)
			if err != nil {
				// log.Fatal(err)
				return
			}
		}()
	}

	return nil
}
