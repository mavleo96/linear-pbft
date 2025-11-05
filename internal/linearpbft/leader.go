package linearpbft

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SendPrePrepare sends a preprepare message to all nodes
func (n *LinearPBFTNode) SendPrePrepare(signedPreprepareMessage *pb.SignedPrePrepareMessage, sequenceNum int64) ([]*pb.SignedPrepareMessage, error) {
	prePrepareMessage := signedPreprepareMessage.Message

	// Add preprepare message to log record
	// record := n.LogRecords[sequenceNum]
	// if record == nil {
	// 	log.Fatal("Leader tried to preprepare a sequence number that is not in the log record")
	// }
	record, _ := n.State.StateLog.Get(sequenceNum)
	request := n.State.TransactionMap.Get(prePrepareMessage.Digest)

	// Multicast preprepare message to all nodes
	responseCh := make(chan *pb.SignedPrepareMessage, len(n.Peers))
	log.Infof("Sending preprepare (v: %d, s: %d): %s", n.State.GetViewNumber(), sequenceNum, utils.LoggingString(request))
	wg := sync.WaitGroup{}
	for _, peer := range n.Peers {
		wg.Add(1)
		go func(peer *models.Node, signedMessage *pb.SignedPrePrepareMessage) {
			defer wg.Done()
			// Byzantine node behavior: dark attack
			if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
				// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
				return
			}
			// Byzantine node behavior: time attack
			if n.Byzantine && n.TimeAttack {
				// log.Infof("Node %s is Byzantine and is performing time attack", peer.ID)
				time.Sleep(TimeAttackDelay)
			}
			// // Byzantine node behavior: equivocation attack
			// if n.Byzantine && n.EquivocationAttack && !slices.Contains(n.EquivocationAttackNodes, peer.ID) {
			// 	log.Infof("Node %s is Byzantine and is performing malicious attack on node %s", n.ID, peer.ID)
			// 	signedMessage = n.CreateMessageWithInvalidSequenceNumber(signedMessage)
			// }
			signedPrepareMsg, err := (*peer.Client).PrePrepareRequest(context.Background(), signedMessage)
			if err != nil {
				// log.Fatal(err)
				return
			}
			responseCh <- signedPrepareMsg
		}(peer, signedPreprepareMessage)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Add leader's own prepare message
	signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  prePrepareMessage.ViewNumber,
		SequenceNum: prePrepareMessage.SequenceNum,
		Digest:      prePrepareMessage.Digest,
		NodeID:      n.ID,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: crypto.Sign(prepareMessage, n.PrivateKey),
	}
	// Byzantine node behavior: sign attack
	if n.Byzantine && n.SignAttack {
		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
		signedPrepareMessage.Signature = []byte("invalid signature")
	}
	signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMessage)

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
		if signedPrepareMsg.Message.ViewNumber != prePrepareMessage.ViewNumber ||
			signedPrepareMsg.Message.SequenceNum != prePrepareMessage.SequenceNum ||
			!cmp.Equal(signedPrepareMsg.Message.Digest, prePrepareMessage.Digest) {
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
	record, _ := n.State.StateLog.Get(sequenceNum)
	if record == nil || !record.IsPrePrepared() {
		log.Fatal("Log record is not preprepared")
	}

	// Add to prepared log
	record.AddPrepareMessages(signedPrepareMessages)
	// Byzantine node behavior: crash attack
	if n.Byzantine && n.CrashAttack {
		// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
		record.MaliciousUpdateLogState()
	}
	n.Mutex.Unlock()
	// Byzantine node behavior: crash attack
	if n.Byzantine && n.CrashAttack {
		// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Create collected signed prepare message
	collectedSignedPrepareMessage := &pb.CollectedSignedPrepareMessage{
		ViewNumber:  n.State.GetViewNumber(),
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
			// Byzantine node behavior: dark attack
			if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
				// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
				return
			}
			// Byzantine node behavior: time attack
			if n.Byzantine && n.TimeAttack {
				// log.Infof("Node %s is Byzantine and is performing time attack", peer.ID)
				time.Sleep(TimeAttackDelay)
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
		ViewNumber:  n.State.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		NodeID:      n.ID,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: crypto.Sign(commitMessage, n.PrivateKey),
	}
	// Byzantine node behavior: sign attack
	if n.Byzantine && n.SignAttack {
		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
		signedCommitMessage.Signature = []byte("invalid signature")
	}
	signedCommitMsgs = append(signedCommitMsgs, signedCommitMessage)

	// Collect 2f + 1 matching commit messages including self
	for range len(n.Peers) {
		signedCommitMsg := <-responseCh
		if signedCommitMsg == nil || signedCommitMsg.Message == nil {
			continue
		}

		// Verify signature
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
	record, _ := n.State.StateLog.Get(sequenceNum)
	if record == nil || !record.IsPrepared() {
		log.Fatal("Log record is not prepared")
	}

	// Add to committed log
	record.AddCommitMessages(signedCommitMessages)
	n.Mutex.Unlock()

	// Create collected signed commit message
	collectedSignedCommitMessage := &pb.CollectedSignedCommitMessage{
		ViewNumber:  n.State.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		Messages:    signedCommitMessages,
	}

	// Multicast commit message to all nodes
	log.Infof("Sending commit message for sequence number %d", sequenceNum)
	for _, peer := range n.Peers {
		go func(peer *models.Node) {
			// Byzantine node behavior: dark attack
			if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
				// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
				return
			}
			// Byzantine node behavior: time attack
			if n.Byzantine && n.TimeAttack {
				// log.Infof("Node %s is Byzantine and is performing time attack", peer.ID)
				time.Sleep(TimeAttackDelay)
			}
			_, err := (*peer.Client).CommitRequest(context.Background(), collectedSignedCommitMessage)
			if err != nil {
				return
			}
		}(peer)
	}

	return nil
}
