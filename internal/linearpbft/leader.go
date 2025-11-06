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
)

// SendPrePrepare sends a preprepare message to all nodes
func (n *LinearPBFTNode) SendPrePrepare(signedPreprepareMessage *pb.SignedPrePrepareMessage, sequenceNum int64) error {
	prePrepareMessage := signedPreprepareMessage.Message

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

	// Add primary's own prepare message
	signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  prePrepareMessage.ViewNumber,
		SequenceNum: prePrepareMessage.SequenceNum,
		Digest:      prePrepareMessage.Digest,
		NodeID:      n.ID,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: crypto.Sign(prepareMessage, n.PrivateKey1),
	}
	// Byzantine node behavior: sign attack
	if n.Byzantine && n.SignAttack {
		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
		signedPrepareMessage.Signature = []byte("invalid signature")
	}
	signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMessage)

	// Collect 2f + 1 matching prepare messages including self
	// Note: primary is attaching his own prepare message to comply with TSS
	for range len(n.Peers) {
		signedPrepareMsg := <-responseCh
		if signedPrepareMsg == nil || signedPrepareMsg.Message == nil {
			continue
		}

		// Verify signature
		ok := crypto.Verify(signedPrepareMsg.Message, n.Peers[signedPrepareMsg.Message.NodeID].PublicKey1, signedPrepareMsg.Signature)
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
			n.PrepareCh <- signedPrepareMsgs
			return nil
		}
	}
	log.Infof("Prepare messages not collected for sequence number %d", sequenceNum)
	return nil
}

// SendPrepare sends a prepare message to all nodes
func (n *LinearPBFTNode) SendPrepare(collectedSignedPrepareMessage *pb.CollectedSignedPrepareMessage) error {

	viewNumber := collectedSignedPrepareMessage.ViewNumber
	sequenceNum := collectedSignedPrepareMessage.SequenceNum
	digest := collectedSignedPrepareMessage.Digest

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
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      digest,
		NodeID:      n.ID,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: crypto.Sign(commitMessage, n.PrivateKey1),
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
		ok := crypto.Verify(signedCommitMsg.Message, n.Peers[signedCommitMsg.Message.NodeID].PublicKey1, signedCommitMsg.Signature)
		if !ok {
			continue
		}

		// Check if the commit message matches prepare message
		if signedCommitMsg.Message.ViewNumber != viewNumber ||
			signedCommitMsg.Message.SequenceNum != sequenceNum ||
			!cmp.Equal(signedCommitMsg.Message.Digest, digest) {
			continue
		}

		// Add to signed commit messages
		signedCommitMsgs = append(signedCommitMsgs, signedCommitMsg)

		// If 2f + 1 (n - f) matching commit messages are collected, then return the signed commit messages
		if len(signedCommitMsgs) == int(n.N-n.F) {
			log.Infof("Verified commit messages for sequence number %d", sequenceNum)
			log.Infof("Collected commit message for sequence number %d", sequenceNum)
			n.CommitCh <- signedCommitMsgs
			return nil
		}
	}
	log.Infof("Commit messages not collected for sequence number %d", sequenceNum)
	return nil
}

// SendCommit sends a commit message to all nodes
func (n *LinearPBFTNode) SendCommit(collectedSignedCommitMessage *pb.CollectedSignedCommitMessage) error {

	sequenceNum := collectedSignedCommitMessage.SequenceNum

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
