package linearpbft

import (
	"context"
	"errors"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// SendPrePrepareToNode sends a preprepare message to a node and returns the signed prepare message from the node
func (n *LinearPBFTNode) SendPrePrepareToNode(signedPreprepareMessage *pb.SignedPrePrepareMessage, nodeID string) (*pb.SignedPrepareMessage, error) {
	prePrepareMessage := signedPreprepareMessage.Message

	// request := n.State.TransactionMap.Get(prePrepareMessage.Digest)

	// Byzantine node behavior: dark attack
	// if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
	// 	// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
	// 	return
	// }
	// // Byzantine node behavior: time attack
	// if n.Byzantine && n.TimeAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing time attack", peer.ID)
	// 	time.Sleep(TimeAttackDelay)
	// }
	// // // Byzantine node behavior: equivocation attack
	// if n.Byzantine && n.EquivocationAttack && !slices.Contains(n.EquivocationAttackNodes, peer.ID) {
	// 	log.Infof("Node %s is Byzantine and is performing malicious attack on node %s", n.ID, peer.ID)
	// 	signedMessage = n.CreateMessageWithInvalidSequenceNumber(signedMessage)
	// }
	signedPrepareMsg, err := (*n.Handler.peers[nodeID].Client).PrePrepareRequest(context.Background(), signedPreprepareMessage)
	if err != nil {
		return nil, err
	}
	if signedPrepareMsg == nil || signedPrepareMsg.Message == nil {
		return nil, errors.New("signed prepare message is nil")
	}

	// Verify signature
	ok := crypto.Verify(signedPrepareMsg.Message, n.Handler.peers[nodeID].PublicKey1, signedPrepareMsg.Signature)
	if !ok {
		return nil, errors.New("invalid signature")
	}

	// Check if the prepare message matches preprepare message
	if signedPrepareMsg.Message.ViewNumber != prePrepareMessage.ViewNumber ||
		signedPrepareMsg.Message.SequenceNum != prePrepareMessage.SequenceNum ||
		!cmp.Equal(signedPrepareMsg.Message.Digest, prePrepareMessage.Digest) {
		return nil, errors.New("invalid prepare message")
	}

	// Return the signed prepare message
	return signedPrepareMsg, nil
}

// SendPrepareToNode sends a prepare message to a node and returns the signed commit message from the node
func (n *LinearPBFTNode) SendPrepareToNode(signedPrepareMessage *pb.SignedPrepareMessage, nodeID string) (*pb.SignedCommitMessage, error) {
	prepareMessage := signedPrepareMessage.Message

	// request := n.State.TransactionMap.Get(prepareMessage.Digest)
	// Byzantine node behavior: dark attack
	// if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
	// 	// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
	// 	return
	// }
	// // Byzantine node behavior: time attack
	// if n.Byzantine && n.TimeAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing time attack", peer.ID)
	// 	time.Sleep(TimeAttackDelay)
	// }

	signedCommitMsg, err := (*n.Handler.peers[nodeID].Client).PrepareRequest(context.Background(), signedPrepareMessage)
	if err != nil {
		return nil, err
	}
	if signedCommitMsg == nil || signedCommitMsg.Message == nil {
		return nil, errors.New("signed commit message is nil")
	}

	// Verify signature
	ok := crypto.Verify(signedCommitMsg.Message, n.Handler.peers[nodeID].PublicKey1, signedCommitMsg.Signature)
	if !ok {
		return nil, errors.New("invalid signature")
	}

	// Check if the commit message matches prepare message
	if signedCommitMsg.Message.ViewNumber != prepareMessage.ViewNumber ||
		signedCommitMsg.Message.SequenceNum != prepareMessage.SequenceNum ||
		!cmp.Equal(signedCommitMsg.Message.Digest, prepareMessage.Digest) {
		return nil, errors.New("invalid commit message")
	}

	// Return the signed commit message
	return signedCommitMsg, nil
}

// SendCommitToNode sends a commit message to a node
func (n *LinearPBFTNode) SendCommitToNode(signedCommitMessage *pb.SignedCommitMessage, nodeID string) error {
	// request := n.State.TransactionMap.Get(commitMessage.Digest)
	// Byzantine node behavior: dark attack
	// if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
	// 	// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
	// 	return
	// }
	// // Byzantine node behavior: time attack
	// if n.Byzantine && n.TimeAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing time attack", peer.ID)
	// 	time.Sleep(TimeAttackDelay)
	// }

	_, err := (*n.Handler.peers[nodeID].Client).CommitRequest(context.Background(), signedCommitMessage)
	if err != nil {
		return err
	}

	// Return nil
	return nil
}

// SendViewChangeMessageToNode sends a view change message to a node
func (n *LinearPBFTNode) SendViewChangeMessageToNode(signedViewChangeMessage *pb.SignedViewChangeMessage, nodeID string) error {

	_, err := (*n.Handler.peers[nodeID].Client).ViewChangeRequest(context.Background(), signedViewChangeMessage)
	if err != nil {
		return err
	}
	return nil
}
