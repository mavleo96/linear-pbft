package linearpbft

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (n *LinearPBFTNode) PrePrepare(ctx context.Context, signedMessage *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error) {
	preprepareMessage := signedMessage.Message
	request := signedMessage.Request

	// Verify View Number
	if preprepareMessage.ViewNumber != n.ViewNumber {
		log.Warnf("Invalid view number %d; expected %d; request: %v", preprepareMessage.ViewNumber, n.ViewNumber, request.String())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify Node's signature
	currentLeaderID := n.ViewNumberToLeader(n.ViewNumber)
	ok := security.Verify(utils.MessageString(preprepareMessage), n.Peers[currentLeaderID].PublicKey, signedMessage.Signature)
	if !ok {
		log.Warnf("Invalid signature on preprepare message with sequence number %d in view number %d; request: %v", preprepareMessage.SequenceNum, preprepareMessage.ViewNumber, request.String())
		return nil, status.Errorf(codes.InvalidArgument, "invalid signature")
	}

	// Verify Digest
	if !cmp.Equal(preprepareMessage.Digest, security.Digest(utils.MessageString(request))) {
		log.Warnf("Invalid digest on preprepare message with sequence number %d in view number %d; request: %v", preprepareMessage.SequenceNum, preprepareMessage.ViewNumber, request.String())
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest")
	}

	// Verify if previously accepted preprepare message with different digest
	if preprepare, ok := n.PrePrepareLog[preprepareMessage.SequenceNum]; ok && !cmp.Equal(preprepare.Digest, preprepareMessage.Digest) {
		log.Warnf("Previously accepted preprepare message with different digest for sequence number %d in view number %d", preprepareMessage.SequenceNum, preprepareMessage.ViewNumber)
		return nil, status.Errorf(codes.InvalidArgument, "previously accepted preprepare message with different digest")
	}

	// Add to preprepare log
	n.PrePrepareLog[preprepareMessage.SequenceNum] = preprepareMessage
	log.Infof("Preprepared message %d: %s", preprepareMessage.SequenceNum, preprepareMessage.String())

	// Create prepare message and sign it
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  preprepareMessage.ViewNumber,
		SequenceNum: preprepareMessage.SequenceNum,
		Digest:      preprepareMessage.Digest,
		NodeID:      n.ID,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: security.Sign(utils.MessageString(prepareMessage), n.PrivateKey),
	}

	return signedPrepareMessage, nil
}

func (n *LinearPBFTNode) Prepare(ctx context.Context, signedPrepareMessages *pb.CollectedSignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	viewNumber := signedPrepareMessages.ViewNumber
	sequenceNum := signedPrepareMessages.SequenceNum

	// Verify View Number
	if viewNumber != n.ViewNumber {
		log.Warnf("Invalid view number %d; expected %d", viewNumber, n.ViewNumber)
		// return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
		return nil, nil
	}

	// Get the preprepare message
	preprepareMessage := n.PrePrepareLog[sequenceNum]
	if preprepareMessage == nil {
		log.Warnf("No preprepare message found for sequence number %d in view number %d", sequenceNum, viewNumber)
		// return nil, status.Errorf(codes.InvalidArgument, "no preprepare message found")
		return nil, nil
	}

	// Verify Prepare Messages
	verifiedCount := 0
	for _, signedPrepareMessage := range signedPrepareMessages.Messages {
		if signedPrepareMessage == nil {
			log.Fatal("Signed prepare message is nil")
		}
		prepareMessage := signedPrepareMessage.Message

		// Verify Signature
		var publicKey []byte
		if prepareMessage.NodeID == n.ID {
			publicKey = n.PublicKey
		} else {
			publicKey = n.Peers[prepareMessage.NodeID].PublicKey
		}
		ok := security.Verify(utils.MessageString(prepareMessage), publicKey, signedPrepareMessage.Signature)
		if !ok {
			log.Warnf("Invalid signature on prepare message with sequence number %d in view number %d; request: %v", prepareMessage.SequenceNum, prepareMessage.ViewNumber, preprepareMessage.String())
			continue
		}

		// Check if the prepare message matches preprepare message
		if !cmp.Equal(prepareMessage.Digest, preprepareMessage.Digest) {
			log.Warnf("Invalid digest on prepare message with sequence number %d in view number %d; request: %v", prepareMessage.SequenceNum, prepareMessage.ViewNumber, preprepareMessage.String())
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	// If verified count is less than 2f then return nil
	if verifiedCount < 2*n.F {
		log.Warnf("Not enough prepare messages to prepare message %d: %s", sequenceNum, preprepareMessage.String())
		return nil, nil
	}

	// Log the prepare message
	n.PrepareLog[sequenceNum] = &pb.PrepareMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      preprepareMessage.Digest,
		NodeID:      n.ID,
	}
	log.Infof("Prepared message %d: %s", sequenceNum, preprepareMessage.String())

	// Create commit message and sign it
	commitMessage := &pb.CommitMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      preprepareMessage.Digest,
		NodeID:      n.ID,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: security.Sign(utils.MessageString(commitMessage), n.PrivateKey),
	}

	return signedCommitMessage, nil
}
