package linearpbft

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/security"
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
	ok := security.Verify(preprepareMessage.String(), n.Peers[currentLeaderID].PublicKey, signedMessage.Signature)
	if !ok {
		log.Warnf("Invalid signature on preprepare message with sequence number %d in view number %d; request: %v", preprepareMessage.SequenceNum, preprepareMessage.ViewNumber, request.String())
		return nil, status.Errorf(codes.InvalidArgument, "invalid signature")
	}

	// Verify Digest
	if !cmp.Equal(preprepareMessage.Digest, security.Digest(request.String())) {
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
		Signature: security.Sign(prepareMessage.String(), n.PrivateKey),
	}

	return signedPrepareMessage, nil
}
