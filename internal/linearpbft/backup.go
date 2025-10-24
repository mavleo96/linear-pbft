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
	// TODO: acquire lock on view number
	if preprepareMessage.ViewNumber != n.ViewNumber {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(preprepareMessage, request), n.ViewNumber)
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify Node's signature
	currentLeaderID := n.ViewNumberToLeader(n.ViewNumber)
	ok := security.Verify(preprepareMessage, n.Peers[currentLeaderID].PublicKey, signedMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(preprepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid signature")
	}

	// Verify Digest
	if !cmp.Equal(preprepareMessage.Digest, security.Digest(request)) {
		log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(preprepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest")
	}

	// Verify if previously accepted preprepare message with different digest
	n.Mutex.Lock()
	prevPreprepare, ok := n.PrePrepareLog[preprepareMessage.SequenceNum]
	if ok && prevPreprepare != nil && !cmp.Equal(prevPreprepare.Digest, preprepareMessage.Digest) {
		n.Mutex.Unlock()
		log.Warnf("Rejected: %s; previously accepted preprepare message with different digest", utils.LoggingString(preprepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "previously accepted preprepare message with different digest")
	}
	n.Mutex.Unlock()

	// Add to preprepare log and transaction map
	n.Mutex.Lock()
	n.PrePrepareLog[preprepareMessage.SequenceNum] = preprepareMessage
	n.TransactionMap[utils.To32Bytes(preprepareMessage.Digest)] = request
	log.Infof("Logged: %s", utils.LoggingString(preprepareMessage, request))
	n.Mutex.Unlock()

	// Create prepare message and sign it
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  preprepareMessage.ViewNumber,
		SequenceNum: preprepareMessage.SequenceNum,
		Digest:      preprepareMessage.Digest,
		NodeID:      n.ID,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: security.Sign(prepareMessage, n.PrivateKey),
	}

	return signedPrepareMessage, nil
}

func (n *LinearPBFTNode) Prepare(ctx context.Context, signedPrepareMessages *pb.CollectedSignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	viewNumber := signedPrepareMessages.ViewNumber
	sequenceNum := signedPrepareMessages.SequenceNum

	// Verify View Number
	if viewNumber != n.ViewNumber {
		// log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedPrepareMessages, n.TransactionMap[utils.To32Bytes(signedPrepareMessages.Digest)]), n.ViewNumber)
		// return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
		return nil, nil
	}

	// Get the preprepare message
	n.Mutex.Lock()
	preprepareMessage := n.PrePrepareLog[sequenceNum]
	n.Mutex.Unlock()

	// If no preprepare message found, then ignore the prepare message
	if preprepareMessage == nil {
		log.Warnf("Ignored: %d; no preprepare message found", sequenceNum)
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
		ok := security.Verify(prepareMessage, publicKey, signedPrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prepareMessage, n.TransactionMap[utils.To32Bytes(prepareMessage.Digest)]))
			continue
		}

		// Check if the prepare message matches preprepare message
		if !cmp.Equal(prepareMessage.Digest, preprepareMessage.Digest) {
			log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prepareMessage, n.TransactionMap[utils.To32Bytes(prepareMessage.Digest)]))
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	// If verified count is less than 2f then return nil
	if verifiedCount < 2*n.F {
		log.Warnf("Ignored: %d; not enough prepare messages (verified: %d)", sequenceNum, verifiedCount)
		return nil, nil
	}

	// Log the prepare message
	n.Mutex.Lock()
	n.PrepareLog[sequenceNum] = &pb.PrepareMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      preprepareMessage.Digest,
		NodeID:      n.ID,
	}
	log.Infof("Logged: %s", utils.LoggingString(n.PrepareLog[sequenceNum], n.TransactionMap[utils.To32Bytes(preprepareMessage.Digest)]))
	n.Mutex.Unlock()

	// Create commit message and sign it
	commitMessage := &pb.CommitMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      preprepareMessage.Digest,
		NodeID:      n.ID,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: security.Sign(commitMessage, n.PrivateKey),
	}

	return signedCommitMessage, nil
}
