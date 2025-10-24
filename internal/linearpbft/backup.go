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
	"google.golang.org/protobuf/types/known/emptypb"
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
	prevPreprepare, ok := n.PrePreparedLog[preprepareMessage.SequenceNum]
	if ok && prevPreprepare != nil && !cmp.Equal(prevPreprepare.Digest, preprepareMessage.Digest) {
		n.Mutex.Unlock()
		log.Warnf("Rejected: %s; previously accepted preprepare message with different digest", utils.LoggingString(preprepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "previously accepted preprepare message with different digest")
	}
	n.Mutex.Unlock()

	// Add to preprepare log and transaction map
	n.Mutex.Lock()
	n.PrePreparedLog[preprepareMessage.SequenceNum] = &LogRecord{
		ViewNumber:  preprepareMessage.ViewNumber,
		SequenceNum: preprepareMessage.SequenceNum,
		Digest:      preprepareMessage.Digest,
	}
	n.TransactionMap[utils.To32Bytes(preprepareMessage.Digest)] = request
	log.Infof("Preprepared (v: %d, s: %d): %s", n.ViewNumber, preprepareMessage.SequenceNum, utils.LoggingString(request))
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

	// Get the preprepare record from preprepare log
	n.Mutex.Lock()
	preprepareRecord := n.PrePreparedLog[sequenceNum]
	n.Mutex.Unlock()

	// If no preprepare message found, then ignore the prepare message
	if preprepareRecord == nil {
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
		if prepareMessage.ViewNumber != preprepareRecord.ViewNumber ||
			prepareMessage.SequenceNum != preprepareRecord.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, preprepareRecord.Digest) {
			log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prepareMessage, n.TransactionMap[utils.To32Bytes(prepareMessage.Digest)]))
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	// If verified count is less than 2f then return nil
	if verifiedCount < int(2*n.F) {
		log.Warnf("Ignored: %d; not enough prepare messages (verified: %d)", sequenceNum, verifiedCount)
		return nil, nil
	}

	// Log the prepare message
	n.Mutex.Lock()
	n.PreparedLog[sequenceNum] = &LogRecord{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      preprepareRecord.Digest,
	}
	log.Infof("Prepared (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(n.TransactionMap[utils.To32Bytes(preprepareRecord.Digest)]))
	n.Mutex.Unlock()

	// Create commit message and sign it
	commitMessage := &pb.CommitMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      preprepareRecord.Digest,
		NodeID:      n.ID,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: security.Sign(commitMessage, n.PrivateKey),
	}

	return signedCommitMessage, nil
}

func (n *LinearPBFTNode) Commit(ctx context.Context, signedCommitMessages *pb.CollectedSignedCommitMessage) (*emptypb.Empty, error) {
	viewNumber := signedCommitMessages.ViewNumber
	sequenceNum := signedCommitMessages.SequenceNum

	// Verify View Number
	if viewNumber != n.ViewNumber {
		return nil, nil
	}

	// Get the prepared record from prepared log
	n.Mutex.Lock()
	preparedRecord := n.PreparedLog[sequenceNum]
	n.Mutex.Unlock()

	// If no prepare message found, then ignore the commit message
	if preparedRecord == nil {
		log.Warnf("Ignored: %d; no prepared message found", sequenceNum)
		return nil, nil
	}

	// Verify Commit Messages
	verifiedCount := 0
	for _, signedCommitMessage := range signedCommitMessages.Messages {
		if signedCommitMessage == nil {
			log.Fatal("Signed commit message is nil")
		}
		commitMessage := signedCommitMessage.Message

		// Verify Signature
		var publicKey []byte
		log.Debug(commitMessage.String())
		if commitMessage.NodeID == n.ID {
			publicKey = n.PublicKey
		} else {
			publicKey = n.Peers[commitMessage.NodeID].PublicKey
		}
		ok := security.Verify(commitMessage, publicKey, signedCommitMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(commitMessage, n.TransactionMap[utils.To32Bytes(commitMessage.Digest)]))
			continue
		}

		// Check if the commit message matches prepare message
		if commitMessage.ViewNumber != preparedRecord.ViewNumber ||
			commitMessage.SequenceNum != preparedRecord.SequenceNum ||
			!cmp.Equal(commitMessage.Digest, preparedRecord.Digest) {
			log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(commitMessage, n.TransactionMap[utils.To32Bytes(commitMessage.Digest)]))
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	// If verified count is less than 2f + 1 then return nil
	if verifiedCount < int(2*n.F+1) {
		log.Warnf("Not enough commit messages to commit message (v: %d, s: %d)", n.ViewNumber, sequenceNum)
		return nil, nil
	}

	// Log the commit message
	n.Mutex.Lock()
	n.CommittedLog[sequenceNum] = &LogRecord{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      preparedRecord.Digest,
	}
	log.Infof("Committed (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(n.TransactionMap[utils.To32Bytes(preparedRecord.Digest)]))
	n.Mutex.Unlock()

	// Execute transaction
	go n.TryExecute(sequenceNum)

	return &emptypb.Empty{}, nil
}
