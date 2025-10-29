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

	// // Verify View Number
	// // TODO: acquire lock on view number
	// if preprepareMessage.ViewNumber != n.ViewNumber {
	// 	log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(preprepareMessage, request), n.ViewNumber)
	// 	return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	// }

	// Ignore if already in view change
	if n.SentViewChange {
		log.Infof("Ignored: %s; already in view change", utils.LoggingString(preprepareMessage, request))
		return nil, nil
	}

	// Verify Node's signature
	currentLeaderID := n.ViewNumberToLeader(n.ViewNumber)
	ok := security.Verify(preprepareMessage, n.Peers[currentLeaderID].PublicKey, signedMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(preprepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid signature")
	}

	// Verify Digest and View Number
	if n.ViewNumber == preprepareMessage.ViewNumber &&
		!cmp.Equal(preprepareMessage.Digest, security.Digest(request)) {
		log.Warnf("Rejected: %s; invalid digest or view number", utils.LoggingString(preprepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest or view number")
	}

	// Verify if previously accepted preprepare message with different digest
	n.Mutex.Lock()
	record, ok := n.LogRecords[preprepareMessage.SequenceNum]
	if ok {
		if record.IsPrePrepared() && !cmp.Equal(record.Digest, preprepareMessage.Digest) {
			log.Warnf("Rejected: %s; previously accepted preprepare message with different digest", utils.LoggingString(preprepareMessage, request))
			return nil, status.Errorf(codes.InvalidArgument, "previously accepted preprepare message with different digest")
		}
		record.AddPrePrepareMessage(signedMessage)
	} else {
		record = CreateLogRecord(preprepareMessage.ViewNumber, preprepareMessage.SequenceNum, security.Digest(request))
		n.LogRecords[preprepareMessage.SequenceNum] = record
		record.AddPrePrepareMessage(signedMessage)

		// Check if the request is in the forwarded requests log
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(security.Digest(forwardedRequest.Request), preprepareMessage.Digest) {
				inForwardedRequestsLog = true
				break
			}
		}
		if !inForwardedRequestsLog {
			n.SafeTimer.IncrementWaitCountOrStart()
		}
	}
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

	go n.TryExecute(preprepareMessage.SequenceNum)

	return signedPrepareMessage, nil
}

func (n *LinearPBFTNode) Prepare(ctx context.Context, signedPrepareMessages *pb.CollectedSignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	viewNumber := signedPrepareMessages.ViewNumber
	sequenceNum := signedPrepareMessages.SequenceNum

	// Ignore if already in view change
	if n.SentViewChange {
		log.Infof("Ignored: %s; already in view change", utils.LoggingString(signedPrepareMessages))
		return nil, nil
	}

	// Verify View Number
	if viewNumber != n.ViewNumber {
		// log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedPrepareMessages, n.TransactionMap[utils.To32Bytes(signedPrepareMessages.Digest)]), n.ViewNumber)
		// return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
		return nil, nil
	}

	// Get the record from log record or create new one
	n.Mutex.Lock()
	record, ok := n.LogRecords[sequenceNum]
	if !ok {
		record = CreateLogRecord(viewNumber, sequenceNum, signedPrepareMessages.Digest)
		n.LogRecords[sequenceNum] = record

		// Check if the request is in the forwarded requests log by comparing the digest
		// If it is then don't increment the wait count else increment the wait count
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(security.Digest(forwardedRequest.Request), signedPrepareMessages.Digest) {
				inForwardedRequestsLog = true
				break
			}
		}
		if !inForwardedRequestsLog {
			n.SafeTimer.IncrementWaitCountOrStart()
		}
	}
	n.Mutex.Unlock()

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
			log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prepareMessage, record.Request))
			continue
		}

		// Check if the prepare message matches preprepare message
		if prepareMessage.ViewNumber != record.ViewNumber ||
			prepareMessage.SequenceNum != record.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, record.Digest) {
			log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prepareMessage, record.Request))
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	// If verified count is less than 2f + 1 then return nil
	if verifiedCount < int(2*n.F+1) {
		log.Warnf("Ignored: %d; not enough prepare messages (verified: %d)", sequenceNum, verifiedCount)
		return nil, nil
	}

	// Log the prepare message
	n.Mutex.Lock()
	record.AddPrepareMessages(signedPrepareMessages.Messages)
	n.Mutex.Unlock()

	// Create commit message and sign it
	commitMessage := &pb.CommitMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		NodeID:      n.ID,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: security.Sign(commitMessage, n.PrivateKey),
	}

	go n.TryExecute(sequenceNum)

	return signedCommitMessage, nil
}

func (n *LinearPBFTNode) Commit(ctx context.Context, signedCommitMessages *pb.CollectedSignedCommitMessage) (*emptypb.Empty, error) {
	viewNumber := signedCommitMessages.ViewNumber
	sequenceNum := signedCommitMessages.SequenceNum

	// Ignore if already in view change
	if n.SentViewChange {
		log.Infof("Ignored: %s; already in view change", utils.LoggingString(signedCommitMessages))
		return nil, nil
	}

	// Verify View Number
	if viewNumber != n.ViewNumber {
		return nil, nil
	}

	// Get the prepared record from prepared log
	n.Mutex.Lock()
	record, ok := n.LogRecords[sequenceNum]
	if !ok {
		record = CreateLogRecord(viewNumber, sequenceNum, signedCommitMessages.Digest)
		n.LogRecords[sequenceNum] = record

		// Check if the request is in the forwarded requests log by comparing the digest
		// If it is then don't increment the wait count else increment the wait count
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(security.Digest(forwardedRequest.Request), signedCommitMessages.Digest) {
				inForwardedRequestsLog = true
				break
			}
		}
		if !inForwardedRequestsLog {
			n.SafeTimer.IncrementWaitCountOrStart()
		}
	}
	n.Mutex.Unlock()

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
			log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(commitMessage, record.Request))
			continue
		}

		// Check if the commit message matches prepare message
		if commitMessage.ViewNumber != record.ViewNumber ||
			commitMessage.SequenceNum != record.SequenceNum ||
			!cmp.Equal(commitMessage.Digest, record.Digest) {
			log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(commitMessage, record.Request))
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
	record.AddCommitMessages(signedCommitMessages.Messages)
	n.Mutex.Unlock()

	// Execute transaction
	go n.TryExecute(sequenceNum)

	return &emptypb.Empty{}, nil
}

func (n *LinearPBFTNode) SendViewChange() error {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Set sent view change flag to true
	n.SentViewChange = true

	// Get max sequence number in log record
	maxSequenceNum := int64(0)
	if utils.Max(utils.Keys(n.LogRecords)) != nil {
		maxSequenceNum = *utils.Max(utils.Keys(n.LogRecords))
	}
	// TODO: later get this from stable checkpoint
	lowerSequenceNum := int64(0)

	// Get prepared message proof set
	preparedSet := make([]*pb.PrepareProof, 0)
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		record := n.LogRecords[sequenceNum]
		if record == nil || !record.IsPrepared() {
			continue
		}
		prepareProof := record.GetPrepareProof()
		preparedSet = append(preparedSet, prepareProof)

	}

	// Create signed view change message
	viewChangeMessage := &pb.ViewChangeMessage{
		ViewNumber:  n.ViewNumber + 1,
		SequenceNum: lowerSequenceNum,
		PreparedSet: preparedSet,
		NodeID:      n.ID,
	}
	signedViewChangeMessage := &pb.SignedViewChangeMessage{
		Message:   viewChangeMessage,
		Signature: security.Sign(viewChangeMessage, n.PrivateKey),
	}

	// Log the view change message
	if _, ok := n.ViewChangeMessageLog[viewChangeMessage.ViewNumber]; !ok {
		n.ViewChangeMessageLog[viewChangeMessage.ViewNumber] = make(map[string]*pb.ViewChangeMessage)
	}
	viewChangeMessageLog := n.ViewChangeMessageLog[viewChangeMessage.ViewNumber]
	if _, ok := viewChangeMessageLog[viewChangeMessage.NodeID]; !ok {
		viewChangeMessageLog[viewChangeMessage.NodeID] = viewChangeMessage
	}

	// Multicast view change message to all nodes
	log.Infof("Sending view change message to all nodes: %s", utils.LoggingString(viewChangeMessage))
	for _, peer := range n.Peers {
		go func() {
			_, err := (*peer.Client).ViewChange(context.Background(), signedViewChangeMessage)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}
	return nil
}

func (n *LinearPBFTNode) ViewChange(ctx context.Context, signedViewChangeMessage *pb.SignedViewChangeMessage) (*emptypb.Empty, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber

	// Verify signature

	ok := security.Verify(viewChangeMessage, n.Peers[viewChangeMessage.NodeID].PublicKey, signedViewChangeMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(viewChangeMessage))
		// return nil, status.Errorf(codes.InvalidArgument, "invalid signature")
		return nil, nil
	}

	// Verify view number
	if viewNumber <= n.ViewNumber {
		return &emptypb.Empty{}, nil
	}

	// Verify prepare set
	for _, prepareProof := range viewChangeMessage.PreparedSet {
		signedPrePrepareMessage := prepareProof.SignedPrePrepareMessage
		prePrepareMessage := signedPrePrepareMessage.Message
		signedPrepareMessages := prepareProof.SignedPrepareMessages

		viewNumber := prePrepareMessage.ViewNumber
		sequenceNum := prePrepareMessage.SequenceNum
		digest := prePrepareMessage.Digest

		// Verify preprepare message signature
		leaderID := n.ViewNumberToLeader(viewNumber)
		var leaderPublicKey []byte
		if leaderID == n.ID {
			leaderPublicKey = n.PublicKey
		} else {
			leaderPublicKey = n.Peers[leaderID].PublicKey
		}
		ok := security.Verify(prePrepareMessage, leaderPublicKey, signedPrePrepareMessage.Signature)
		if !ok {
			// log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(preprepareMessage))
			// continue
			return nil, nil
		}

		// Verify preprepare message digest
		// TODO: think what else needs to be verified
		// view number and sequence number have to accepted
		// digest may not be possible to verify if request not availables

		// Verify prepare messages signatures
		for _, signedPrepareMessage := range signedPrepareMessages {
			prepareMessage := signedPrepareMessage.Message
			// Verify signature
			var publicKey []byte
			if prepareMessage.NodeID == n.ID {
				publicKey = n.PublicKey
			} else {
				publicKey = n.Peers[prepareMessage.NodeID].PublicKey
			}
			ok := security.Verify(prepareMessage, publicKey, signedPrepareMessage.Signature)
			if !ok {
				// log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prepareMessage))
				return nil, nil
			}

			// Verify prepare message digest, view number and sequence number
			if prepareMessage.ViewNumber != viewNumber ||
				prepareMessage.SequenceNum != sequenceNum ||
				!cmp.Equal(prepareMessage.Digest, digest) {
				// log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prepareMessage))
				return nil, nil
			}
		}
	}

	// Log the view change message
	log.Infof("Logged view change message: %s", utils.LoggingString(viewChangeMessage))
	if _, ok := n.ViewChangeMessageLog[viewNumber]; !ok {
		n.ViewChangeMessageLog[viewNumber] = make(map[string]*pb.ViewChangeMessage)
	}
	viewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	if _, ok := viewChangeMessageLog[viewChangeMessage.NodeID]; !ok {
		viewChangeMessageLog[viewChangeMessage.NodeID] = viewChangeMessage
	}

	// Send view change message to all nodes if f + 1 view change messages are collected
	if !n.SentViewChange && len(viewChangeMessageLog) >= int(n.F+1) {
		go n.SendViewChange()
	}
	return &emptypb.Empty{}, nil
}
