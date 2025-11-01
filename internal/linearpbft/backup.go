package linearpbft

import (
	"context"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// PrePrepare handles incoming preprepare messages
// This function is a rpc which is called by the leader to preprepare a request
// It is also called by inside new view request rpc
func (n *LinearPBFTNode) PrePrepareRequest(ctx context.Context, signedMessage *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error) {
	prePrepareMessage := signedMessage.Message
	signedRequest := signedMessage.Request

	// Ignore if already in view change
	if n.ViewChangePhase {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify Node's signature
	currentLeaderID := utils.ViewNumberToLeaderID(n.ViewNumber, n.N)
	ok := crypto.Verify(prePrepareMessage, n.GetPublicKey(currentLeaderID), signedMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// May not have the request in the transaction map if called inside new view routine
	// We may overwrite the request in the transaction map if called inside new view routine
	// if signed request is nil then get from transaction map
	if signedRequest == nil {
		signedRequest = n.TransactionMap.Get(prePrepareMessage.Digest)
	}
	// if not in transaction map then send a get request to all nodes; if still nil then return error
	if signedRequest == nil {
		response, err := n.SendGetRequest(prePrepareMessage.Digest)
		if err != nil || response == nil {
			log.Warnf("Rejected: %s; request could not be retrieved from any node", utils.LoggingString(prePrepareMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "request could not be retrieved from any node")
		}
		signedRequest = response
	}
	request := signedRequest.Request

	// Verify client signature
	ok = crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(request))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature on request")
	}

	// Add request to transaction map
	if n.TransactionMap.Get(prePrepareMessage.Digest) == nil {
		log.Infof("Adding request to transaction map: %s", utils.LoggingString(signedRequest.Request))
		n.TransactionMap.Set(prePrepareMessage.Digest, signedRequest)
	}

	// Verify View Number
	if prePrepareMessage.ViewNumber != n.ViewNumber {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(prePrepareMessage, request), n.ViewNumber)
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify Digest
	if !cmp.Equal(prePrepareMessage.Digest, crypto.Digest(request)) {
		log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prePrepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest")
	}

	// Get record from log record
	n.Mutex.Lock()
	record, ok := n.LogRecords[prePrepareMessage.SequenceNum]
	if !ok {
		// Create new log record if no record exists for this sequence number
		record = CreateLogRecord(prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, crypto.Digest(request))
		n.LogRecords[prePrepareMessage.SequenceNum] = record

		//  TODO: check if safety issue here and if code can be improved
		// Check if the request is in the forwarded requests log
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(crypto.Digest(forwardedRequest.Request), prePrepareMessage.Digest) {
				inForwardedRequestsLog = true
				break
			}
		}
		if !inForwardedRequestsLog {
			n.SafeTimer.IncrementWaitCountOrStart()
		}
	} else if record.ViewNumber < prePrepareMessage.ViewNumber {
		// Reset log record if view number is less than preprepare message view number
		record.Reset(prePrepareMessage.ViewNumber, prePrepareMessage.Digest)
	}
	n.Mutex.Unlock()

	// Verify if previously accepted preprepare message with different digest for same view and sequence number
	if record.IsPrePrepared() && !cmp.Equal(record.Digest, prePrepareMessage.Digest) {
		log.Warnf("Rejected: %s; previously accepted %s", utils.LoggingString(prePrepareMessage, request), utils.LoggingString(n.TransactionMap.Get(record.Digest).Request))
		return nil, status.Errorf(codes.FailedPrecondition, "previously accepted preprepare message with different digest")
	}

	// Log the preprepare message in record
	n.Mutex.Lock()
	record.AddPrePrepareMessage(signedMessage)
	n.Mutex.Unlock()

	// Create prepare message and sign it
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

	go n.TryExecute(prePrepareMessage.SequenceNum)

	return signedPrepareMessage, nil
}

// Prepare handles incoming prepare messages
func (n *LinearPBFTNode) PrepareRequest(ctx context.Context, signedPrepareMessages *pb.CollectedSignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	viewNumber := signedPrepareMessages.ViewNumber
	sequenceNum := signedPrepareMessages.SequenceNum

	// Ignore if already in view change
	if n.ViewChangePhase {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedPrepareMessages))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.ViewNumber {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedPrepareMessages), n.ViewNumber)
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Get the record from log record or create new one
	n.Mutex.Lock()
	record, ok := n.LogRecords[sequenceNum]
	if !ok {
		// Create new log record if no record exists for this sequence number
		record = CreateLogRecord(viewNumber, sequenceNum, signedPrepareMessages.Digest)
		n.LogRecords[sequenceNum] = record

		// Check if the request is in the forwarded requests log by comparing the digest
		// If it is then don't increment the wait count else increment the wait count
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(crypto.Digest(forwardedRequest.Request), signedPrepareMessages.Digest) {
				inForwardedRequestsLog = true
				break
			}
		}
		if !inForwardedRequestsLog {
			n.SafeTimer.IncrementWaitCountOrStart()
		}
	} else if record.ViewNumber < viewNumber {
		// Reset log record if view number is less than prepare message view number
		record.Reset(viewNumber, signedPrepareMessages.Digest)
	}
	n.Mutex.Unlock()

	// Verify Prepare Messages
	verifiedCount := 0
	for _, signedPrepareMessage := range signedPrepareMessages.Messages {
		// TODO: remove this check later if we are sure that the prepare messages are not nil
		if signedPrepareMessage == nil {
			log.Fatal("Signed prepare message is nil")
		}
		prepareMessage := signedPrepareMessage.Message

		// Verify Node's signature
		ok := crypto.Verify(prepareMessage, n.GetPublicKey(prepareMessage.NodeID), signedPrepareMessage.Signature)
		if !ok {
			// log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prepareMessage, record.Request))
			continue
		}

		// Check if the prepare message matches preprepare message (here actually the view number in log record)
		if prepareMessage.ViewNumber != record.ViewNumber ||
			prepareMessage.SequenceNum != record.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, record.Digest) {
			// log.Warnf("Rejected: %s; does not match log record", utils.LoggingString(prepareMessage, record.Request))
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	// If verified count is less than 2f + 1 then return nil
	if verifiedCount < int(2*n.F+1) {
		log.Warnf("Ignored: %d; not enough prepare messages (verified: %d)", sequenceNum, verifiedCount)
		return nil, status.Errorf(codes.FailedPrecondition, "not enough prepare messages")
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
		Signature: crypto.Sign(commitMessage, n.PrivateKey),
	}

	go n.TryExecute(sequenceNum)

	return signedCommitMessage, nil
}

// Commit handles incoming commit messages
func (n *LinearPBFTNode) CommitRequest(ctx context.Context, signedCommitMessages *pb.CollectedSignedCommitMessage) (*emptypb.Empty, error) {
	viewNumber := signedCommitMessages.ViewNumber
	sequenceNum := signedCommitMessages.SequenceNum

	// Ignore if already in view change
	if n.ViewChangePhase {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedCommitMessages))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.ViewNumber {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedCommitMessages), n.ViewNumber)
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Get the record from log record or create new one
	n.Mutex.Lock()
	record, ok := n.LogRecords[sequenceNum]
	if !ok {
		// Create new log record if no record exists for this sequence number
		record = CreateLogRecord(viewNumber, sequenceNum, signedCommitMessages.Digest)
		n.LogRecords[sequenceNum] = record

		// Check if the request is in the forwarded requests log by comparing the digest
		// If it is then don't increment the wait count else increment the wait count
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(crypto.Digest(forwardedRequest.Request), signedCommitMessages.Digest) {
				inForwardedRequestsLog = true
				break
			}
		}
		if !inForwardedRequestsLog {
			n.SafeTimer.IncrementWaitCountOrStart()
		}
	} else if record.ViewNumber < viewNumber {
		// Reset log record if view number is less than commit message view number
		record.Reset(viewNumber, signedCommitMessages.Digest)
	}
	n.Mutex.Unlock()

	// Verify Commit Messages
	verifiedCount := 0
	for _, signedCommitMessage := range signedCommitMessages.Messages {
		// TODO: remove this check later if we are sure that the commit messages are not nil
		if signedCommitMessage == nil {
			log.Fatal("Signed commit message is nil")
		}
		commitMessage := signedCommitMessage.Message

		// Verify Node's signature
		ok := crypto.Verify(commitMessage, n.GetPublicKey(commitMessage.NodeID), signedCommitMessage.Signature)
		if !ok {
			// log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(commitMessage, record.Request))
			continue
		}

		// Check if the commit message matches prepare message
		if commitMessage.ViewNumber != record.ViewNumber ||
			commitMessage.SequenceNum != record.SequenceNum ||
			!cmp.Equal(commitMessage.Digest, record.Digest) {
			// log.Warnf("Rejected: %s; does not match log record", utils.LoggingString(commitMessage, record.Request))
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	// If verified count is less than 2f + 1 then return nil
	if verifiedCount < int(2*n.F+1) {
		log.Warnf("Ignored: %d; not enough commit messages (verified: %d)", sequenceNum, verifiedCount)
		return nil, status.Errorf(codes.FailedPrecondition, "not enough commit messages")
	}

	// Log the commit message
	n.Mutex.Lock()
	record.AddCommitMessages(signedCommitMessages.Messages)
	n.Mutex.Unlock()

	// Execute transaction
	go n.TryExecute(sequenceNum)

	return &emptypb.Empty{}, nil
}

// SendGetRequest sends a get request to all nodes for a given sequence number
func (n *LinearPBFTNode) SendGetRequest(digest []byte) (*pb.SignedTransactionRequest, error) {
	getRequestMessage := &pb.GetRequestMessage{
		Digest: digest,
		NodeID: n.ID,
	}

	// Multicast get request to all nodes
	responseCh := make(chan *pb.SignedTransactionRequest, len(n.Peers))
	wg := sync.WaitGroup{}
	log.Infof("Sending get request: %s", utils.LoggingString(getRequestMessage))
	for _, peer := range n.Peers {
		wg.Add(1)
		go func(peer *models.Node) {
			defer wg.Done()
			signedRequest, err := (*peer.Client).GetRequest(context.Background(), getRequestMessage)
			if err != nil {
				return
			}
			responseCh <- signedRequest
		}(peer)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Return the first valid response
	for signedRequest := range responseCh {
		request := signedRequest.Request

		if request == nil {
			continue
		}

		// Verify client signature
		ok := crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(request))
			continue
		}

		// Verify if digest is same as in log record
		if !cmp.Equal(crypto.Digest(request), digest) {
			log.Warnf("Rejected: %s; invalid digest on request", utils.LoggingString(request))
			continue
		}

		return signedRequest, nil
	}
	log.Warnf("Missing request: %s; could not be retrieved from any node", utils.LoggingString(getRequestMessage))
	return nil, status.Errorf(codes.NotFound, "request not found")
}

// GetRequest gets a request from the log record for a given sequence number
func (n *LinearPBFTNode) GetRequest(ctx context.Context, getRequestMessage *pb.GetRequestMessage) (*pb.SignedTransactionRequest, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	digest := getRequestMessage.Digest
	signedRequest := n.TransactionMap.Get(digest)
	if signedRequest == nil {
		log.Warnf("Rejected: %s; request not found in transaction map", utils.LoggingString(getRequestMessage))
		return nil, status.Errorf(codes.NotFound, "request not found in transaction map")
	}
	log.Infof("Sent request: %s: request %s", utils.LoggingString(getRequestMessage), utils.LoggingString(signedRequest.Request))
	return signedRequest, nil
}
