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

	// If request is nil then try getting it from log record or send get request rpc
	if signedRequest == nil {
		// Try getting request from log record
		if record, ok := n.LogRecords[prePrepareMessage.SequenceNum]; ok && record.Request != nil {
			signedRequest = record.Request
		} else {
			// If request is not in log record then send get request rpc
			response, err := n.SendGetRequest(prePrepareMessage.SequenceNum)
			if err != nil || response == nil {
				log.Warnf("Rejected: %s; request could not be retrieved", utils.LoggingString(prePrepareMessage))
				return nil, status.Errorf(codes.FailedPrecondition, "request could not be retrieved")
			}
			signedRequest = response
		}
	}
	request := signedRequest.Request

	// Verify client signature
	ok = crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(request))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature on request")
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

	// Verify if previously accepted preprepare message with different digest
	n.Mutex.Lock()
	record, ok := n.LogRecords[prePrepareMessage.SequenceNum]
	if ok {
		// Reject if some other request was previously assigned to this sequence number
		// TODO: what if something was preprepared only but now i get a null message from new view message
		if record.IsPrePrepared() && !cmp.Equal(record.Digest, prePrepareMessage.Digest) {
			log.Warnf("Rejected: %s; previously accepted %s", utils.LoggingString(prePrepareMessage, request), utils.LoggingString(record.Request))
			return nil, status.Errorf(codes.FailedPrecondition, "previously accepted preprepare message with different digest")
		}
		record.AddRequest(signedRequest)
		record.AddPrePrepareMessage(signedMessage)
	} else {
		// Create new log record if no record exists for this sequence number
		record = CreateLogRecord(prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, crypto.Digest(request))
		n.LogRecords[prePrepareMessage.SequenceNum] = record
		record.AddRequest(signedRequest)
		record.AddPrePrepareMessage(signedMessage)

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
	}
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

		// Verify Signature
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

		// Verify Signature
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
func (n *LinearPBFTNode) SendGetRequest(sequenceNum int64) (*pb.SignedTransactionRequest, error) {
	getRequestMessage := &pb.GetRequestMessage{
		SequenceNum: sequenceNum,
		NodeID:      n.ID,
	}

	// Multicast get request to all nodes
	responseCh := make(chan *pb.SignedTransactionRequest, len(n.Peers))
	wg := sync.WaitGroup{}
	log.Infof("Sending get request to all nodes for sequence number %d", sequenceNum)
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

		// Check if record exists for this sequence number
		n.Mutex.Lock()
		record, ok := n.LogRecords[sequenceNum]
		if !ok {
			record = CreateLogRecord(n.ViewNumber, sequenceNum, crypto.Digest(request))
			n.LogRecords[sequenceNum] = record
			record.AddRequest(signedRequest)
		}
		n.Mutex.Unlock()

		// Verify if digest is same as in log record
		if !cmp.Equal(crypto.Digest(request), record.Digest) {
			log.Warnf("Rejected: %s; invalid digest on request", utils.LoggingString(request))
			continue
		}

		return signedRequest, nil
	}
	log.Warnf("Missing request for sequence number %d could not be retrieved from any node", sequenceNum)
	return nil, status.Errorf(codes.NotFound, "request not found")
}

// GetRequest gets a request from the log record for a given sequence number
func (n *LinearPBFTNode) GetRequest(ctx context.Context, getRequestMessage *pb.GetRequestMessage) (*pb.SignedTransactionRequest, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	sequenceNum := getRequestMessage.SequenceNum
	record, ok := n.LogRecords[sequenceNum]
	if !ok || record.Request == nil {
		log.Warnf("Rejected: %s; sequence number not found", utils.LoggingString(getRequestMessage))
		return nil, status.Errorf(codes.NotFound, "sequence number not found")
	}
	log.Infof("Sent request for %s: request %s", utils.LoggingString(getRequestMessage), utils.LoggingString(record.Request))
	return record.Request, nil
}
