package linearpbft

import (
	"context"
	"slices"
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
// This function is a rpc which is called by the primary to preprepare a request
// It is also called by inside new view request rpc
func (n *LinearPBFTNode) PrePrepareRequest(ctx context.Context, signedMessage *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error) {
	prePrepareMessage := signedMessage.Message
	signedRequest := signedMessage.Request

	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.State.IsViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if prePrepareMessage.ViewNumber != n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(prePrepareMessage), n.State.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify Node's signature
	currentPrimaryID := utils.ViewNumberToPrimaryID(n.State.GetViewNumber(), n.N)
	ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(currentPrimaryID), signedMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// May not have the request in the transaction map if called inside new view routine
	// We may overwrite the request in the transaction map if called inside new view routine
	// if signed request is nil then get from transaction map
	if signedRequest == nil {
		signedRequest = n.State.TransactionMap.Get(prePrepareMessage.Digest)
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

	// Verify client signature if not no-op transaction
	if !cmp.Equal(prePrepareMessage.Digest, DigestNoOp) &&
		!crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature) {
		log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(request))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature on request")
	}

	// Add request to transaction map
	if n.State.TransactionMap.Get(prePrepareMessage.Digest) == nil {
		log.Infof("Adding request to transaction map: %s", utils.LoggingString(signedRequest.Request))
		n.State.TransactionMap.Set(prePrepareMessage.Digest, signedRequest)
	}

	// Verify Digest
	if !cmp.Equal(prePrepareMessage.Digest, crypto.Digest(signedRequest)) {
		log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prePrepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest")
	}

	// Get record from log record
	n.Mutex.Lock()
	record, exists := n.State.StateLog.Get(prePrepareMessage.SequenceNum)
	if !exists {
		// Create new log record if no record exists for this sequence number
		record = CreateLogRecord(prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, crypto.Digest(signedRequest))
		n.State.StateLog.Set(prePrepareMessage.SequenceNum, record)

		//  TODO: check if safety issue here and if code can be improved
		// Check if the request is in the forwarded requests log
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(crypto.Digest(forwardedRequest), prePrepareMessage.Digest) {
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
		log.Warnf("Rejected: %s; previously accepted %s", utils.LoggingString(prePrepareMessage, request), utils.LoggingString(n.State.TransactionMap.Get(record.Digest).Request))
		return nil, status.Errorf(codes.FailedPrecondition, "previously accepted preprepare message with different digest")
	}

	// Log the preprepare message in record
	n.Mutex.Lock()
	record.AddPrePrepareMessage(signedMessage)
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

	// Create prepare message and sign it
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

	n.Executor.GetExecuteChannel() <- prePrepareMessage.SequenceNum

	// Byzantine node behavior: dark attack
	if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, prepareMessage.NodeID) {
		// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, prepareMessage.NodeID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	return signedPrepareMessage, nil
}

// Prepare handles incoming prepare messages
func (n *LinearPBFTNode) PrepareRequest(ctx context.Context, signedPrepareMessages *pb.CollectedSignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	viewNumber := signedPrepareMessages.ViewNumber
	sequenceNum := signedPrepareMessages.SequenceNum

	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.State.IsViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedPrepareMessages))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedPrepareMessages), n.State.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Get the record from log record or create new one
	n.Mutex.Lock()
	record, exists := n.State.StateLog.Get(sequenceNum)
	if !exists {
		// Create new log record if no record exists for this sequence number
		record = CreateLogRecord(viewNumber, sequenceNum, signedPrepareMessages.Digest)
		n.State.StateLog.Set(sequenceNum, record)

		// Check if the request is in the forwarded requests log by comparing the digest
		// If it is then don't increment the wait count else increment the wait count
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(crypto.Digest(forwardedRequest), signedPrepareMessages.Digest) {
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
		ok := crypto.Verify(prepareMessage, n.GetPublicKey1(prepareMessage.NodeID), signedPrepareMessage.Signature)
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

	// Create commit message and sign it
	commitMessage := &pb.CommitMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
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

	n.Executor.GetExecuteChannel() <- sequenceNum

	// Byzantine node behavior: dark attack
	if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, commitMessage.NodeID) {
		// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, commitMessage.NodeID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	return signedCommitMessage, nil
}

// Commit handles incoming commit messages
func (n *LinearPBFTNode) CommitRequest(ctx context.Context, signedCommitMessages *pb.CollectedSignedCommitMessage) (*emptypb.Empty, error) {
	viewNumber := signedCommitMessages.ViewNumber
	sequenceNum := signedCommitMessages.SequenceNum

	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.State.IsViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedCommitMessages))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedCommitMessages), n.State.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Get the record from log record or create new one
	n.Mutex.Lock()
	record, exists := n.State.StateLog.Get(sequenceNum)
	if !exists {
		// Create new log record if no record exists for this sequence number
		record = CreateLogRecord(viewNumber, sequenceNum, signedCommitMessages.Digest)
		n.State.StateLog.Set(sequenceNum, record)

		// Check if the request is in the forwarded requests log by comparing the digest
		// If it is then don't increment the wait count else increment the wait count
		inForwardedRequestsLog := false
		for _, forwardedRequest := range n.ForwardedRequestsLog {
			if cmp.Equal(crypto.Digest(forwardedRequest), signedCommitMessages.Digest) {
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
		ok := crypto.Verify(commitMessage, n.GetPublicKey1(commitMessage.NodeID), signedCommitMessage.Signature)
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

	// Execute transaction
	n.Executor.GetExecuteChannel() <- sequenceNum

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
			// Byzantine node behavior: dark attack
			if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
				// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
				return
			}
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
		if !cmp.Equal(crypto.Digest(signedRequest), DigestNoOp) &&
			!crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature) {
			log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(request))
			continue
		}

		// Verify if digest is same as in log record
		if !cmp.Equal(crypto.Digest(signedRequest), digest) {
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
	n.Mutex.RLock()
	defer n.Mutex.RUnlock()

	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Byzantine node behavior: dark attack
	if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, getRequestMessage.NodeID) {
		// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, getRequestMessage.NodeID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	digest := getRequestMessage.Digest
	signedRequest := n.State.TransactionMap.Get(digest)
	if signedRequest == nil {
		log.Warnf("Rejected: %s; request not found in transaction map", utils.LoggingString(getRequestMessage))
		return nil, status.Errorf(codes.NotFound, "request not found in transaction map")
	}

	log.Infof("Get request: %s: request %s", utils.LoggingString(getRequestMessage), utils.LoggingString(signedRequest.Request))
	return signedRequest, nil
}
