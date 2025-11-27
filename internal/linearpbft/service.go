package linearpbft

import (
	"context"
	"slices"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TransferRequest handles incoming transaction requests from clients
func (n *LinearPBFTNode) TransferRequest(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (*emptypb.Empty, error) {
	request := signedRequest.Request

	// Ignore request if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return &emptypb.Empty{}, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore request if in view change phase
	if n.state.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedRequest))
		return &emptypb.Empty{}, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify client signature
	if !cmp.Equal(crypto.Digest(signedRequest), DigestNoOp) &&
		!crypto.Verify(request, n.clients[request.Sender].PublicKey, signedRequest.Signature) {
		log.Warnf("Invalid client signature for request %s", utils.LoggingString(signedRequest))
		return &emptypb.Empty{}, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Send reply to client if duplicate request
	if n.state.LastReply.Get(request.Sender) != nil && request.Timestamp == n.state.LastReply.Get(request.Sender).Timestamp {
		log.Infof("Received duplicate request from client %s for request %s, sending reply", request.Sender, utils.LoggingString(signedRequest))
		go n.SendReply(signedRequest, n.state.LastReply.Get(request.Sender).Result)
		return &emptypb.Empty{}, nil
	}

	// Forward request to primary if not primary
	if n.ID != utils.ViewNumberToPrimaryID(n.state.GetViewNumber(), n.config.N) {
		// Check if request is already in forward request log
		digest := crypto.Digest(signedRequest)
		if n.state.InForwardedRequestsLog(digest) {
			log.Infof("Ignored: %s; already forwarded", utils.LoggingString(signedRequest))
			return &emptypb.Empty{}, nil
		}

		// Check if already preprepared in current view number
		sequenceNum := n.state.StateLog.GetSequenceNumberByDigest(digest)
		if sequenceNum != 0 && n.state.StateLog.IsPrePrepared(sequenceNum) && n.state.StateLog.GetViewNumber(sequenceNum) == n.state.GetViewNumber() {
			log.Infof("Ignored: %s; already preprepared", utils.LoggingString(signedRequest))
			return &emptypb.Empty{}, nil
		}

		// Logger: add received transaction request
		n.logger.AddReceivedTransactionRequest(signedRequest)

		n.handler.timer.IncrementWaitCountOrStart()
		go n.ForwardRequest(signedRequest)
		n.state.AddForwardedRequest(digest)
		return &emptypb.Empty{}, nil
	}

	// If primary and already preprepared then
	digest := crypto.Digest(signedRequest)
	sequenceNum := n.state.StateLog.GetSequenceNumberByDigest(digest)
	if sequenceNum != 0 && n.state.StateLog.IsPrePrepared(sequenceNum) {
		log.Infof("Ignored: %s; already preprepared", utils.LoggingString(signedRequest))
		return &emptypb.Empty{}, nil
	}

	// Logger: add received transaction request
	n.logger.AddReceivedTransactionRequest(signedRequest)

	go n.handler.LeaderTransactionRequestHandler(signedRequest)
	return &emptypb.Empty{}, nil

}

// ReadOnlyRequest handles incoming read only transaction requests from clients
// This function replies to the client in the same RPC call directly instead of a separate RPC call to the client
func (n *LinearPBFTNode) ReadOnlyRequest(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error) {
	request := signedRequest.Request

	// Ignore request if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore request if in view change phase
	if n.state.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedRequest))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Byzantine node behavior: crash attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.CrashAttack {
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify client signature
	ok := crypto.Verify(request, n.clients[request.Sender].PublicKey, signedRequest.Signature)
	if !ok {
		log.Warnf("Invalid client signature for request %s", utils.LoggingString(signedRequest))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Logger: add received read only request
	n.logger.AddReceivedReadOnlyRequest(signedRequest)

	// Get balance from database
	balance, err := n.executor.db.GetBalance(request.Sender)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	// Create signed transaction response message
	message := &pb.TransactionResponse{
		ViewNumber: n.state.GetViewNumber(),
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
		Result:     int64(balance),
	}
	signedMessage := &pb.SignedTransactionResponse{
		Message:   message,
		Signature: crypto.Sign(message, n.handler.privateKey1),
	}

	// Byzantine node behavior: sign attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
		signedMessage.Signature = []byte("invalid signature")
	}

	// Logger: add sent read only response
	n.logger.AddSentReadOnlyResponse(signedMessage)

	log.Infof("Node %s: Read only request %s -> %d", n.ID, utils.LoggingString(signedRequest), balance)
	return signedMessage, nil
}

// SendReply sends a reply to a client
func (n *LinearPBFTNode) SendReply(signedRequest *pb.SignedTransactionRequest, result int64) {
	request := signedRequest.Request
	// Create signed transaction response message
	reply := &pb.TransactionResponse{
		ViewNumber: n.state.GetViewNumber(),
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
		Result:     result,
	}
	signedReply := &pb.SignedTransactionResponse{
		Message:   reply,
		Signature: crypto.Sign(reply, n.handler.privateKey1),
	}

	// Byzantine node behavior: sign attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
		signedReply.Signature = []byte("invalid signature")
	}

	// Update last reply
	n.state.LastReply.Update(request.Sender, reply)

	// Logger: add sent transaction response
	n.logger.AddSentTransactionResponse(signedReply)

	// Send reply to client with simple retries to avoid crashing replica on transient issues
	for attempt := 1; attempt <= MaxSendAttempts; attempt++ {
		_, err := n.clients[request.Sender].Client.ReceiveReply(n.serverCtx, signedReply)
		if err == nil {
			return
		}

		// Warn and retry with exponential backoff
		log.Warnf("Failed to send reply to client %s (attempt %d/%d): %v", request.Sender, attempt, MaxSendAttempts, err)
		time.Sleep(SendAttemptDelay)
	}

	log.Errorf("Giving up sending reply to client %s after %d attempts", request.Sender, MaxSendAttempts)
}

// ForwardRequest forwards a transaction request to the primary
func (n *LinearPBFTNode) ForwardRequest(signedRequest *pb.SignedTransactionRequest) {
	// Forward request to primary
	primaryID := utils.ViewNumberToPrimaryID(n.state.GetViewNumber(), n.config.N)

	// Byzantine node behavior: dark attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, primaryID) {
		log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, primaryID)
		return
	}

	// Logger: add forwarded transaction request
	n.logger.AddForwardedTransactionRequest(signedRequest)

	log.Infof("Forwarding to primary %s: %s", primaryID, utils.LoggingString(signedRequest))
	_, err := n.handler.peers[primaryID].Client.TransferRequest(n.serverCtx, signedRequest)
	if err != nil {
		log.Warnf("Forwarding failed: %s; %s", utils.LoggingString(signedRequest), err.Error())
	}
}
