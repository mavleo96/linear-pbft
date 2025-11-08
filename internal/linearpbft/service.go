package linearpbft

import (
	"context"
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
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
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(request))
		return &emptypb.Empty{}, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify client signature
	if !cmp.Equal(crypto.Digest(signedRequest), DigestNoOp) &&
		!crypto.Verify(request, n.clients[request.Sender].PublicKey, signedRequest.Signature) {
		log.Warnf("Invalid client signature for request %s", utils.LoggingString(request))
		return &emptypb.Empty{}, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Send reply to client if duplicate request
	if n.state.LastReply.Get(request.Sender) != nil && request.Timestamp == n.state.LastReply.Get(request.Sender).Timestamp {
		log.Infof("Received duplicate request from client %s for request %s, sending reply", request.Sender, utils.LoggingString(request))
		go n.SendReply(signedRequest, n.state.LastReply.Get(request.Sender).Result)
		return &emptypb.Empty{}, nil
	}

	// TODO: this does not belong here, it should be part of the request handler
	// Add request to transaction map
	if n.state.TransactionMap.Get(crypto.Digest(signedRequest)) == nil {
		// log.Infof("Adding request to transaction map: %s", utils.LoggingString(request))
		n.state.TransactionMap.Set(crypto.Digest(signedRequest), signedRequest)
	}

	// Forward request to primary if not primary
	if n.ID != utils.ViewNumberToPrimaryID(n.state.GetViewNumber(), n.config.N) {
		// Check if request is already in forward request log
		digest := crypto.Digest(signedRequest)
		if n.state.InForwardedRequestsLog(digest) {
			log.Infof("Ignored: %s; already forwarded", utils.LoggingString(request))
			return &emptypb.Empty{}, nil
		}
		n.timer.IncrementWaitCountOrStart()
		ctx := n.timer.GetContext()
		go n.ForwardRequest(ctx, signedRequest)
		n.state.AddForwardedRequest(digest)
		return &emptypb.Empty{}, nil
	}

	// If primary and already preprepared then
	digest := crypto.Digest(signedRequest)
	sequenceNum := n.state.StateLog.GetSequenceNumberByDigest(digest)
	if sequenceNum != 0 && n.state.StateLog.IsPrePrepared(sequenceNum) {
		log.Infof("Ignored: %s; already preprepared", utils.LoggingString(request))
		return &emptypb.Empty{}, nil
	}

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
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(request))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Byzantine node behavior: crash attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.CrashAttack {
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify client signature
	ok := crypto.Verify(request, n.clients[request.Sender].PublicKey, signedRequest.Signature)
	if !ok {
		log.Warnf("Invalid client signature for request %s", utils.LoggingString(request))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

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

	log.Infof("Node %s: Read only request %s -> %d", n.ID, utils.LoggingString(request), balance)
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

	// Send reply to client
	_, err := (*n.clients[request.Sender].Client).ReceiveReply(context.Background(), signedReply)
	if err != nil {
		log.Fatal(err)
	}
}

// ForwardRequest forwards a transaction request to the primary
func (n *LinearPBFTNode) ForwardRequest(ctx context.Context, signedRequest *pb.SignedTransactionRequest) {
	// Forward request to primary
	primaryID := utils.ViewNumberToPrimaryID(n.state.GetViewNumber(), n.config.N)

	// Byzantine node behavior: dark attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, primaryID) {
		log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, primaryID)
		return
	}

	log.Infof("Forwarding to primary %s: %s", primaryID, utils.LoggingString(signedRequest.Request))
	_, err := (*n.handler.peers[primaryID].Client).TransferRequest(context.Background(), signedRequest)
	if err != nil {
		log.Warnf("Forwarding Failed: %s; %s", utils.LoggingString(signedRequest.Request), err.Error())
	}
}
