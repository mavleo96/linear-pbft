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
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return &emptypb.Empty{}, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore request if in view change phase
	if n.ViewChangePhase {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(request))
		return &emptypb.Empty{}, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify client signature
	if !cmp.Equal(crypto.Digest(signedRequest), DigestNoOp) &&
		!crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature) {
		log.Warnf("Invalid client signature for request %s", utils.LoggingString(request))
		return &emptypb.Empty{}, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Send reply to client if duplicate request
	if n.LastReply.Get(request.Sender) != nil && request.Timestamp == n.LastReply.Get(request.Sender).Timestamp {
		sequenceNum, _ := n.GetOrAssignSequenceNumber(signedRequest)
		log.Infof("Received duplicate request from client %s for request %s, sending reply", request.Sender, utils.LoggingString(request))
		go n.SendReply(sequenceNum, request, n.LastReply.Get(request.Sender).Result)
		return &emptypb.Empty{}, nil
	}

	// Forward request to leader if not leader
	if n.ID != utils.ViewNumberToLeaderID(n.ViewNumber, n.N) {
		n.SafeTimer.IncrementWaitCountOrStart()
		ctx := n.SafeTimer.GetContext()
		go n.ForwardRequest(ctx, signedRequest)
		n.ForwardedRequestsLog = append(n.ForwardedRequestsLog, signedRequest)
		return &emptypb.Empty{}, nil
		// } else if !n.Flag {
		// 	log.Infof("Ignore request for debugging purposes %s", utils.LoggingString(request))
		// 	n.Flag = true
		// return &emptypb.Empty{}, nil
	}
	n.RequestCh <- signedRequest
	return &emptypb.Empty{}, nil
}

// 	// Get or assign sequence number
// 	sequenceNum, exists := n.GetOrAssignSequenceNumber(signedRequest)
// 	if !exists {
// 		// Add request to log record
// 		n.Mutex.Lock()
// 		n.LogRecords[sequenceNum] = CreateLogRecord(n.ViewNumber, sequenceNum, crypto.Digest(signedRequest))
// 		n.Mutex.Unlock()
// 	}

// 	// Add request to log record
// 	record := n.LogRecords[sequenceNum]
// 	if record.IsPrePrepared() {
// 		log.Infof("In Progress: %s", utils.LoggingString(request))
// 		return &emptypb.Empty{}, nil
// 	}

// 	// Create signed preprepare message and add to log record
// 	preprepare := &pb.PrePrepareMessage{
// 		ViewNumber:  n.ViewNumber,
// 		SequenceNum: sequenceNum,
// 		Digest:      crypto.Digest(signedRequest),
// 	}
// 	signedPreprepare := &pb.SignedPrePrepareMessage{
// 		Message:   preprepare,
// 		Signature: crypto.Sign(preprepare, n.PrivateKey),
// 		Request:   signedRequest,
// 	}
// 	// Byzantine node behavior: sign attack
// 	if n.Byzantine && n.SignAttack {
// 		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
// 		signedPreprepare.Signature = []byte("invalid signature")
// 	}
// 	record.AddPrePrepareMessage(signedPreprepare)

// 	// Send preprepare message to all nodes and collect prepare messages
// 	prepareMsgs, err := n.SendPrePrepare(signedPreprepare, sequenceNum)
// 	if err != nil || prepareMsgs == nil {
// 		return &emptypb.Empty{}, nil
// 	}

// 	// Send prepare message to all nodes and collect commit messages
// 	commitMsgs, err := n.SendPrepare(prepareMsgs, sequenceNum)
// 	if err != nil || commitMsgs == nil {
// 		return &emptypb.Empty{}, nil
// 	}

// 	// Send commit message to all nodes
// 	err = n.SendCommit(commitMsgs, sequenceNum)
// 	if err != nil {
// 		return &emptypb.Empty{}, nil
// 	}

// 	// Execute transaction
// 	go n.TryExecute(sequenceNum)

// 	return &emptypb.Empty{}, nil
// }

// ReadOnlyRequest handles incoming read only transaction requests from clients
// This function replies to the client in the same RPC call directly instead of a separate RPC call to the client
func (n *LinearPBFTNode) ReadOnlyRequest(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error) {
	request := signedRequest.Request

	// Ignore request if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore request if in view change phase
	if n.ViewChangePhase {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(request))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Byzantine node behavior: crash attack
	if n.Byzantine && n.CrashAttack {
		// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify client signature
	ok := crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature)
	if !ok {
		log.Warnf("Invalid client signature for request %s", utils.LoggingString(request))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Get balance from database
	balance, err := n.DB.GetBalance(request.Sender)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	// Create signed transaction response message
	message := &pb.TransactionResponse{
		ViewNumber: n.ViewNumber,
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
		Result:     int64(balance),
	}
	signedMessage := &pb.SignedTransactionResponse{
		Message:   message,
		Signature: crypto.Sign(message, n.PrivateKey),
	}
	// Byzantine node behavior: sign attack
	if n.Byzantine && n.SignAttack {
		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
		signedMessage.Signature = []byte("invalid signature")
	}
	log.Infof("Node %s: Read only request %s -> %d", n.ID, utils.LoggingString(request), balance)
	return signedMessage, nil
}

// SendReply sends a reply to a client
func (n *LinearPBFTNode) SendReply(sequenceNum int64, request *pb.TransactionRequest, result int64) {
	// Create signed transaction response message
	reply := &pb.TransactionResponse{
		ViewNumber: n.ViewNumber,
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
		Result:     result,
	}
	signedReply := &pb.SignedTransactionResponse{
		Message:   reply,
		Signature: crypto.Sign(reply, n.PrivateKey),
	}
	// Byzantine node behavior: sign attack
	if n.Byzantine && n.SignAttack {
		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
		signedReply.Signature = []byte("invalid signature")
	}
	// Update last reply
	n.LastReply.Update(request.Sender, reply)

	// Send reply to client
	_, err := (*n.Clients[request.Sender].Client).ReceiveReply(context.Background(), signedReply)
	if err != nil {
		log.Fatal(err)
	}
}

// ForwardRequest forwards a transaction request to the leader
func (n *LinearPBFTNode) ForwardRequest(ctx context.Context, signedRequest *pb.SignedTransactionRequest) {
	// Forward request to leader
	leaderID := utils.ViewNumberToLeaderID(n.ViewNumber, n.N)
	// Byzantine node behavior: dark attack
	if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, leaderID) {
		log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, leaderID)
		return
	}
	log.Infof("Forwarding to leader %s: %s", leaderID, utils.LoggingString(signedRequest.Request))
	_, err := (*n.Peers[leaderID].Client).TransferRequest(context.Background(), signedRequest)
	if err != nil {
		log.Warnf("Forwarding Failed: %s; %s", utils.LoggingString(signedRequest.Request), err.Error())
	}
}
