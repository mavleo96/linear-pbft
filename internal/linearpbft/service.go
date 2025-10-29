package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/security"
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

	// Verify client signature
	ok := security.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature)
	if !ok {
		log.Warnf("Invalid client signature for request %s", request.String())
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Send reply to client if duplicate request
	if n.LastReply[request.Sender] != nil && request.Timestamp == n.LastReply[request.Sender].Timestamp {
		log.Infof("Received duplicate request from client %s for request %s, sending reply", request.Sender, utils.LoggingString(request))
		go n.SendReply(n.AssignSequenceNumber(request), request, n.LastReply[request.Sender].Result)
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

	// Assign sequence number to request
	sequenceNum := n.AssignSequenceNumber(request)

	// Add request to log record
	record := n.LogRecords[sequenceNum]
	if record.IsPrePrepared() {
		log.Infof("In Progress: %s", utils.LoggingString(request))
		return &emptypb.Empty{}, nil
	}

	// Create preprepare message
	preprepare := &pb.PrePrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      security.Digest(request),
	}
	signedPreprepare := &pb.SignedPrePrepareMessage{
		Message:   preprepare,
		Signature: security.Sign(preprepare, n.PrivateKey),
		Request:   request,
	}
	record.AddPrePrepareMessage(signedPreprepare)

	// Send preprepare message to all nodes and collect prepare messages
	prepareMsgs, err := n.SendPrePrepare(signedPreprepare, sequenceNum)
	if err != nil {
		// return nil, status.Errorf(codes.Internal, err.Error())
		return nil, nil
	}
	if prepareMsgs == nil {
		return &emptypb.Empty{}, nil
	}

	// Send prepare message to all nodes and collect commit messages
	commitMsgs, err := n.SendPrepare(prepareMsgs, sequenceNum)
	if err != nil {
		// return nil, status.Errorf(codes.Internal, err.Error())
		return nil, nil
	}
	if commitMsgs == nil {
		return &emptypb.Empty{}, nil
	}

	// Send commit message to all nodes
	committed, err := n.SendCommit(commitMsgs, sequenceNum)
	if err != nil {
		// return nil, status.Errorf(codes.Internal, err.Error())
		return nil, nil
	}
	if !committed {
		return nil, nil
	}

	// Execute transaction
	go n.TryExecute(n.AssignSequenceNumber(request))

	return &emptypb.Empty{}, nil
}

func (n *LinearPBFTNode) ReadOnlyRequest(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error) {
	request := signedRequest.Request

	// Verify client signature
	ok := security.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature)
	if !ok {
		log.Warnf("Invalid client signature for request %s", request.String())
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}
	balance, err := n.DB.GetBalance(request.Sender)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}
	message := &pb.TransactionResponse{
		ViewNumber: n.ViewNumber,
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
		Result:     int64(balance),
	}
	signedMessage := &pb.SignedTransactionResponse{
		Message:   message,
		Signature: security.Sign(message, n.PrivateKey),
	}
	log.Infof("Node %s: Read only request %s -> %d", n.ID, request.String(), balance)
	return signedMessage, nil
}

func (n *LinearPBFTNode) SendReply(sequenceNum int64, request *pb.TransactionRequest, result int64) {
	// Send reply to clients
	reply := &pb.TransactionResponse{
		ViewNumber: n.ViewNumber,
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
		Result:     result,
	}
	signedReply := &pb.SignedTransactionResponse{
		Message:   reply,
		Signature: security.Sign(reply, n.PrivateKey),
	}
	n.LastReply[request.Sender] = reply
	_, err := (*n.Clients[request.Sender].Client).ReceiveReply(context.Background(), signedReply)
	if err != nil {
		log.Fatal(err)
		return
	}
}

func (n *LinearPBFTNode) ForwardRequest(ctx context.Context, signedRequest *pb.SignedTransactionRequest) {
	// Forward request to leader
	leaderID := utils.ViewNumberToLeaderID(n.ViewNumber, n.N)
	leader := n.Peers[leaderID]
	log.Infof("Forwarding to leader %s: %s", leaderID, utils.LoggingString(signedRequest.Request))
	_, err := (*leader.Client).TransferRequest(context.Background(), signedRequest)
	if err != nil {
		log.Fatal(err)
		return
	}
}
