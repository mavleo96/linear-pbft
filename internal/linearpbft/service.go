package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/security"
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

	// TODO: need to ignore or forward request if not leader

	// Send preprepare message to all nodes
	prepareMsgs, err := n.SendPrePrepare(request)
	if err != nil {
		// return nil, status.Errorf(codes.Internal, err.Error())
		return nil, nil
	}
	if prepareMsgs == nil {
		return &emptypb.Empty{}, nil
	}

	commitMsgs, err := n.SendPrepare(prepareMsgs, n.AssignSequenceNumber(request))
	if err != nil {
		// return nil, status.Errorf(codes.Internal, err.Error())
		return nil, nil
	}
	if commitMsgs == nil {
		return &emptypb.Empty{}, nil
	}

	committed, err := n.SendCommit(commitMsgs, n.AssignSequenceNumber(request))
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
