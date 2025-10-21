package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// LinearPBFTNode represents a LinearPBFT node
type LinearPBFTNode struct {
	*models.Node
	PrivateKey []byte
	DB         *database.Database
	Peers      map[string]*models.Node
	Clients    map[string]*models.Client
	*pb.UnimplementedLinearPBFTNodeServer
}

func (n *LinearPBFTNode) ReadOnly(ctx context.Context, req *pb.TransactionRequest) (*emptypb.Empty, error) {

	// Verify signature
	ok := security.Verify(utils.MessageString(req), n.Clients[req.Sender].PublicKey, req.Signature)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "invalid signature")
	}

	// Process transaction
	balance, err := n.DB.GetBalance(req.Transaction.Sender)
	if err != nil {
		log.Fatal(err)
	}
	response := &pb.TransactionResponse{
		ViewNumber: 0,
		Timestamp:  req.Timestamp,
		Sender:     req.Sender,
		NodeID:     n.ID,
		Result:     int64(balance),
	}
	response.Signature = security.Sign(utils.MessageString(response), n.PrivateKey)

	// Send reply to client
	_, err = (*n.Clients[req.Sender].Client).ReceiveReply(ctx, response)
	if err != nil {
		log.Fatal(err)
	}
	return &emptypb.Empty{}, nil
}
