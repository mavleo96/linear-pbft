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

	return &emptypb.Empty{}, nil
}
