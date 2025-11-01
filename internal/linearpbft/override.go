package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (n *LinearPBFTNode) ReconfigureNode(ctx context.Context, changeStatusMessage *pb.ChangeStatusMessage) (*emptypb.Empty, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	n.Alive = changeStatusMessage.Alive
	n.Byzantine = changeStatusMessage.Byzantine
	log.Infof("Reconfigured node %s to alive: %t, byzantine: %t", n.ID, n.Alive, n.Byzantine)

	return &emptypb.Empty{}, nil
}
