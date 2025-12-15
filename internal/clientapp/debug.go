package clientapp

import (
	"context"

	"github.com/mavleo96/linear-pbft/internal/models"
	"github.com/mavleo96/linear-pbft/internal/network"
	networkgrpc "github.com/mavleo96/linear-pbft/internal/network/grpc"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// createNodeTransport creates a ClientTransport from a node map
func createNodeTransport(nodeMap map[string]*models.Node) (network.ClientTransport, error) {
	nodeAddresses := make(map[string]string, len(nodeMap))
	for id, node := range nodeMap {
		nodeAddresses[id] = node.Address
	}
	return networkgrpc.NewClientTransport(nodeAddresses)
}

// SendPrintLogCommand sends a print log command to all nodes
func SendPrintLogCommand(ctx context.Context, nodeMap map[string]*models.Node, testSet int64) error {
	log.Info("Print log command received")
	transport, err := createNodeTransport(nodeMap)
	if err != nil {
		return err
	}
	defer transport.Close()

	for _, node := range nodeMap {
		go func(nodeID string) {
			err := transport.SendPrintLog(ctx, nodeID, &wrapperspb.Int64Value{Value: testSet})
			if err != nil {
				log.Warnf("Error sending print log command to node %s: %v", nodeID, err)
			}
		}(node.ID)
	}
	return nil
}

// SendPrintDBCommand sends a print db command to all nodes
func SendPrintDBCommand(ctx context.Context, nodeMap map[string]*models.Node, testSet int64) error {
	log.Info("Print db command received")
	transport, err := createNodeTransport(nodeMap)
	if err != nil {
		return err
	}
	defer transport.Close()

	for _, node := range nodeMap {
		go func(nodeID string) {
			err := transport.SendPrintDB(ctx, nodeID, &wrapperspb.Int64Value{Value: testSet})
			if err != nil {
				log.Warnf("Error sending print db command to node %s: %v", nodeID, err)
			}
		}(node.ID)
	}
	return nil
}

// SendPrintStatusCommand sends a print status command to all nodes
func SendPrintStatusCommand(ctx context.Context, nodeMap map[string]*models.Node, testSet int64, sequenceNum int64) error {
	if sequenceNum == 0 {
		log.Infof("Print status command received for all sequence numbers")
	} else {
		log.Infof("Print status command received for %d", sequenceNum)
	}
	transport, err := createNodeTransport(nodeMap)
	if err != nil {
		return err
	}
	defer transport.Close()

	for _, node := range nodeMap {
		go func(nodeID string) {
			err := transport.SendPrintStatus(ctx, nodeID, &pb.StatusRequest{TestSet: testSet, SequenceNum: sequenceNum})
			if err != nil {
				log.Warnf("Error sending print status command to node %s: %v", nodeID, err)
			}
		}(node.ID)
	}
	return nil
}

// SendPrintViewCommand sends a print view command to all nodes
func SendPrintViewCommand(ctx context.Context, nodeMap map[string]*models.Node, testSet int64) error {
	log.Info("Print view command received")
	transport, err := createNodeTransport(nodeMap)
	if err != nil {
		return err
	}
	defer transport.Close()

	for _, node := range nodeMap {
		go func(nodeID string) {
			err := transport.SendPrintView(ctx, nodeID, &wrapperspb.Int64Value{Value: testSet})
			if err != nil {
				log.Warnf("Error sending print view command to node %s: %v", nodeID, err)
			}
		}(node.ID)
	}
	return nil
}
