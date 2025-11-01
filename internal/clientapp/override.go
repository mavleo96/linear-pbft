package clientapp

import (
	"context"
	"slices"
	"strings"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// ReconfigureNodes reconfigures the nodes based on the live, byzantine, and attack lists
func ReconfigureNodes(nodeMap map[string]*models.Node, liveNodes []*models.Node, byzantineNodes []*models.Node, attacks []*Attack) {
	log.Infof("Live nodes: %s", nodeListString(liveNodes))
	log.Infof("Byzantine nodes: %s", nodeListString(byzantineNodes))
	log.Infof("Attacks: %v", attacks)

	for _, node := range nodeMap {
		changeStatusMessage := &pb.ChangeStatusMessage{
			Alive:     slices.Contains(liveNodes, node),
			Byzantine: slices.Contains(byzantineNodes, node),
		}
		_, err := (*node.Client).ReconfigureNode(context.Background(), changeStatusMessage)
		if err != nil {
			log.Warn(err)
		}
	}
}

// SendResetCommand sends a reset command to all nodes
func SendResetCommand(nodeMap map[string]*models.Node) {
	log.Info("Reset command received")
}

// nodeListString returns a string representation of a list of nodes
func nodeListString(nodes []*models.Node) string {
	nodesString := make([]string, 0)
	for _, node := range nodes {
		nodesString = append(nodesString, node.ID)
	}
	return strings.Join(nodesString, ", ")
}
