package clientapp

import (
	"context"
	"slices"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// ReconfigureNodes reconfigures the nodes based on the live, byzantine, and attack lists
func ReconfigureNodes(nodeMap map[string]*models.Node, liveNodes []*models.Node, byzantineNodes []*models.Node, attacks []*Attack) {
	log.Infof("Live nodes: %v", liveNodes)
	log.Infof("Byzantine nodes: %v", byzantineNodes)
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

func SendResetCommand(nodeMap map[string]*models.Node) {
	log.Info("Reset command received")
}
