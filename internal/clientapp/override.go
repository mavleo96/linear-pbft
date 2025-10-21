package clientapp

import (
	"github.com/mavleo96/bft-mavleo96/internal/models"
	log "github.com/sirupsen/logrus"
)

func ReconfigureNodes(liveNodes []*models.Node, byzantineNodes []*models.Node, attacks []*Attack) {
	// TODO: Implement reconfiguration
	log.Infof("Reconfigured nodes: %v", liveNodes)
	log.Infof("Byzantine nodes: %v", byzantineNodes)
	log.Infof("Attacks: %v", attacks)
}
