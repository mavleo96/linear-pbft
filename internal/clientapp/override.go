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
	log.Infof("Live nodes: %s", nodeStringSlice(liveNodes))
	log.Infof("Byzantine nodes: %s", nodeStringSlice(byzantineNodes))
	log.Infof("Attacks: %v", attacks)

	for _, node := range nodeMap {
		changeStatusMessage := &pb.ChangeStatusMessage{
			Alive:                   slices.Contains(liveNodes, node),
			Byzantine:               slices.Contains(byzantineNodes, node),
			SignAttack:              false,
			CrashAttack:             false,
			DarkAttack:              false,
			DarkAttackNodes:         make([]string, 0),
			TimeAttack:              false,
			EquivocationAttack:      false,
			EquivocationAttackNodes: make([]string, 0),
		}
		for _, attack := range attacks {
			if attack.Type == "sign" {
				changeStatusMessage.SignAttack = true
			}
			if attack.Type == "crash" {
				changeStatusMessage.CrashAttack = true
			}
			if attack.Type == "dark" {
				changeStatusMessage.DarkAttack = true
				changeStatusMessage.DarkAttackNodes = nodeStringSlice(attack.AttackNodes)
			}
			if attack.Type == "time" {
				changeStatusMessage.TimeAttack = true
			}
			if attack.Type == "equivocation" {
				changeStatusMessage.EquivocationAttack = true
				changeStatusMessage.EquivocationAttackNodes = nodeStringSlice(attack.AttackNodes)
			}
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

// nodeStringSlice returns a slice of strings representing the IDs of the nodes
func nodeStringSlice(nodes []*models.Node) []string {
	nodeStrings := make([]string, 0)
	for _, node := range nodes {
		nodeStrings = append(nodeStrings, node.ID)
	}
	return nodeStrings
}
