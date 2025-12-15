package clientapp

import (
	"context"
	"slices"

	"github.com/mavleo96/linear-pbft/internal/models"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
)

// ReconfigureNodes reconfigures the nodes based on the live, byzantine, and attack lists
func ReconfigureNodes(ctx context.Context, nodeMap map[string]*models.Node, liveNodes []*models.Node, byzantineNodes []*models.Node, attacks []*Attack) {
	log.Infof("Live nodes: %s", nodeStringSlice(liveNodes))
	log.Infof("Byzantine nodes: %s", nodeStringSlice(byzantineNodes))
	log.Infof("Attacks: %v", attacks)

	transport, err := createNodeTransport(nodeMap)
	if err != nil {
		log.Errorf("Failed to create transport for reconfiguration: %v", err)
		return
	}
	defer transport.Close()

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
		err := transport.SendReconfigure(ctx, node.ID, changeStatusMessage)
		if err != nil {
			log.Warn(err)
		}
	}
}

// SendResetCommand sends a reset command to all nodes
func SendResetCommand(ctx context.Context, nodeMap map[string]*models.Node, initBalance int64) {
	log.Info("Node Reset command received")
	transport, err := createNodeTransport(nodeMap)
	if err != nil {
		log.Errorf("Failed to create transport for reset: %v", err)
		return
	}
	defer transport.Close()

	for _, node := range nodeMap {
		err := transport.SendReset(ctx, node.ID, &pb.ResetRequest{InitBalance: initBalance})
		if err != nil {
			log.Warnf("Error sending reset command to node %s: %v", node.ID, err)
		}
	}
}

// nodeStringSlice returns a slice of strings representing the IDs of the nodes
func nodeStringSlice(nodes []*models.Node) []string {
	nodeStrings := make([]string, 0)
	for _, node := range nodes {
		nodeStrings = append(nodeStrings, node.ID)
	}
	return nodeStrings
}
