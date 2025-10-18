package client

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// ClientRoutine is a persistent routine that processes transactions for a client
func ClientRoutine(ctx context.Context, clientID string, signalCh chan *TestSet, nodeClients map[string]pb.LinearPBFTClient) {
	for {
		select {
		// Wait for set id to process from main routine
		case testSet := <-signalCh:
			// leaderNode := "n1" // leader initialized to n1 by default
			// Process transactions for the set
			for _, t := range testSet.Transactions[clientID] {
				log.Info(t)
			}
			// Signal main routine that the set is done
			signalCh <- nil

		// Exit signal
		case <-ctx.Done():
			log.Infof("%s received exit signal", clientID)
			return
		}
	}
}

func ReconfigureNodes(liveNodes []*models.Node, byzantineNodes []*models.Node, attacks []*Attack) {
	// TODO: Implement reconfiguration
	log.Infof("Reconfigured nodes: %v", liveNodes)
	log.Infof("Byzantine nodes: %v", byzantineNodes)
	log.Infof("Attacks: %v", attacks)
}
