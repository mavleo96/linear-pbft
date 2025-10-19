package client

import (
	"context"
	"path/filepath"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// ClientRoutine is a persistent routine that processes transactions for a client
func ClientRoutine(ctx context.Context, clientID string, signalCh chan *TestSet, nodeClients map[string]pb.LinearPBFTClient) {
	privateKey, err := security.ReadPrivateKey(filepath.Join("./keys", "client", clientID+".pem"))
	if err != nil {
		log.Fatal(err)
	}
	// TODO: remove this
	publicKey, err := security.ReadPublicKey(filepath.Join("./keys", "client", clientID+".pub.pem"))
	if err != nil {
		log.Fatal(err)
	}
	for {
		select {
		// Wait for set id to process from main routine
		case testSet := <-signalCh:
			// leaderNode := "n1" // leader initialized to n1 by default
			// Process transactions for the set
			for _, t := range testSet.Transactions[clientID] {
				err := processTransaction(t, clientID, privateKey, publicKey)
				if err != nil {
					log.Fatal(err)
				}
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

func processTransaction(t *pb.Transaction, clientID string, privateKey []byte, publicKey []byte) error {
	// Create a signed transaction request
	timestamp := time.Now().UnixMilli()
	TransactionRequest := &pb.TransactionRequest{
		Transaction: t,
		Timestamp:   timestamp,
		Sender:      clientID,
	}
	signature := security.Sign(utils.MessageString(TransactionRequest), privateKey)
	TransactionRequest.Signature = signature

	// Verify the signature (dummy for now)
	ok := security.Verify(utils.MessageString(TransactionRequest), publicKey, TransactionRequest.Signature)
	log.Infof("%s <- %s: %t", clientID, utils.MessageString(t), ok)
	return nil
}
