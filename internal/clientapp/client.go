package clientapp

import (
	"context"
	"errors"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// TODO: raise this to 1000 later
const (
	maxAttempts   = 3
	clientTimeout = 60000 * time.Millisecond // 1 minute
)

// TODO: change this to read write operations
func processTransaction(request *pb.SignedTransactionRequest, clientID string, leaderNode *string, nodeMap map[string]*models.Node, resultCh chan int64) (int64, error) {

	var result int64
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		log.Infof("%s: Attempt %d", clientID, attempt)
		// Create context with timeout common for current attempt
		ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
		// If first attempt
		// 1. send to leader node
		if attempt == 1 {
			leaderClient := *nodeMap[*leaderNode].Client
			_, err := leaderClient.TransferRequest(context.Background(), request)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			// If not first attempt then multicast to all nodes
			for _, node := range nodeMap {
				go func(r *pb.SignedTransactionRequest, nID string, nClient pb.LinearPBFTNodeClient) {
					_, err := nClient.TransferRequest(context.Background(), r)
					if err != nil {
						log.Fatal(err)
					}
				}(request, node.ID, *node.Client)
			}
		}

		select {
		case result = <-resultCh:
			// log.Infof("%s: %s -> %d", clientID, request.Request.String(), result)
			cancel()
			return result, nil
		case <-ctx.Done():
			cancel()
			log.Warnf("Client timeout for attempt %d", attempt)
		}
	}
	return 0, errors.New("transaction timed out")
}
