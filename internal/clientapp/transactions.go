package clientapp

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

const (
	maxAttempts   = 1000
	clientTimeout = 1000 * time.Millisecond
)

// TODO: change this to read write operations
func processTransaction(request *pb.SignedTransactionRequest, clientID string, leaderNode string, nodeMap map[string]*models.Node, resultCh chan int64) (int64, error) {

	var result int64
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Create context with timeout common for current attempt
		ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
		// If first attempt
		// 1. send to leader node
		if attempt == 1 {
			leaderClient := *nodeMap[leaderNode].Client
			_, err := leaderClient.TransferRequest(context.Background(), request)
			if err != nil {
				log.Warnf("Error sending transaction to leader: %s", err.Error())
			}
		} else {
			// If not first attempt then multicast to all nodes
			for _, node := range nodeMap {
				go func(r *pb.SignedTransactionRequest, nID string, nClient pb.LinearPBFTNodeClient) {
					_, err := nClient.TransferRequest(context.Background(), r)
					if err != nil {
						log.Warnf("Error sending transaction to node: %s", err.Error())
					}
				}(request, node.ID, *node.Client)
			}
		}

		select {
		case result = <-resultCh:
			cancel()
			return result, nil
		case <-ctx.Done():
			cancel()
			log.Warnf("%s: %s -> attempt %d timed out", clientID, utils.LoggingString(request.Request), attempt)
		}
	}
	return 0, errors.New("transaction timed out")
}

func processReadOnlyTransaction(request *pb.SignedTransactionRequest, clientID string, nodeMap map[string]*models.Node) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	// Multicast to all nodes
	responseCh := make(chan *pb.SignedTransactionResponse, len(nodeMap))
	wg := sync.WaitGroup{}

	for _, node := range nodeMap {
		wg.Add(1)
		go func(r *pb.SignedTransactionRequest, nID string, nClient pb.LinearPBFTNodeClient) {
			defer wg.Done()
			resp, err := nClient.ReadOnlyRequest(context.Background(), r)
			if err != nil {
				// log.Fatal(err)
				// log.Warnf("Error reading only request: %s", err.Error())
				return
			}
			responseCh <- resp
		}(request, node.ID, *node.Client)
	}

	go func() {
		wg.Wait()
		close(responseCh)
	}()

	resultMap := make(map[int64]int64)
	for {
		select {
		case signedResponse, ok := <-responseCh:
			if !ok {
				return 0, errors.New("no majority")
			}
			message := signedResponse.Message

			// verify signature
			if !crypto.Verify(message, nodeMap[message.NodeID].PublicKey, signedResponse.Signature) {
				// log.Warnf("Invalid signature from node: %s", message.NodeID)
				continue
			}

			// Add to reply map
			resultMap[message.Result]++

			// Check if we have enough matches
			maxVal, maxCnt := utils.MaxByValue(resultMap)
			if maxCnt >= 5 {
				return maxVal, nil
			}
		case <-ctx.Done():
			return 0, errors.New("timed out")
		}
	}
}
