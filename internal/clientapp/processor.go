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
	clientTimeout = 10000 * time.Millisecond
)

// Processor processes transactions
type Processor struct {
	clientID   string
	state      *State
	nodes      *NodeMap
	privateKey []byte

	// Channels
	resultCh <-chan int64
}

// ProcessTransaction processes a transaction
func (p *Processor) ProcessTransaction(ctx context.Context, t *pb.Transaction) (int64, error) {
	// Create signed transaction request
	timestamp := time.Now().UnixMilli()
	request := &pb.TransactionRequest{
		Transaction: t,
		Timestamp:   timestamp,
		Sender:      p.clientID,
	}
	signedRequest := &pb.SignedTransactionRequest{
		Request:   request,
		Signature: crypto.Sign(request, p.privateKey),
	}

	// If transaction is read-only then try read-only processing
	if t.Type == "read" {
		result, err := p.processReadOnlyTransaction(ctx, signedRequest)
		if err == nil {
			return result, nil
		}
	}
	return p.processWriteTransaction(ctx, signedRequest)
}

// processWriteTransaction processes a write transaction
func (p *Processor) processWriteTransaction(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (int64, error) {
	var result int64
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// ctxWithTimeout, cancel := context.WithTimeout(context.Background(), clientTimeout)
		// If first attempt send to primary node
		if attempt == 1 {
			primaryID := utils.ViewNumberToLeaderID(p.state.GetViewNumber(), p.nodes.N)
			_, err := (*p.nodes.GetNode(primaryID).Client).TransferRequest(context.Background(), signedRequest)
			if err != nil {
				log.Warnf("%s -> %s: error sending transaction to %s: %s", p.clientID, utils.LoggingString(signedRequest.Request), primaryID, err.Error())
			}
		} else {
			// If not first attempt multicast to all nodes
			for _, node := range p.nodes.GetNodes() {
				go func(node *models.Node, signedRequest *pb.SignedTransactionRequest) {
					_, err := (*node.Client).TransferRequest(context.Background(), signedRequest)
					if err != nil {
						log.Warnf("%s -> %s: error sending transaction to %s: %s", p.clientID, utils.LoggingString(signedRequest.Request), node.ID, err.Error())
					}
				}(node, signedRequest)
			}
		}

		select {
		// If results with f+1 matches in aggregator are received, return result
		case result = <-p.resultCh:
			return result, nil
		// If timeout reached, retry
		case <-time.After(clientTimeout):
			log.Warnf("%s -> %s: retrying transaction (attempt %d)", p.clientID, utils.LoggingString(signedRequest.Request), attempt)
		// If context done, return error
		case <-ctx.Done():
			log.Infof("%s: received exit signal on process write transaction", p.clientID)
			return 0, ctx.Err()
		}
	}
	log.Warnf("%s -> %s: transaction attempt limit reached", p.clientID, utils.LoggingString(signedRequest.Request))
	return 0, errors.New("transaction attempt limit reached")
}

// processReadOnlyTransaction processes a read-only transaction
func (p *Processor) processReadOnlyTransaction(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (int64, error) {
	// Multicast the request to all nodes
	responseCh := make(chan *pb.SignedTransactionResponse, p.nodes.N)
	wg := sync.WaitGroup{}
	for _, node := range p.nodes.GetNodes() {
		wg.Add(1)
		go func(node *models.Node, signedRequest *pb.SignedTransactionRequest) {
			defer wg.Done()
			resp, err := (*node.Client).ReadOnlyRequest(ctx, signedRequest)
			if err != nil {
				log.Warnf("%s -> %s: error sending read-only request to %s: %s", p.clientID, utils.LoggingString(signedRequest.Request), node.ID, err.Error())
				return
			}
			responseCh <- resp
		}(node, signedRequest)
	}

	// Close response channel after all responses are received
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Collect responses and check for super-majority
	responseCounter := make(map[int64]int64)
	for {
		select {
		// If response is received, add to response counter
		case signedResp, channelOpen := <-responseCh:
			// If majority not reached yet and no more responses, return error
			if !channelOpen {
				log.Warnf("%s -> %s: no majority", p.clientID, utils.LoggingString(signedRequest.Request))
				return 0, errors.New("no majority")
			}

			resp := signedResp.Message

			// Verify signature
			ok := crypto.Verify(resp, p.nodes.GetPublicKey(resp.NodeID), signedResp.Signature)
			if !ok {
				continue
			}

			// Add response to state
			responseCounter[resp.Result]++

			// Check if we have enough matches
			maxVal, maxCnt := utils.MaxByValue(responseCounter)
			if maxCnt >= 2*p.nodes.F+1 {
				return maxVal, nil
			}
		// If timeout reached, return error
		case <-time.After(clientTimeout):
			// If timeout reached, return error
			log.Warnf("%s -> %s: read-only transaction timed out", p.clientID, utils.LoggingString(signedRequest.Request))
			return 0, errors.New("read-only transaction timed out")
		// If context done, return error
		case <-ctx.Done():
			// If context done, return error
			log.Warnf("%s: received exit signal on read-only transaction", p.clientID)
			return 0, ctx.Err()
		}
	}
}
