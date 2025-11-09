package linearpbft

import (
	"context"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BenchmarkHandler manages signal channels for YCSB benchmarking
type BenchmarkHandler struct {
	mutex       sync.RWMutex
	signalChMap map[[32]byte]chan any
}

// CreateSignalCh creates a new signal channel for a given request digest
func (h *BenchmarkHandler) CreateSignalCh(digest []byte) chan any {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if _, ok := h.signalChMap[utils.To32Bytes(digest)]; !ok {
		h.signalChMap[utils.To32Bytes(digest)] = make(chan any)
	}
	return h.signalChMap[utils.To32Bytes(digest)]
}

// CloseSignalCh closes a signal channel for a given request digest
func (h *BenchmarkHandler) CloseSignalCh(digest []byte) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	close(h.signalChMap[utils.To32Bytes(digest)])
	delete(h.signalChMap, utils.To32Bytes(digest))
}

// GetSendSignalCh returns a channel to send results to
func (h *BenchmarkHandler) GetSendSignalCh(digest []byte) chan<- any {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.signalChMap[utils.To32Bytes(digest)]
}

// GetReceiveSignalCh returns a channel to receive results from
func (h *BenchmarkHandler) GetReceiveSignalCh(digest []byte) <-chan any {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.signalChMap[utils.To32Bytes(digest)]
}

// NewBenchmarkHandler creates a new BenchmarkHandler
func NewBenchmarkHandler() *BenchmarkHandler {
	return &BenchmarkHandler{
		mutex:       sync.RWMutex{},
		signalChMap: make(map[[32]byte]chan any),
	}
}

// BenchmarkRPC handles a benchmark request
func (n *LinearPBFTNode) BenchmarkRPC(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error) {
	request := signedRequest.Request

	// Ignore request if in view change phase
	if n.state.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedRequest))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify client signature
	if !cmp.Equal(crypto.Digest(signedRequest), DigestNoOp) &&
		!crypto.Verify(request, n.clients[request.Sender].PublicKey, signedRequest.Signature) {
		log.Warnf("Invalid client signature for request %s", utils.LoggingString(signedRequest))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Add request to transaction map (needed for PRE-PREPARE processing)
	digest := crypto.Digest(signedRequest)
	if n.state.TransactionMap.Get(digest) == nil {
		log.Infof("Adding request to transaction map: %s", utils.LoggingString(signedRequest))
		n.state.TransactionMap.Set(digest, signedRequest)
	}

	// Create signal channel (all nodes wait on this channel for execution result)
	signalCh := n.benchmarkHandler.CreateSignalCh(digest)

	// Only primary handles the message; backups just wait on the channel
	primaryID := utils.ViewNumberToPrimaryID(n.state.GetViewNumber(), n.config.N)
	if primaryID == n.ID {
		// Primary: process the request (will trigger consensus)
		go n.handler.LeaderTransactionRequestHandler(signedRequest)
	}

	// Backups: just wait on the channel (will receive PRE-PREPARE messages and process through normal consensus)
	// Wait for result from execution (all nodes wait, including backups)
	var resultValue any
	select {
	case resultValue = <-signalCh:
		// Result received, continue to build response
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Build response based on transaction type
	tx := request.Transaction
	message := &pb.TransactionResponse{
		ViewNumber: n.state.GetViewNumber(),
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
	}

	switch tx.Type {
	case "ycsb_read":
		if resultData, ok := resultValue.(map[string][]byte); ok {
			message.ResultData = resultData
		} else {
			message.Error = "invalid result type for read operation"
		}

	case "ycsb_scan":
		if results, ok := resultValue.([]map[string][]byte); ok {
			scanResults := make([]*pb.ScanResult, 0, len(results))
			for _, r := range results {
				scanResults = append(scanResults, &pb.ScanResult{
					Fields: r,
				})
			}
			message.ScanResults = scanResults
		} else {
			message.Error = "invalid result type for scan operation"
		}

	case "ycsb_write", "ycsb_update", "ycsb_delete":
		if result, ok := resultValue.(int64); ok {
			message.Result = result
		} else {
			message.Error = "invalid result type for write/update/delete operation"
		}

	default:
		message.Error = "unknown transaction type"
	}

	// Sign the response
	signedResponse := &pb.SignedTransactionResponse{
		Message:   message,
		Signature: crypto.Sign(message, n.handler.privateKey1),
	}

	return signedResponse, nil
}
