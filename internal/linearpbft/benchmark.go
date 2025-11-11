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
	"google.golang.org/protobuf/types/known/emptypb"
)

// BenchmarkHandler manages signal channels for YCSB benchmarking
type BenchmarkHandler struct {
	mutex sync.RWMutex
}

// NewBenchmarkHandler creates a new BenchmarkHandler
func NewBenchmarkHandler() *BenchmarkHandler {
	return &BenchmarkHandler{
		mutex: sync.RWMutex{},
	}
}

// BenchmarkRPC handles a benchmark request
// func (n *LinearPBFTNode) BenchmarkRPC(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error) {
func (n *LinearPBFTNode) BenchmarkRPC(ctx context.Context, signedRequest *pb.SignedTransactionRequest) (*emptypb.Empty, error) {
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

	// Only primary handles the message; backups just wait for pre-prepare messages
	primaryID := utils.ViewNumberToPrimaryID(n.state.GetViewNumber(), n.config.N)
	if primaryID == n.ID {
		go n.handler.LeaderTransactionRequestHandler(signedRequest)
	}
	return &emptypb.Empty{}, nil
}

func (n *LinearPBFTNode) BenchmarkSendReply(signedRequest *pb.SignedTransactionRequest, result any) {
	// Build response based on transaction type
	request := signedRequest.Request
	tx := request.Transaction
	message := &pb.TransactionResponse{
		ViewNumber: n.state.GetViewNumber(),
		Timestamp:  request.Timestamp,
		Sender:     request.Sender,
		NodeID:     n.ID,
	}

	switch tx.Type {
	case "ycsb_read":
		if resultData, ok := result.(map[string][]byte); ok {
			log.Infof("Benchmark RPC: Received result data for read operation: %v", resultData)
			message.ResultData = resultData
		} else {
			log.Warnf("Benchmark RPC: Invalid result type for read operation: %v", result)
			message.Error = "invalid result type for read operation"
		}

	case "ycsb_scan":
		if results, ok := result.([]map[string][]byte); ok {
			scanResults := make([]*pb.ScanResult, 0, len(results))
			for _, r := range results {
				scanResults = append(scanResults, &pb.ScanResult{
					Fields: r,
				})
			}
			log.Infof("Benchmark RPC: Received scan results: %v", scanResults)
			message.ScanResults = scanResults
		} else {
			log.Warnf("Benchmark RPC: Invalid result type for scan operation: %v", result)
			message.Error = "invalid result type for scan operation"
		}

	case "ycsb_write", "ycsb_update", "ycsb_delete":
		if result, ok := result.(bool); ok && result {
			log.Infof("Benchmark RPC: Received result for write/update/delete operation: %v", result)
			message.Result = utils.BoolToInt64(result)
		} else {
			log.Warnf("Benchmark RPC: Invalid result type for write/update/delete operation: %v", result)
			message.Error = "invalid result type for write/update/delete operation"
		}

	default:
		log.Warnf("Benchmark RPC: Unknown transaction type: %s", tx.Type)
		message.Error = "unknown transaction type"
	}

	// Sign the response
	signedResponse := &pb.SignedTransactionResponse{
		Message:   message,
		Signature: crypto.Sign(message, n.handler.privateKey1),
	}

	n.logger.AddSentTransactionResponse(signedResponse)

	log.Infof("Benchmark RPC: Sending response: %s", utils.LoggingString(signedResponse))
	_, err := (*n.clients[request.Sender].Client).ReceiveReply(context.Background(), signedResponse)
	if err != nil {
		log.Fatal(err)
	}
}
