package linearpbft

import (
	"context"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// BenchmarkRPC handles a benchmark request
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

// BenchmarkSendReply sends a reply to the client for a benchmark request
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

	for attempt := 1; attempt <= MaxSendAttempts; attempt++ {
		err := n.clientTransport.SendReply(n.serverCtx, request.Sender, signedResponse)
		if err == nil {
			return
		}
		log.Warnf("Benchmark RPC: failed to send response to client %s (attempt %d/%d): %v", request.Sender, attempt, MaxSendAttempts, err)
		time.Sleep(SendAttemptDelay)
	}

	log.Errorf("Benchmark RPC: giving up sending response to client %s after %d attempts", request.Sender, MaxSendAttempts)
}
