package network

import (
	"context"
	"io"

	"github.com/mavleo96/linear-pbft/pb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// NodeTransport defines the interface for node-to-node communication
// Methods take peerID to route messages to specific peers
type NodeTransport interface {
	// SendTransfer sends a transaction request to a peer (fire-and-forget)
	SendTransfer(ctx context.Context, peerID string, req *pb.SignedTransactionRequest) error

	// SendReadOnly sends a read-only transaction request to a peer and waits for response
	SendReadOnly(ctx context.Context, peerID string, req *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error)

	// SendPrePrepare sends a pre-prepare message to a peer and waits for prepare response
	SendPrePrepare(ctx context.Context, peerID string, req *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error)

	// SendPrepare sends a prepare message to a peer and waits for commit response
	SendPrepare(ctx context.Context, peerID string, req *pb.SignedPrepareMessage) (*pb.SignedCommitMessage, error)

	// SendCommit sends a commit message to a peer (fire-and-forget)
	SendCommit(ctx context.Context, peerID string, req *pb.SignedCommitMessage) error

	// SendCheckpoint sends a checkpoint message to a peer (fire-and-forget)
	SendCheckpoint(ctx context.Context, peerID string, req *pb.SignedCheckpointMessage) error

	// SendViewChange sends a view change message to a peer (fire-and-forget)
	SendViewChange(ctx context.Context, peerID string, req *pb.SignedViewChangeMessage) error

	// SendNewView sends a new view message to a peer and returns a stream of prepare messages
	SendNewView(ctx context.Context, peerID string, req *pb.SignedNewViewMessage) (NewViewStream, error)

	// GetRequest requests a transaction by digest from a peer
	GetRequest(ctx context.Context, peerID string, req *pb.GetRequestMessage) (*pb.SignedTransactionRequest, error)

	// GetCheckpoint requests a checkpoint by sequence number from a peer
	GetCheckpoint(ctx context.Context, peerID string, req *pb.GetCheckpointMessage) (*pb.Checkpoint, error)

	// SendReconfigure sends a reconfiguration message to a peer (fire-and-forget)
	SendReconfigure(ctx context.Context, peerID string, req *pb.ChangeStatusMessage) error

	// SendReset sends a reset message to a peer (fire-and-forget)
	SendReset(ctx context.Context, peerID string, req *pb.ResetRequest) error

	// SendBenchmark sends a benchmark request to a peer (fire-and-forget)
	SendBenchmark(ctx context.Context, peerID string, req *pb.SignedTransactionRequest) error

	// Debug methods (fire-and-forget)
	SendPrintLog(ctx context.Context, peerID string, req *wrapperspb.Int64Value) error
	SendPrintDB(ctx context.Context, peerID string, req *wrapperspb.Int64Value) error
	SendPrintStatus(ctx context.Context, peerID string, req *pb.StatusRequest) error
	SendPrintView(ctx context.Context, peerID string, req *wrapperspb.Int64Value) error

	// Close closes the transport connection
	Close() error
}

// NewViewStream represents a stream of prepare messages from SendNewView
type NewViewStream interface {
	Recv() (*pb.SignedPrepareMessage, error)
	io.Closer
}

// ClientTransport defines the interface for client-to-node communication
type ClientTransport interface {
	// SendTransfer sends a transaction request to a node (fire-and-forget)
	SendTransfer(ctx context.Context, nodeID string, req *pb.SignedTransactionRequest) error

	// SendReadOnly sends a read-only transaction request to a node and waits for response
	SendReadOnly(ctx context.Context, nodeID string, req *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error)

	// SendBenchmark sends a benchmark request to a node (fire-and-forget)
	SendBenchmark(ctx context.Context, nodeID string, req *pb.SignedTransactionRequest) error

	// SendReconfigure sends a reconfiguration message to a node (fire-and-forget)
	SendReconfigure(ctx context.Context, nodeID string, req *pb.ChangeStatusMessage) error

	// SendReset sends a reset message to a node (fire-and-forget)
	SendReset(ctx context.Context, nodeID string, req *pb.ResetRequest) error

	// Debug methods (fire-and-forget)
	SendPrintLog(ctx context.Context, nodeID string, req *wrapperspb.Int64Value) error
	SendPrintDB(ctx context.Context, nodeID string, req *wrapperspb.Int64Value) error
	SendPrintStatus(ctx context.Context, nodeID string, req *pb.StatusRequest) error
	SendPrintView(ctx context.Context, nodeID string, req *wrapperspb.Int64Value) error

	// Close closes the transport connection
	Close() error
}

// ClientAppTransport defines the interface for node-to-client communication
type ClientAppTransport interface {
	// SendReply sends a transaction response to a client (fire-and-forget)
	SendReply(ctx context.Context, clientID string, resp *pb.SignedTransactionResponse) error

	// Close closes the transport connection
	Close() error
}
