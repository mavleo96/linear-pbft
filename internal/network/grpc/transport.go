package grpc

import (
	"context"
	"fmt"
	"sync"

	"github.com/mavleo96/linear-pbft/internal/network"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// grpcNodeTransport implements NodeTransport using gRPC
type grpcNodeTransport struct {
	mu    sync.RWMutex
	peers map[string]pb.LinearPBFTNodeClient
	conns map[string]*grpc.ClientConn
}

// grpcClientTransport implements ClientTransport using gRPC
type grpcClientTransport struct {
	mu    sync.RWMutex
	nodes map[string]pb.LinearPBFTNodeClient
	conns map[string]*grpc.ClientConn
}

// grpcClientAppTransport implements ClientAppTransport using gRPC
type grpcClientAppTransport struct {
	mu      sync.RWMutex
	clients map[string]pb.ClientAppClient
	conns   map[string]*grpc.ClientConn
}

// grpcNewViewStream wraps the gRPC stream for NewViewRequest
type grpcNewViewStream struct {
	stream pb.LinearPBFTNode_NewViewRequestClient
}

// Helper to close all connections
func closeConnections(conns map[string]*grpc.ClientConn) error {
	var firstErr error
	for _, conn := range conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Helper to get peer with error handling
func (t *grpcNodeTransport) getPeer(peerID string) (pb.LinearPBFTNodeClient, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	peer, ok := t.peers[peerID]
	if !ok {
		return nil, fmt.Errorf("peer %s not found", peerID)
	}
	return peer, nil
}

// Helper to get node with error handling
func (t *grpcClientTransport) getNode(nodeID string) (pb.LinearPBFTNodeClient, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	node, ok := t.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %s not found", nodeID)
	}
	return node, nil
}

// Helper to get client with error handling
func (t *grpcClientAppTransport) getClient(clientID string) (pb.ClientAppClient, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	client, ok := t.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client %s not found", clientID)
	}
	return client, nil
}

// NewNodeTransport creates a new gRPC-based NodeTransport
func NewNodeTransport(peers map[string]string) (network.NodeTransport, error) {
	t := &grpcNodeTransport{
		peers: make(map[string]pb.LinearPBFTNodeClient),
		conns: make(map[string]*grpc.ClientConn),
	}

	for peerID, address := range peers {
		conn, err := utils.Connect(address)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("failed to connect to peer %s at %s: %w", peerID, address, err)
		}
		t.peers[peerID] = pb.NewLinearPBFTNodeClient(conn)
		t.conns[peerID] = conn
	}

	return t, nil
}

// NewClientTransport creates a new gRPC-based ClientTransport
func NewClientTransport(nodes map[string]string) (network.ClientTransport, error) {
	t := &grpcClientTransport{
		nodes: make(map[string]pb.LinearPBFTNodeClient),
		conns: make(map[string]*grpc.ClientConn),
	}

	for nodeID, address := range nodes {
		conn, err := utils.Connect(address)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("failed to connect to node %s at %s: %w", nodeID, address, err)
		}
		t.nodes[nodeID] = pb.NewLinearPBFTNodeClient(conn)
		t.conns[nodeID] = conn
	}

	return t, nil
}

// NewClientAppTransport creates a new gRPC-based ClientAppTransport
func NewClientAppTransport(clients map[string]string) (network.ClientAppTransport, error) {
	t := &grpcClientAppTransport{
		clients: make(map[string]pb.ClientAppClient),
		conns:   make(map[string]*grpc.ClientConn),
	}

	for clientID, address := range clients {
		conn, err := utils.Connect(address)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("failed to connect to client %s at %s: %w", clientID, address, err)
		}
		t.clients[clientID] = pb.NewClientAppClient(conn)
		t.conns[clientID] = conn
	}

	return t, nil
}

// NodeTransport implementation

func (t *grpcNodeTransport) SendTransfer(ctx context.Context, peerID string, req *pb.SignedTransactionRequest) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.TransferRequest(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendReadOnly(ctx context.Context, peerID string, req *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error) {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return nil, err
	}
	return peer.ReadOnlyRequest(ctx, req)
}

func (t *grpcNodeTransport) SendPrePrepare(ctx context.Context, peerID string, req *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error) {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return nil, err
	}
	return peer.PrePrepareRequest(ctx, req)
}

func (t *grpcNodeTransport) SendPrepare(ctx context.Context, peerID string, req *pb.SignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return nil, err
	}
	return peer.PrepareRequest(ctx, req)
}

func (t *grpcNodeTransport) SendCommit(ctx context.Context, peerID string, req *pb.SignedCommitMessage) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.CommitRequest(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendCheckpoint(ctx context.Context, peerID string, req *pb.SignedCheckpointMessage) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.CheckpointRequest(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendViewChange(ctx context.Context, peerID string, req *pb.SignedViewChangeMessage) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.ViewChangeRequest(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendNewView(ctx context.Context, peerID string, req *pb.SignedNewViewMessage) (network.NewViewStream, error) {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return nil, err
	}
	stream, err := peer.NewViewRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return &grpcNewViewStream{stream: stream}, nil
}

func (t *grpcNodeTransport) GetRequest(ctx context.Context, peerID string, req *pb.GetRequestMessage) (*pb.SignedTransactionRequest, error) {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return nil, err
	}
	return peer.GetRequest(ctx, req)
}

func (t *grpcNodeTransport) GetCheckpoint(ctx context.Context, peerID string, req *pb.GetCheckpointMessage) (*pb.Checkpoint, error) {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return nil, err
	}
	return peer.GetCheckpoint(ctx, req)
}

func (t *grpcNodeTransport) SendReconfigure(ctx context.Context, peerID string, req *pb.ChangeStatusMessage) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.ReconfigureNode(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendReset(ctx context.Context, peerID string, req *pb.ResetRequest) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.ResetNode(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendBenchmark(ctx context.Context, peerID string, req *pb.SignedTransactionRequest) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.BenchmarkRPC(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendPrintLog(ctx context.Context, peerID string, req *wrapperspb.Int64Value) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.PrintLog(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendPrintDB(ctx context.Context, peerID string, req *wrapperspb.Int64Value) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.PrintDB(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendPrintStatus(ctx context.Context, peerID string, req *pb.StatusRequest) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.PrintStatus(ctx, req)
	return err
}

func (t *grpcNodeTransport) SendPrintView(ctx context.Context, peerID string, req *wrapperspb.Int64Value) error {
	peer, err := t.getPeer(peerID)
	if err != nil {
		return err
	}
	_, err = peer.PrintView(ctx, req)
	return err
}

func (t *grpcNodeTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return closeConnections(t.conns)
}

// ClientTransport implementation

func (t *grpcClientTransport) SendTransfer(ctx context.Context, nodeID string, req *pb.SignedTransactionRequest) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.TransferRequest(ctx, req)
	return err
}

func (t *grpcClientTransport) SendReadOnly(ctx context.Context, nodeID string, req *pb.SignedTransactionRequest) (*pb.SignedTransactionResponse, error) {
	node, err := t.getNode(nodeID)
	if err != nil {
		return nil, err
	}
	return node.ReadOnlyRequest(ctx, req)
}

func (t *grpcClientTransport) SendBenchmark(ctx context.Context, nodeID string, req *pb.SignedTransactionRequest) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.BenchmarkRPC(ctx, req)
	return err
}

func (t *grpcClientTransport) SendReconfigure(ctx context.Context, nodeID string, req *pb.ChangeStatusMessage) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.ReconfigureNode(ctx, req)
	return err
}

func (t *grpcClientTransport) SendReset(ctx context.Context, nodeID string, req *pb.ResetRequest) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.ResetNode(ctx, req)
	return err
}

func (t *grpcClientTransport) SendPrintLog(ctx context.Context, nodeID string, req *wrapperspb.Int64Value) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.PrintLog(ctx, req)
	return err
}

func (t *grpcClientTransport) SendPrintDB(ctx context.Context, nodeID string, req *wrapperspb.Int64Value) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.PrintDB(ctx, req)
	return err
}

func (t *grpcClientTransport) SendPrintStatus(ctx context.Context, nodeID string, req *pb.StatusRequest) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.PrintStatus(ctx, req)
	return err
}

func (t *grpcClientTransport) SendPrintView(ctx context.Context, nodeID string, req *wrapperspb.Int64Value) error {
	node, err := t.getNode(nodeID)
	if err != nil {
		return err
	}
	_, err = node.PrintView(ctx, req)
	return err
}

func (t *grpcClientTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return closeConnections(t.conns)
}

// ClientAppTransport implementation

func (t *grpcClientAppTransport) SendReply(ctx context.Context, clientID string, resp *pb.SignedTransactionResponse) error {
	client, err := t.getClient(clientID)
	if err != nil {
		return err
	}
	_, err = client.ReceiveReply(ctx, resp)
	return err
}

func (t *grpcClientAppTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return closeConnections(t.conns)
}

// NewViewStream implementation

func (s *grpcNewViewStream) Recv() (*pb.SignedPrepareMessage, error) {
	return s.stream.Recv()
}

func (s *grpcNewViewStream) Close() error {
	return s.stream.CloseSend()
}
