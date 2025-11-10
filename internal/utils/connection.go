package utils

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Connect establishes a connection to a server at the given address
// Connections are created lazily (non-blocking) and will be established on first RPC call
// This prevents blocking during startup when other servers may not be ready yet
// WaitForReady(true) ensures RPC calls wait for connections to establish rather than failing immediately
func Connect(addr string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client for %s: %w", addr, err)
	}
	return conn, nil
}
