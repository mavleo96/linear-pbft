package utils

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Connect establishes a connection to a server at the given address
func Connect(addr string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
