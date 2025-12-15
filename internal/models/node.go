package models

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/linear-pbft/internal/config"
	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/network"
	networkgrpc "github.com/mavleo96/linear-pbft/internal/network/grpc"
)

// Node represents a node in the distributed system
type Node struct {
	ID         string `yaml:"id"`
	Address    string `yaml:"address"`
	PublicKey1 *bls.PublicKey
	PublicKey2 *bls.PublicKey
	Transport  network.NodeTransport
	Close      func() error
}

type Client struct {
	ID        string `yaml:"id"`
	Address   string `yaml:"address"`
	PublicKey *bls.PublicKey
	Transport network.ClientAppTransport
	Close     func() error
}

func GetNodeMap(nodeConfig map[string]*config.NodeEntry) (map[string]*Node, error) {
	nodeMap := make(map[string]*Node, len(nodeConfig))

	// Build address map for transport manager
	addresses := make(map[string]string, len(nodeConfig))
	for id, node := range nodeConfig {
		addresses[id] = node.Address
	}

	// Create shared transport manager
	transport, err := networkgrpc.NewNodeTransport(addresses)
	if err != nil {
		return nil, err
	}

	// Create a shared closer that closes the transport once
	closeTransport := createSharedCloser(transport)

	for id, node := range nodeConfig {
		// Read and store public key
		publicKey1, err := crypto.ReadPublicKey(filepath.Join("./keys", "node", fmt.Sprintf("%s_public1.key", id)))
		if err != nil {
			transport.Close()
			cleanupNodes(nodeMap)
			return nil, err
		}
		publicKey2, err := crypto.ReadPublicKey(filepath.Join("./keys", "node", fmt.Sprintf("%s_public2.key", id)))
		if err != nil {
			transport.Close()
			cleanupNodes(nodeMap)
			return nil, err
		}

		// Create node struct and store in map
		nodeMap[id] = &Node{
			ID:         node.ID,
			Address:    node.Address,
			PublicKey1: publicKey1,
			PublicKey2: publicKey2,
			Transport:  transport,
			Close:      closeTransport,
		}
	}
	return nodeMap, nil
}

func GetClientMap(clientConfig map[string]*config.ClientEntry) (map[string]*Client, error) {
	clientMap := make(map[string]*Client, len(clientConfig))

	// Build address map for transport manager
	addresses := make(map[string]string, len(clientConfig))
	for id, client := range clientConfig {
		addresses[id] = client.Address
	}

	// Create shared transport manager
	transport, err := networkgrpc.NewClientAppTransport(addresses)
	if err != nil {
		return nil, err
	}

	// Create a shared closer that closes the transport once
	closeTransport := createSharedCloser(transport)

	for id, client := range clientConfig {
		// Read and store public key
		publicKey, err := crypto.ReadPublicKey(filepath.Join("./keys", "client", fmt.Sprintf("%s_public.key", id)))
		if err != nil {
			transport.Close()
			cleanupClients(clientMap)
			return nil, err
		}

		// Create client struct and store in map
		clientMap[id] = &Client{
			ID:        client.ID,
			Address:   client.Address,
			PublicKey: publicKey,
			Transport: transport,
			Close:     closeTransport,
		}
	}
	return clientMap, nil
}

func cleanupNodes(nodeMap map[string]*Node) {
	for _, node := range nodeMap {
		if node != nil && node.Close != nil {
			_ = node.Close()
		}
	}
}

func cleanupClients(clientMap map[string]*Client) {
	for _, client := range clientMap {
		if client != nil && client.Close != nil {
			_ = client.Close()
		}
	}
}

// createSharedCloser creates a function that closes the transport exactly once
func createSharedCloser(transport interface{ Close() error }) func() error {
	var (
		closed bool
		mu     sync.Mutex
	)
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			closed = true
			return transport.Close()
		}
		return nil
	}
}
