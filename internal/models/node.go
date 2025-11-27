package models

import (
	"fmt"
	"path/filepath"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/linear-pbft/internal/config"
	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
)

// Node represents a node in the distributed system
type Node struct {
	ID         string `yaml:"id"`
	Address    string `yaml:"address"`
	PublicKey1 *bls.PublicKey
	PublicKey2 *bls.PublicKey
	Client     pb.LinearPBFTNodeClient
	Close      func() error // TODO: this needs to be changed
}

type Client struct {
	ID        string `yaml:"id"`
	Address   string `yaml:"address"`
	PublicKey *bls.PublicKey
	Client    pb.LinearPBFTClientAppClient
	Close     func() error
}

func GetNodeMap(nodeConfig map[string]*config.NodeEntry) (map[string]*Node, error) {
	nodeMap := make(map[string]*Node, len(nodeConfig))
	for id, node := range nodeConfig {
		// Read and store public key
		publicKey1, err := crypto.ReadPublicKey(filepath.Join("./keys", "node", fmt.Sprintf("%s_public1.key", id)))
		if err != nil {
			cleanupNodes(nodeMap)
			return nil, err
		}
		publicKey2, err := crypto.ReadPublicKey(filepath.Join("./keys", "node", fmt.Sprintf("%s_public2.key", id)))
		if err != nil {
			cleanupNodes(nodeMap)
			return nil, err
		}

		// Connect to node
		conn, err := utils.Connect(node.Address)
		if err != nil {
			cleanupNodes(nodeMap)
			return nil, err
		}
		nodeClient := pb.NewLinearPBFTNodeClient(conn)
		currentConn := conn

		// Create node struct and store in map
		nodeMap[id] = &Node{
			ID:         node.ID,
			Address:    node.Address,
			PublicKey1: publicKey1,
			PublicKey2: publicKey2,
			Client:     nodeClient,
			Close:      func() error { return currentConn.Close() },
		}
	}
	return nodeMap, nil
}

func GetClientMap(clientConfig map[string]*config.ClientEntry) (map[string]*Client, error) {
	clientMap := make(map[string]*Client, len(clientConfig))
	for id, client := range clientConfig {
		// Read and store public key
		publicKey, err := crypto.ReadPublicKey(filepath.Join("./keys", "client", fmt.Sprintf("%s_public.key", id)))
		if err != nil {
			cleanupClients(clientMap)
			return nil, err
		}

		// Connect to client
		conn, err := utils.Connect(client.Address)
		if err != nil {
			cleanupClients(clientMap)
			return nil, err
		}
		clientClient := pb.NewLinearPBFTClientAppClient(conn)
		currentConn := conn

		// Create client struct and store in map
		clientMap[id] = &Client{
			ID:        client.ID,
			Address:   client.Address,
			PublicKey: publicKey,
			Client:    clientClient,
			Close:     func() error { return currentConn.Close() },
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
