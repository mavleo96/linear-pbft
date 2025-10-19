package main

import (
	"flag"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/linearpbft"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	log.SetFormatter(&log.TextFormatter{TimestampFormat: "15:04.000"})

	id := flag.String("id", "n1", "Node ID")
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	// Load configurations
	// Peer nodes and their addresses, clients, database directory are read from config file
	cfg, err := config.ParseConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	for nodeID, node := range cfg.Nodes {
		node.PublicKey, err = security.ReadPublicKey(filepath.Join("./keys", "node", nodeID+".pub.pem"))
		if err != nil {
			log.Fatal(err)
		}
	}
	clientPublicKeys := make(map[string][]byte)
	for _, clientID := range cfg.Clients {
		clientPublicKeys[clientID], err = security.ReadPublicKey(filepath.Join("./keys", "client", clientID+".pub.pem"))
		if err != nil {
			log.Fatal(err)
		}
	}

	// Find self node configuration
	selfNode, ok := cfg.Nodes[*id]
	if !ok {
		log.Fatal("Node ID not found in config")
	}
	log.Infof("Self node configuration: %v", selfNode)

	// Create database
	bankDB := &database.Database{}
	dbPath := filepath.Join(cfg.DBDir, *id+".db")
	log.Infof("Initializing database at %s with clients %s", dbPath, strings.Join(cfg.Clients, ", "))
	err = bankDB.InitDB(dbPath, cfg.Clients, cfg.InitBalance)
	if err != nil {
		log.Fatal(err)
	}
	defer bankDB.Close()
	log.Infof("Database initialized at %s", dbPath)

	// Create gRPC server
	lis, err := net.Listen("tcp", selfNode.Address)
	if err != nil {
		log.Fatal(err)
	}
	grpcServer := grpc.NewServer()

	// Register LinearPBFT server
	pb.RegisterLinearPBFTServer(grpcServer, &linearpbft.LinearPBFTServer{
		Node: selfNode,
		DB:   bankDB,
	})

	// Start gRPC server and paxos server timeout routine
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatal(err)
		}
	})
	log.Infof("gRPC server listening on %s", selfNode.Address)

	// Wait for gRPC server and paxos server timeout routine to finish
	wg.Wait()
}
