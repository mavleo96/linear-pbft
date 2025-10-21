package main

import (
	"flag"
	"net"
	"path/filepath"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/linearpbft"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
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
	nodeMap, err := models.GetNodeMap(cfg.Nodes)
	if err != nil {
		log.Fatal(err)
	}

	clientMap, err := models.GetClientMap(cfg.Clients)
	if err != nil {
		log.Fatal(err)
	}

	// Find self node configuration
	selfNode, ok := nodeMap[*id]
	if !ok {
		log.Fatal("Node ID not found in config")
	}
	log.Infof("Self node configuration: %v", selfNode)

	// Create database
	bankDB := &database.Database{}
	dbPath := filepath.Join(cfg.DBDir, *id+".db")
	log.Infof("Initializing database")
	err = bankDB.InitDB(dbPath, utils.Keys(cfg.Clients), cfg.InitBalance)
	if err != nil {
		log.Fatal(err)
	}
	defer bankDB.Close()
	log.Infof("Database initialized at %s", dbPath)

	privateKey, err := security.ReadPrivateKey(filepath.Join("./keys", "node", *id+".pem"))
	if err != nil {
		log.Fatal(err)
	}

	// Create gRPC server
	lis, err := net.Listen("tcp", selfNode.Address)
	if err != nil {
		log.Fatal(err)
	}
	grpcServer := grpc.NewServer()

	// Register LinearPBFTNode server
	pb.RegisterLinearPBFTNodeServer(grpcServer, &linearpbft.LinearPBFTNode{
		Node:       selfNode,
		DB:         bankDB,
		PrivateKey: privateKey,
		Peers:      nodeMap,
		Clients:    clientMap,
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
