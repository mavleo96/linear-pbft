package main

import (
	"context"
	"flag"
	"net"
	"path/filepath"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/linearpbft"
	"github.com/mavleo96/bft-mavleo96/internal/models"
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
	peerNodes := make(map[string]*models.Node)
	for _, node := range nodeMap {
		if node.ID != *id {
			peerNodes[node.ID] = node
		}
	}

	grpcServer, err := CreateServer(selfNode, peerNodes, clientMap, cfg.DBDir, cfg.InitBalance)
	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", selfNode.Address)
	if err != nil {
		log.Fatal(err)
	}

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

func CreateServer(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, dbDir string, initBalance int64) (*grpc.Server, error) {
	privateKey, err := crypto.ReadPrivateKey(filepath.Join("./keys", "node", selfNode.ID+".pem"))
	if err != nil {
		log.Fatal(err)
	}

	bankDB := &database.Database{}
	dbPath := filepath.Join(dbDir, selfNode.ID+".db")
	log.Infof("Initializing database")
	err = bankDB.InitDB(dbPath, utils.Keys(clientMap), initBalance)
	if err != nil {
		log.Fatal(err)
	}
	// defer bankDB.Close()
	log.Infof("Database initialized at %s", dbPath)

	grpcServer := grpc.NewServer()

	node := linearpbft.CreateLinearPBFTNode(selfNode, peerNodes, clientMap, bankDB, privateKey)
	pb.RegisterLinearPBFTNodeServer(grpcServer, node)

	go node.ViewChangeRoutine(context.Background())
	go node.CheckPointRoutine(context.Background())
	go node.ServiceRoutine(context.Background())

	return grpcServer, nil
}
