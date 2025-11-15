package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/pbft/internal/config"
	"github.com/mavleo96/pbft/internal/crypto"
	"github.com/mavleo96/pbft/internal/database"
	"github.com/mavleo96/pbft/internal/linearpbft"
	"github.com/mavleo96/pbft/internal/models"
	"github.com/mavleo96/pbft/internal/utils"
	"github.com/mavleo96/pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	log.SetFormatter(&log.TextFormatter{TimestampFormat: "15:04.000"})

	// Initialize BLS library
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

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

	// Create context for graceful shutdown (will be cancelled on signal)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverData, err := CreateServer(selfNode, peerNodes, clientMap, cfg.DBDir, cfg.InitBalance, ctx)
	if err != nil {
		log.Fatal(err)
	}
	grpcServer := serverData.grpcServer
	bankDB := serverData.bankDB

	lis, err := net.Listen("tcp", selfNode.Address)
	if err != nil {
		log.Fatal(err)
	}
	// Ensure listener is closed on exit (though GracefulStop() handles this)
	defer lis.Close()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Start gRPC server in a goroutine
	var wg sync.WaitGroup
	var serveErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Infof("gRPC server listening on %s", selfNode.Address)
		if err := grpcServer.Serve(lis); err != nil {
			serveErr = err
			// Only log error if it's not from closing the listener
			if err.Error() != "use of closed network connection" {
				log.Errorf("gRPC server error: %v", err)
			}
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Info("Received shutdown signal, shutting down gracefully...")

	// Cancel context to stop LinearPBFT node routines
	cancel()

	// Stop gRPC server gracefully (waits for existing RPCs to complete)
	// This stops accepting new connections and waits for existing RPCs to finish
	log.Info("Stopping gRPC server...")
	grpcServer.GracefulStop()
	log.Info("gRPC server stopped")

	// Close all node connections
	log.Info("Closing node connections...")
	for _, node := range nodeMap {
		if err := node.Close(); err != nil {
			log.Warnf("Error closing node connection %s: %v", node.ID, err)
		}
	}

	// Close all client connections
	log.Info("Closing client connections...")
	for _, client := range clientMap {
		if err := client.Close(); err != nil {
			log.Warnf("Error closing client connection %s: %v", client.ID, err)
		}
	}

	// Close database
	if bankDB != nil {
		log.Info("Closing database...")
		if err := bankDB.Close(); err != nil {
			log.Warnf("Error closing database: %v", err)
		}
	}

	// Wait for gRPC server to finish
	wg.Wait()

	if serveErr != nil && serveErr.Error() != "use of closed network connection" {
		log.Fatalf("gRPC server error: %v", serveErr)
	}

	log.Info("Server shut down complete")
}

// ServerData holds server components that need cleanup
type ServerData struct {
	grpcServer *grpc.Server
	bankDB     *database.Database
	pbftNode   *linearpbft.LinearPBFTNode
}

func CreateServer(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, dbDir string, initBalance int64, ctx context.Context) (*ServerData, error) {
	privateKey1, err := crypto.ReadPrivateKey(filepath.Join("./keys", "node", fmt.Sprintf("%s_secret1.key", selfNode.ID)))
	if err != nil {
		return nil, err
	}
	privateKey2, err := crypto.ReadPrivateKey(filepath.Join("./keys", "node", fmt.Sprintf("%s_secret2.key", selfNode.ID)))
	if err != nil {
		return nil, err
	}
	masterPublicKey1, err := crypto.ReadPublicKey(filepath.Join("./keys", "node", "master_public1.key"))
	if err != nil {
		return nil, err
	}
	masterPublicKey2, err := crypto.ReadPublicKey(filepath.Join("./keys", "node", "master_public2.key"))
	if err != nil {
		return nil, err
	}

	bankDB := &database.Database{}
	dbPath := filepath.Join(dbDir, selfNode.ID+".db")
	log.Infof("Initializing database")
	err = bankDB.InitDB(dbPath, utils.Keys(clientMap), initBalance)
	if err != nil {
		return nil, err
	}
	log.Infof("Database initialized at %s", dbPath)

	grpcServer := grpc.NewServer()

	node := linearpbft.CreateLinearPBFTNode(selfNode, peerNodes, clientMap, bankDB, privateKey1, privateKey2, masterPublicKey1, masterPublicKey2)
	pb.RegisterLinearPBFTNodeServer(grpcServer, node)

	// Start LinearPBFT node (it will stop when context is cancelled)
	go node.Start(ctx)

	return &ServerData{
		grpcServer: grpcServer,
		bankDB:     bankDB,
		pbftNode:   node,
	}, nil
}
