package linearpbftdb

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/magiconair/properties"
	"github.com/mavleo96/linear-pbft/internal/config"
	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/models"
	"github.com/mavleo96/linear-pbft/internal/network"
	networkgrpc "github.com/mavleo96/linear-pbft/internal/network/grpc"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	"github.com/pingcap/go-ycsb/pkg/util"
	"github.com/pingcap/go-ycsb/pkg/ycsb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// LinearPBFTDB represents a LinearPBFT database
type LinearPBFTDB struct {
	n              int64
	f              int64
	p              *properties.Properties
	nodeTransport  network.ClientTransport
	nodeIDs        []string
	nodePublicKeys map[string]*bls.PublicKey
	clientMap      map[string]*models.Client
	r              *util.RowCodec
	bufPool        *util.BufPool
	// Track servers for cleanup in Close()
	mu        sync.Mutex
	servers   []*grpc.Server
	listeners []net.Listener
}

// LinearPBFTDBCreator implements ycsb.DBCreator
type LinearPBFTDBCreator struct{}

// Create creates a new LinearPBFTDB instance
func (c *LinearPBFTDBCreator) Create(props *properties.Properties) (ycsb.DB, error) {
	// Read from config file
	cfg, err := config.ParseConfig("./configs/config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	// Get client map
	clientMap, err := models.GetClientMap(cfg.Clients)
	if err != nil {
		return nil, fmt.Errorf("failed to get client map: %v", err)
	}

	// Get node map to extract addresses and public keys
	nodeMap, err := models.GetNodeMap(cfg.Nodes)
	if err != nil {
		return nil, fmt.Errorf("failed to get node map: %v", err)
	}

	// Build address map and extract node IDs and public keys
	nodeAddresses := make(map[string]string, len(nodeMap))
	nodeIDs := make([]string, 0, len(nodeMap))
	nodePublicKeys := make(map[string]*bls.PublicKey, len(nodeMap))
	for id, node := range nodeMap {
		nodeAddresses[id] = node.Address
		nodeIDs = append(nodeIDs, id)
		nodePublicKeys[id] = node.PublicKey1
	}

	// Create transport manager
	nodeTransport, err := networkgrpc.NewClientTransport(nodeAddresses)
	if err != nil {
		// Cleanup node connections
		for _, node := range nodeMap {
			node.Close()
		}
		// Cleanup client connections
		for _, client := range clientMap {
			client.Close()
		}
		return nil, fmt.Errorf("failed to create node transport: %v", err)
	}

	// Create LinearPBFTDB instance
	db := &LinearPBFTDB{
		n:              int64(len(nodeMap)),
		f:              int64((len(nodeMap) - 1) / 3),
		p:              props,
		nodeTransport:  nodeTransport,
		nodeIDs:        nodeIDs,
		nodePublicKeys: nodePublicKeys,
		clientMap:      clientMap,
		r:              util.NewRowCodec(props),
		bufPool:        util.NewBufPool(),
		servers:        make([]*grpc.Server, 0),
		listeners:      make([]net.Listener, 0),
	}

	return db, nil
}

// contextKey represents a context key
type contextKey string

const clientIDKey contextKey = "clientID"
const privateKeyKey contextKey = "privateKey"
const responseChKey contextKey = "responseCh"
const listenerKey contextKey = "listener"
const grpcServerKey contextKey = "grpcServer"

// InitThread initializes thread-specific state
func (p *LinearPBFTDB) InitThread(ctx context.Context, threadID int, threadCount int) context.Context {
	// Note: thread related state is passed as part of the context

	// Assign thread ID as client ID
	clientID := string(rune(threadID + 65))
	ctx = context.WithValue(ctx, clientIDKey, clientID)

	// Check if client exists in map
	client, exists := p.clientMap[clientID]
	if !exists {
		keys := make([]string, 0, len(p.clientMap))
		for k := range p.clientMap {
			keys = append(keys, k)
		}
		log.Fatalf("Client %s not found in client map. Available clients: %v", clientID, keys)
	}

	// Get private key for this thread
	privateKey, err := crypto.ReadPrivateKey(filepath.Join("./keys", "client", fmt.Sprintf("%s_secret.key", clientID)))
	if err != nil {
		log.Fatal(err)
	}
	ctx = context.WithValue(ctx, privateKeyKey, privateKey)

	// Create Channel for receiving replies
	responseCh := make(chan *pb.SignedTransactionResponse, 100)
	ctx = context.WithValue(ctx, responseChKey, responseCh)

	// Create Listener for receiving replies
	lis, err := net.Listen("tcp", client.Address)
	if err != nil {
		log.Fatalf("Failed to listen on %s for client %s: %v. This usually means the address is already in use. Try killing existing processes or using a different port.", client.Address, clientID, err)
	}

	// Create Server for receiving replies
	server := &ReceiveServer{clientID: clientID, nodePublicKeys: p.nodePublicKeys, responseCh: responseCh}
	grpcServer := grpc.NewServer()
	pb.RegisterClientAppServer(grpcServer, server)

	// Store listener and server in context for cleanup
	ctx = context.WithValue(ctx, listenerKey, lis)
	ctx = context.WithValue(ctx, grpcServerKey, grpcServer)

	// Track servers and listeners for cleanup in Close()
	p.mu.Lock()
	p.servers = append(p.servers, grpcServer)
	p.listeners = append(p.listeners, lis)
	p.mu.Unlock()

	// Start server in goroutine
	// The server will run until CleanupThread or Close() is called
	go func() {
		serveErr := grpcServer.Serve(lis)
		// Serve() returns when:
		// 1. GracefulStop() is called (normal shutdown) - may return nil or an error
		// 2. Stop() is called (immediate shutdown)
		// 3. Listener is closed externally (may cause error)
		//
		// IMPORTANT: Errors from normal shutdown (like "use of closed network connection")
		// are expected and should not be logged. These occur when the listener is closed
		// as part of graceful shutdown, which is a normal operation.
		if serveErr != nil {
			// Check if error is from normal shutdown (any variation)
			// These errors are expected when the server is shut down gracefully
			errStr := serveErr.Error()
			isShutdownError := strings.Contains(errStr, "use of closed network connection") ||
				strings.Contains(errStr, "server has been stopped") ||
				strings.Contains(errStr, "grpc: the server has been stopped")

			// Only log if it's not a shutdown error
			// Shutdown errors are expected and should be silently ignored
			if !isShutdownError {
				log.Errorf("%s: gRPC server error: %v", clientID, serveErr)
			}
		}
	}()

	return ctx
}

// Close closes all connections and stops all servers
func (p *LinearPBFTDB) Close() error {
	// Stop all gRPC servers gracefully
	for _, grpcServer := range p.servers {
		if grpcServer != nil {
			grpcServer.GracefulStop()
		}
	}

	// Close all listeners
	for _, lis := range p.listeners {
		if lis != nil {
			lis.Close()
		}
	}

	// Close transport
	if p.nodeTransport != nil {
		p.nodeTransport.Close()
	}

	// Close client connections
	for _, client := range p.clientMap {
		client.Close()
	}

	return nil
}

// CleanupThread cleans up thread-specific state
// This is called when a YCSB thread finishes its work.
// We shut down the server here so it can be recreated in the next phase if needed.
func (p *LinearPBFTDB) CleanupThread(cx context.Context) {
	// Get gRPC server and response channel from context
	grpcServer, hasServer := cx.Value(grpcServerKey).(*grpc.Server)
	responseCh, hasChannel := cx.Value(responseChKey).(chan *pb.SignedTransactionResponse)

	// Stop gRPC server gracefully - this stops accepting new connections
	// and waits for existing RPCs to complete, causing Serve() to return
	// GracefulStop() handles closing the listener internally
	if hasServer && grpcServer != nil {
		grpcServer.GracefulStop()
	}

	// Close response channel after server has stopped
	if hasChannel && responseCh != nil {
		close(responseCh)
	}
}

// Register registers the LinearPBFTDB creator
func Register() {
	ycsb.RegisterDBCreator("linearpbftdb", &LinearPBFTDBCreator{})
}

// ReceiveServer is the server for receiving replies from nodes
type ReceiveServer struct {
	clientID       string
	nodePublicKeys map[string]*bls.PublicKey
	responseCh     chan *pb.SignedTransactionResponse
	*pb.UnimplementedClientAppServer
}

// ReceiveReply receives a reply from a node and send to channel
func (s *ReceiveServer) ReceiveReply(ctx context.Context, signedResponse *pb.SignedTransactionResponse) (*emptypb.Empty, error) {
	response := signedResponse.Message

	// Verify signature
	publicKey, ok := s.nodePublicKeys[response.NodeID]
	if !ok {
		log.Warnf("%s: Unknown node ID %s", s.clientID, response.NodeID)
		signedResponse.Message.Error = "unknown node"
		s.responseCh <- signedResponse
		return &emptypb.Empty{}, nil
	}
	ok = crypto.Verify(response, publicKey, signedResponse.Signature)
	if !ok {
		log.Warnf("%s: Invalid signature for reply from node %s for request %s", s.clientID, response.NodeID, utils.LoggingString(signedResponse))
		signedResponse.Message.Error = "invalid signature"
	} else {
		// log.Infof("%s: Received reply from node %s for request %s", s.clientID, response.NodeID, utils.LoggingString(signedResponse))
	}
	s.responseCh <- signedResponse
	return &emptypb.Empty{}, nil
}
