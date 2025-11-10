package linearpbftdb

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/magiconair/properties"
	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	"github.com/pingcap/go-ycsb/pkg/util"
	"github.com/pingcap/go-ycsb/pkg/ycsb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// LinearPBFTDB represents a LinearPBFT database
type LinearPBFTDB struct {
	n         int64
	f         int64
	p         *properties.Properties
	nodeMap   map[string]*models.Node
	clientMap map[string]*models.Client
	r         *util.RowCodec
	bufPool   *util.BufPool
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

	// Get node map and connections
	nodeMap, err := models.GetNodeMap(cfg.Nodes)
	if err != nil {
		return nil, fmt.Errorf("failed to get node map: %v", err)
	}

	// Create LinearPBFTDB instance
	db := &LinearPBFTDB{
		n:         int64(len(nodeMap)),
		f:         int64((len(nodeMap) - 1) / 3),
		p:         props,
		nodeMap:   nodeMap,
		clientMap: clientMap,
		r:         util.NewRowCodec(props),
		bufPool:   util.NewBufPool(),
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
	server := &ReceiveServer{clientID: clientID, nodeMap: p.nodeMap, responseCh: responseCh}
	grpcServer := grpc.NewServer()
	pb.RegisterLinearPBFTClientAppServer(grpcServer, server)

	// Store listener and server in context for cleanup
	ctx = context.WithValue(ctx, listenerKey, lis)
	ctx = context.WithValue(ctx, grpcServerKey, grpcServer)

	go func() {
		defer grpcServer.GracefulStop()
		defer lis.Close()
		// log.Infof("%s: Receiving server listening on %s", clientID, lis.Addr().String())
		if err := grpcServer.Serve(lis); err != nil {
			log.Errorf("%s: gRPC server error: %v", clientID, err)
		}
	}()

	return ctx
}

// Close closes all connections
func (p *LinearPBFTDB) Close() error {
	for _, node := range p.nodeMap {
		node.Close()
	}
	for _, client := range p.clientMap {
		client.Close()
	}
	return nil
}

// CleanupThread cleans up thread-specific state
func (p *LinearPBFTDB) CleanupThread(cx context.Context) {
	// Close response channel
	if responseCh, ok := cx.Value(responseChKey).(chan *pb.SignedTransactionResponse); ok {
		close(responseCh)
	}

	// Stop gRPC server gracefully
	if grpcServer, ok := cx.Value(grpcServerKey).(*grpc.Server); ok {
		grpcServer.GracefulStop()
	}

	// Close listener
	if lis, ok := cx.Value(listenerKey).(net.Listener); ok {
		lis.Close()
	}
}

// Register registers the LinearPBFTDB creator
func Register() {
	ycsb.RegisterDBCreator("linearpbftdb", &LinearPBFTDBCreator{})
}

// ReceiveServer is the server for receiving replies from nodes
type ReceiveServer struct {
	clientID   string
	nodeMap    map[string]*models.Node
	responseCh chan *pb.SignedTransactionResponse
	*pb.UnimplementedLinearPBFTClientAppServer
}

// ReceiveReply receives a reply from a node and send to channel
func (s *ReceiveServer) ReceiveReply(ctx context.Context, signedResponse *pb.SignedTransactionResponse) (*emptypb.Empty, error) {
	response := signedResponse.Message

	// Verify signature
	ok := crypto.Verify(response, s.nodeMap[response.NodeID].PublicKey1, signedResponse.Signature)
	if !ok {
		log.Warnf("%s: Invalid signature for reply from node %s for request %s", s.clientID, response.NodeID, utils.LoggingString(signedResponse))
		signedResponse.Message.Error = "invalid signature"
	} else {
		// log.Infof("%s: Received reply from node %s for request %s", s.clientID, response.NodeID, utils.LoggingString(signedResponse))
	}
	s.responseCh <- signedResponse
	return &emptypb.Empty{}, nil
}
