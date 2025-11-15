package clientapp

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"

	"github.com/mavleo96/pbft/internal/crypto"
	"github.com/mavleo96/pbft/internal/models"
	"github.com/mavleo96/pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ClientAppServer is the server for the client app
type ClientAppServer struct {
	*models.Client
	coordinator *Coordinator
	grpcServer  *grpc.Server
	*pb.UnimplementedLinearPBFTClientAppServer
}

// ReceiveReply receives a reply from a node and sends it to the coordinator
func (s *ClientAppServer) ReceiveReply(ctx context.Context, signedResponse *pb.SignedTransactionResponse) (*emptypb.Empty, error) {
	response := signedResponse.Message

	// Verify signature
	ok := crypto.Verify(response, s.coordinator.nodes.GetPublicKey1(response.NodeID), signedResponse.Signature)
	if !ok {
		// log.Warnf("Invalid signature for reply from node %s", response.NodeID)
		return &emptypb.Empty{}, nil
	}

	// Send response to coordinator
	select {
	case s.coordinator.collector.GetSendResponseChannel() <- response:
	case <-ctx.Done():
		return &emptypb.Empty{}, nil
	}
	return &emptypb.Empty{}, nil
}

// StartServer starts the gRPC server and the coordinator
func (s *ClientAppServer) StartServer(mainCtx context.Context) {
	// Listen on the client's address
	lis, err := net.Listen("tcp", s.Client.Address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server and register service
	s.grpcServer = grpc.NewServer()
	pb.RegisterLinearPBFTClientAppServer(s.grpcServer, s)

	// Start coordinator before serving
	s.coordinator.Start()

	// Graceful shutdown handler
	go func() {
		<-mainCtx.Done()
		log.Infof("%s received exit signal, shutting down", s.ID)

		// Stop coordinator first
		s.coordinator.Stop()

		// Stop gRPC server gracefully (waits for existing RPCs to complete)
		// This will cause Serve() to return gracefully
		log.Infof("%s stopping gRPC server", s.ID)
		s.grpcServer.GracefulStop()
		log.Infof("%s gRPC server stopped", s.ID)
	}()

	// Start serving (this blocks until server stops)
	log.Infof("%s gRPC server listening on %s", s.ID, s.Client.Address)
	serveErr := s.grpcServer.Serve(lis)

	// Only log error if it's not from closing the listener
	if serveErr != nil && serveErr.Error() != "use of closed network connection" {
		log.Warnf("%s gRPC server error: %v", s.ID, serveErr)
	}
}

// CreateClientAppServer creates a client app server
func CreateClientAppServer(mainCtx context.Context, client *models.Client, nodes map[string]*models.Node) (chan<- *TestSet, chan bool, error) {
	privateKey, err := crypto.ReadPrivateKey(filepath.Join("./keys", "client", fmt.Sprintf("%s_secret.key", client.ID)))
	if err != nil {
		log.Fatal(err)
	}

	// Calculate F (fault tolerance) based on number of nodes: F = (N-1)/3
	f := int64((len(nodes) - 1) / 3)
	nodeMap := &NodeMap{
		nodes: nodes,
		N:     int64(len(nodes)),
		F:     f,
	}

	resultCh := make(chan Result, 1)

	state := &ClientState{
		currentTimestamp:  0,
		currentViewNumber: 0,
		responseMap:       make(map[string]Result),
		mutex:             sync.RWMutex{},
	}
	processor := &Processor{
		clientID:   client.ID,
		state:      state,
		nodes:      nodeMap,
		privateKey: privateKey,
		resultCh:   resultCh,
	}

	collector := &ResponseCollector{
		clientID:   client.ID,
		state:      state,
		f:          f,
		responseCh: make(chan *pb.TransactionResponse, 100),
		resultCh:   resultCh,
	}

	ctx, cancel := context.WithCancel(mainCtx)
	coordinator := &Coordinator{
		clientID:  client.ID,
		state:     state,
		processor: processor,
		collector: collector,
		nodes:     nodeMap,
		parentCtx: mainCtx,
		testSetCh: make(chan *TestSet),
		resetCh:   make(chan bool),
		ctx:       ctx,
		cancel:    cancel,
		wg:        sync.WaitGroup{},
	}

	server := &ClientAppServer{
		Client:      client,
		coordinator: coordinator,
	}

	go server.StartServer(mainCtx)

	return server.coordinator.GetReceiveTestSetChannel(), server.coordinator.GetReceiveResetChannel(), nil
}
