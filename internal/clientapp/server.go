package clientapp

import (
	"context"
	"net"
	"path/filepath"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
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
	ok := crypto.Verify(response, s.coordinator.nodes.GetPublicKey(response.NodeID), signedResponse.Signature)
	if !ok {
		log.Warnf("Invalid signature for reply from node %s", response.NodeID)
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
	defer lis.Close()

	// Create gRPC server and register service
	s.grpcServer = grpc.NewServer()
	pb.RegisterLinearPBFTClientAppServer(s.grpcServer, s)

	// Graceful shutdown
	go func() {
		<-mainCtx.Done()
		log.Infof("%s received exit signal on gRPC server", s.ID)
		s.grpcServer.GracefulStop()
		log.Infof("%s gRPC server graceful stop complete", s.ID)
	}()
	go s.coordinator.Start()

	// Start serving
	log.Infof("%s gRPC server listening on %s", s.ID, s.Client.Address)
	if err := s.grpcServer.Serve(lis); err != nil {
		// log.Fatalf("Failed to serve: %v", err)
		log.Warnf("Failed to serve: %v", err)
	}

	// Wait for coordinator to finish
	go func() {
		s.coordinator.wgReset.Wait()
		log.Infof("%s coordinator finished", s.ID)
	}()
}

// CreateClientAppServer creates a client app server
func CreateClientAppServer(mainCtx context.Context, client *models.Client, nodes map[string]*models.Node) (chan<- *TestSet, chan bool, error) {
	privateKey, err := crypto.ReadPrivateKey(filepath.Join("./keys", "client", client.ID+".pem"))
	if err != nil {
		log.Fatal(err)
	}

	nodeMap := &NodeMap{
		nodes: nodes,
		N:     int64(len(nodes)),
		F:     2,
	}

	resultCh := make(chan int64)

	state := &State{
		currentTimestamp:  0,
		currentViewNumber: 0,
		responseMap:       make(map[string]int64),
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
		f:          2,
		responseCh: make(chan *pb.TransactionResponse),
		resultCh:   resultCh,
	}

	ctx, cancel := context.WithCancel(context.Background())
	coordinator := &Coordinator{
		clientID:  client.ID,
		state:     state,
		processor: processor,
		collector: collector,
		nodes:     nodeMap,
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
