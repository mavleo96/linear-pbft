package linearpbft

import (
	"context"
	"sync"
	"time"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
)

const (
	ExecutionTimeout  = 400 * time.Millisecond
	ViewChangeTimeout = 700 * time.Millisecond
	TimeAttackDelay   = 100 * time.Millisecond
)

// LinearPBFTNode represents a LinearPBFT node
type LinearPBFTNode struct {
	// Node information
	*models.Node
	config          *ServerConfig
	byzantineConfig *ByzantineConfig
	clients         map[string]*models.Client
	state           *ServerState

	// Timer instance
	timer *SafeTimer

	// Component managers
	executor    *Executor
	handler     *ProtocolHandler
	viewchanger *ViewChangeManager

	// Wait group for graceful shutdown
	wg sync.WaitGroup

	// UnimplementedLinearPBFTNodeServer is the server interface for the LinearPBFT node
	*pb.UnimplementedLinearPBFTNodeServer
}

// Start starts the LinearPBFT node
func (n *LinearPBFTNode) Start(ctx context.Context) {
	n.wg.Add(1)
	go n.RouterRoutine(ctx)

	n.wg.Add(1)
	go n.executor.ExecuteRoutine(ctx)

	n.wg.Add(1)
	go n.viewchanger.ViewChangeRoutine(ctx)

	n.wg.Add(1)
	go n.executor.checkpointer.CheckpointRoutine(ctx)

	n.wg.Wait()
}

// CreateLinearPBFTNode creates a new LinearPBFT node
func CreateLinearPBFTNode(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, bankDB *database.Database, privateKey1 *bls.SecretKey, privateKey2 *bls.SecretKey, masterPublicKey1 *bls.PublicKey, masterPublicKey2 *bls.PublicKey) *LinearPBFTNode {

	timer := CreateSafeTimer(ExecutionTimeout, ViewChangeTimeout)
	serverConfig := CreateServerConfig(int64(len(peerNodes)+1), 10, 100)
	byzantineConfig := CreateByzantineConfig()
	serverState := CreateServerState(serverConfig, byzantineConfig)

	executionTriggerChannel := make(chan int64, 100)

	viewchanger := CreateViewChangeManager(selfNode.ID, timer, serverState, serverConfig)
	checkpointer := CreateCheckpointManager(selfNode.ID, serverState, serverConfig)
	executor := CreateExecutor(serverState, serverConfig, bankDB, checkpointer, timer, executionTriggerChannel)
	handler := CreateProtocolHandler(selfNode.ID, serverState, serverConfig, byzantineConfig, privateKey1, masterPublicKey1, peerNodes, executionTriggerChannel)

	server := &LinearPBFTNode{
		Node:            selfNode,
		config:          serverConfig,
		byzantineConfig: byzantineConfig,
		clients:         clientMap,
		state:           serverState,
		timer:           timer,
		executor:        executor,
		handler:         handler,
		viewchanger:     viewchanger,
		wg:              sync.WaitGroup{},
	}

	executor.sendReply = func(signedRequest *pb.SignedTransactionRequest, result int64) {
		server.SendReply(signedRequest, result)
	}

	handler.SendGetRequest = func(digest []byte) (*pb.SignedTransactionRequest, error) {
		return server.SendGetRequest(digest)
	}

	return server
}
