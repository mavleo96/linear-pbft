package linearpbft

import (
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
	TimeAttackDelay   = 50 * time.Millisecond
)

// type ServerState struct {

type ServerConfig struct {
	mutex         sync.RWMutex
	LowWaterMark  int64
	HighWaterMark int64
	K             int64
	N             int64
	F             int64
}

// LinearPBFTNode represents a LinearPBFT node
type LinearPBFTNode struct {
	// Node information
	*models.Node

	// Node status
	Alive                   bool
	Byzantine               bool
	SignAttack              bool
	CrashAttack             bool
	DarkAttack              bool
	DarkAttackNodes         []string
	TimeAttack              bool
	EquivocationAttack      bool
	EquivocationAttackNodes []string

	config *ServerConfig

	// Clients and their information
	Clients map[string]*models.Client

	// State variables and mutex for synchronizing access to shared resources
	Mutex     sync.RWMutex
	LastReply *LastReply

	// Server state
	State *ServerState

	// Executor
	Executor *Executor

	// Protocol handler
	Handler *ProtocolHandler

	// View change manager
	ViewChangeManager *ViewChangeManager

	// Check point manager
	CheckPointManager *CheckPointManager

	// Timer instance
	SafeTimer *SafeTimer

	// Message logs
	ViewChangeMessageLog map[int64]map[string]*pb.SignedViewChangeMessage // v -> (id -> msg)
	ForwardedRequestsLog []*pb.SignedTransactionRequest
	// CheckPointLog        *CheckpointLog

	// UnimplementedLinearPBFTNodeServer is the server interface for the LinearPBFT node
	*pb.UnimplementedLinearPBFTNodeServer
}

// CreateLinearPBFTNode creates a new LinearPBFT node
func CreateLinearPBFTNode(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, bankDB *database.Database, privateKey1 *bls.SecretKey, privateKey2 *bls.SecretKey, masterPublicKey1 *bls.PublicKey, masterPublicKey2 *bls.PublicKey) *LinearPBFTNode {

	timer := CreateSafeTimer(ExecutionTimeout, ViewChangeTimeout)

	serverConfig := &ServerConfig{
		mutex:         sync.RWMutex{},
		LowWaterMark:  0,
		HighWaterMark: 100,
		K:             10,
		N:             int64(len(peerNodes) + 1),
		F:             int64(len(peerNodes) / 3),
	}

	serverState := &ServerState{
		mutex:                   sync.RWMutex{},
		viewNumber:              0,
		viewChangePhase:         false,
		viewChangeViewNumber:    0,
		lastExecutedSequenceNum: 0,
		StateLog:                &StateLog{mutex: sync.RWMutex{}, log: make(map[int64]*LogRecord), config: serverConfig},
		TransactionMap:          CreateTransactionMap(),
		config:                  serverConfig,
	}

	executeChannel := make(chan int64, 20)

	CheckPointManager := &CheckPointManager{
		id:                  selfNode.ID,
		mutex:               sync.RWMutex{},
		log:                 make(map[int64]map[string]*pb.SignedCheckPointMessage),
		checkpoints:         make(map[int64]*pb.CheckPoint),
		state:               serverState,
		config:              serverConfig,
		checkPointCreateCh:  make(chan int64, 5),
		checkPointRequestCh: make(chan int64, 5),
		// installCheckPointCh: make(chan int64, 5),
	}

	executor := &Executor{
		mutex:               sync.Mutex{},
		db:                  bankDB,
		safeTimer:           timer,
		state:               serverState,
		config:              serverConfig,
		executeCh:           executeChannel,
		installCheckPointCh: make(chan int64),
		CheckPointManager:   CheckPointManager,
	}

	handler := &ProtocolHandler{
		id:               selfNode.ID,
		state:            serverState,
		privateKey1:      privateKey1,
		masterPublicKey1: masterPublicKey1,
		peers:            peerNodes,
		config:           serverConfig,
		executeCh:        executeChannel,
		requestCh:        make(chan *pb.SignedTransactionRequest, 20),
		preprepareCh:     make(chan *pb.SignedPrePrepareMessage, 20),
		prepareCh:        make(chan *pb.SignedPrepareMessage, 20),
		commitCh:         make(chan *pb.SignedCommitMessage, 20),
	}

	ViewChangeManager := &ViewChangeManager{
		id:            selfNode.ID,
		mutex:         sync.RWMutex{},
		viewChangeLog: make(map[int64]map[string]*pb.SignedViewChangeMessage),
		newViewLog:    make(map[int64]*pb.SignedNewViewMessage),
		SafeTimer:     timer,
		state:         serverState,
		config:        serverConfig,

		viewChangeRequestCh: make(chan bool, 5),
		newViewRequestCh:    make(chan bool, 5),
		viewChangeRouterCh:  make(chan int64, 5),
		newViewRouterCh:     make(chan int64, 5),
		installCheckPointCh: make(chan int64, 5),
	}

	server := &LinearPBFTNode{
		Node:                    selfNode,
		Alive:                   true,
		Byzantine:               false,
		SignAttack:              false,
		CrashAttack:             false,
		DarkAttack:              false,
		DarkAttackNodes:         make([]string, 0),
		TimeAttack:              false,
		EquivocationAttack:      false,
		EquivocationAttackNodes: make([]string, 0),

		Clients:              clientMap,
		config:               serverConfig,
		Mutex:                sync.RWMutex{},
		LastReply:            &LastReply{Mutex: sync.RWMutex{}, ReplyMap: make(map[string]*pb.TransactionResponse)},
		State:                serverState,
		SafeTimer:            timer,
		Executor:             executor,
		Handler:              handler,
		ViewChangeManager:    ViewChangeManager,
		CheckPointManager:    CheckPointManager,
		ViewChangeMessageLog: make(map[int64]map[string]*pb.SignedViewChangeMessage),
		ForwardedRequestsLog: make([]*pb.SignedTransactionRequest, 0),
	}

	executor.sendReply = func(signedRequest *pb.SignedTransactionRequest, result int64) {
		server.SendReply(signedRequest, result)
	}

	handler.SendGetRequest = func(digest []byte) (*pb.SignedTransactionRequest, error) {
		return server.SendGetRequest(digest)
	}

	return server
}
