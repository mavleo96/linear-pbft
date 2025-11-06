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
	lowWaterMark  int64
	highWaterMark int64
	k             int64
}

// LinearPBFTNode represents a LinearPBFT node
type LinearPBFTNode struct {
	// Node information
	*models.Node
	PrivateKey1 *bls.SecretKey
	PrivateKey2 *bls.SecretKey

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

	// Peer nodes and their information
	Peers map[string]*models.Node
	F     int64
	N     int64

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

	// Timer instance
	SafeTimer *SafeTimer

	// Channels
	CheckPointRoutineCh chan bool
	RequestCh           chan *pb.SignedTransactionRequest
	PrepareCh           chan []*pb.SignedPrepareMessage
	CommitCh            chan []*pb.SignedCommitMessage

	// Message logs
	ViewChangeMessageLog map[int64]map[string]*pb.SignedViewChangeMessage // v -> (id -> msg)
	ForwardedRequestsLog []*pb.SignedTransactionRequest
	CheckPointLog        *CheckpointLog

	// UnimplementedLinearPBFTNodeServer is the server interface for the LinearPBFT node
	*pb.UnimplementedLinearPBFTNodeServer
}

// CreateLinearPBFTNode creates a new LinearPBFT node
func CreateLinearPBFTNode(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, bankDB *database.Database, privateKey1 *bls.SecretKey, privateKey2 *bls.SecretKey) *LinearPBFTNode {

	timer := CreateSafeTimer(ExecutionTimeout, ViewChangeTimeout)

	serverConfig := &ServerConfig{
		lowWaterMark:  0,
		highWaterMark: 100,
		k:             10,
	}

	serverState := &ServerState{
		mutex:                   sync.RWMutex{},
		viewNumber:              0,
		viewChangePhase:         false,
		viewChangeViewNumber:    0,
		lastExecutedSequenceNum: 0,
		StateLog:                &StateLog{mutex: sync.RWMutex{}, log: make(map[int64]*LogRecord)},
		TransactionMap:          CreateTransactionMap(),
	}

	checkPointCh := make(chan bool)

	executor := &Executor{
		db:           bankDB,
		safeTimer:    timer,
		state:        serverState,
		config:       serverConfig,
		executeCh:    make(chan int64, 20),
		checkPointCh: checkPointCh,
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
		PrivateKey1:             privateKey1,
		PrivateKey2:             privateKey2,
		Peers:                   peerNodes,
		Clients:                 clientMap,
		F:                       int64(len(peerNodes) / 3),
		N:                       int64(len(peerNodes) + 1),
		config:                  serverConfig,
		Mutex:                   sync.RWMutex{},
		LastReply:               &LastReply{Mutex: sync.RWMutex{}, ReplyMap: make(map[string]*pb.TransactionResponse)},
		State:                   serverState,
		SafeTimer:               timer,
		Executor:                executor,
		CheckPointRoutineCh:     checkPointCh,
		RequestCh:               make(chan *pb.SignedTransactionRequest, 20),
		PrepareCh:               make(chan []*pb.SignedPrepareMessage, 20),
		CommitCh:                make(chan []*pb.SignedCommitMessage, 20),
		ViewChangeMessageLog:    make(map[int64]map[string]*pb.SignedViewChangeMessage),
		ForwardedRequestsLog:    make([]*pb.SignedTransactionRequest, 0),
		CheckPointLog:           &CheckpointLog{Mutex: sync.RWMutex{}, LastCheckPointSequenceNum: 0, Log: make(map[int64]map[string]*pb.SignedCheckPointMessage), Quorum: 2*int64(len(peerNodes)/3) + 1},
	}

	executor.sendReply = func(sequenceNum int64, request *pb.TransactionRequest, result int64) {
		server.SendReply(sequenceNum, request, result)
	}

	return server
}
