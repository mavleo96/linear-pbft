package linearpbft

import (
	"sync"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
)

const (
	ExecutionTimeout  = 400 * time.Millisecond
	ViewChangeTimeout = 600 * time.Millisecond
	TimeAttackDelay   = 50 * time.Millisecond
)

// type ServerState struct {

// LinearPBFTNode represents a LinearPBFT node
type LinearPBFTNode struct {
	// Node information
	*models.Node
	PrivateKey []byte
	DB         *database.Database

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
	Peers         map[string]*models.Node
	F             int64
	N             int64
	K             int64 // checkpoint interval
	LowWaterMark  int64
	HighWaterMark int64

	// Clients and their information
	Clients map[string]*models.Client

	// State variables and mutex for synchronizing access to shared resources
	Mutex     sync.RWMutex
	LastReply *LastReply

	// Server state
	State *ServerState

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
func CreateLinearPBFTNode(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, bankDB *database.Database, privateKey []byte) *LinearPBFTNode {

	serverState := &ServerState{
		mutex:                   sync.RWMutex{},
		viewNumber:              0,
		viewChangePhase:         false,
		viewChangeViewNumber:    0,
		lastExecutedSequenceNum: 0,
		StateLog:                &StateLog{mutex: sync.RWMutex{}, log: make(map[int64]*LogRecord)},
		TransactionMap:          CreateTransactionMap(),
	}

	return &LinearPBFTNode{
		Node:                    selfNode,
		DB:                      bankDB,
		Alive:                   true,
		Byzantine:               false,
		SignAttack:              false,
		CrashAttack:             false,
		DarkAttack:              false,
		DarkAttackNodes:         make([]string, 0),
		TimeAttack:              false,
		EquivocationAttack:      false,
		EquivocationAttackNodes: make([]string, 0),
		PrivateKey:              privateKey,
		Peers:                   peerNodes,
		Clients:                 clientMap,
		F:                       int64(len(peerNodes) / 3),
		N:                       int64(len(peerNodes) + 1),
		K:                       10,
		LowWaterMark:            0,
		HighWaterMark:           100,
		Mutex:                   sync.RWMutex{},
		LastReply:               &LastReply{Mutex: sync.RWMutex{}, ReplyMap: make(map[string]*pb.TransactionResponse)},
		State:                   serverState,
		SafeTimer:               CreateSafeTimer(ExecutionTimeout, ViewChangeTimeout),
		CheckPointRoutineCh:     make(chan bool),
		RequestCh:               make(chan *pb.SignedTransactionRequest, 20),
		PrepareCh:               make(chan []*pb.SignedPrepareMessage, 20),
		CommitCh:                make(chan []*pb.SignedCommitMessage, 20),
		ViewChangeMessageLog:    make(map[int64]map[string]*pb.SignedViewChangeMessage),
		ForwardedRequestsLog:    make([]*pb.SignedTransactionRequest, 0),
		CheckPointLog:           &CheckpointLog{Mutex: sync.RWMutex{}, LastCheckPointSequenceNum: 0, Log: make(map[int64]map[string]*pb.SignedCheckPointMessage), Quorum: 2*int64(len(peerNodes)/3) + 1},
	}
}
