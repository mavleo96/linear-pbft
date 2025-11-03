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
	ViewChangeTimeout = 700 * time.Millisecond
	TimeAttackDelay   = 50 * time.Millisecond
)

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
	Mutex                   sync.RWMutex
	ViewNumber              int64
	LastReply               *LastReply
	ViewChangePhase         bool
	ViewChangeViewNumber    int64
	TransactionMap          *TransactionMap
	LogRecords              map[int64]*LogRecord
	LastExecutedSequenceNum int64

	// Timer instance
	SafeTimer *SafeTimer

	// Channels
	CheckPointRoutineCh chan bool

	// Message logs
	ViewChangeMessageLog map[int64]map[string]*pb.SignedViewChangeMessage // v -> (id -> msg)
	ForwardedRequestsLog []*pb.SignedTransactionRequest
	CheckPointLog        *CheckpointLog

	// UnimplementedLinearPBFTNodeServer is the server interface for the LinearPBFT node
	*pb.UnimplementedLinearPBFTNodeServer
}

// CreateLinearPBFTNode creates a new LinearPBFT node
func CreateLinearPBFTNode(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, bankDB *database.Database, privateKey []byte) *LinearPBFTNode {
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
		ViewNumber:              0,
		LogRecords:              make(map[int64]*LogRecord),
		LastExecutedSequenceNum: 0,
		LastReply:               &LastReply{Mutex: sync.RWMutex{}, ReplyMap: make(map[string]*pb.TransactionResponse)},
		ViewChangePhase:         false,
		ViewChangeViewNumber:    0,
		TransactionMap:          CreateTransactionMap(),
		SafeTimer:               CreateSafeTimer(ExecutionTimeout, ViewChangeTimeout),
		CheckPointRoutineCh:     make(chan bool),
		ViewChangeMessageLog:    make(map[int64]map[string]*pb.SignedViewChangeMessage),
		ForwardedRequestsLog:    make([]*pb.SignedTransactionRequest, 0),
		CheckPointLog:           &CheckpointLog{Mutex: sync.RWMutex{}, LastCheckPointSequenceNum: 0, Log: make(map[int64]map[string]*pb.SignedCheckPointMessage), Quorum: 2*int64(len(peerNodes)/3) + 1},
	}
}
