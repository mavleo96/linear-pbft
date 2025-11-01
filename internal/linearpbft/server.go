package linearpbft

import (
	"sync"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
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
	Peers map[string]*models.Node
	F     int64
	N     int64

	// Clients and their information
	Clients map[string]*models.Client

	// State variables and mutex for synchronizing access to shared resources
	Mutex                   sync.Mutex
	ViewNumber              int64
	LogRecords              map[int64]*LogRecord
	LastExecutedSequenceNum int64
	LastReply               *LastReply
	ViewChangePhase         bool
	ViewChangeViewNumber    int64
	TransactionMap          *TransactionMap

	// Timer instance
	SafeTimer *SafeTimer

	// Message logs
	ViewChangeMessageLog map[int64]map[string]*pb.SignedViewChangeMessage // v -> (id -> msg)
	ForwardedRequestsLog []*pb.SignedTransactionRequest

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
		Mutex:                   sync.Mutex{},
		ViewNumber:              0,
		LogRecords:              make(map[int64]*LogRecord),
		LastExecutedSequenceNum: 0,
		LastReply:               &LastReply{Mutex: sync.RWMutex{}, ReplyMap: make(map[string]*pb.TransactionResponse)},
		ViewChangePhase:         false,
		ViewChangeViewNumber:    0,
		TransactionMap:          CreateTransactionMap(),
		SafeTimer:               CreateSafeTimer(500 * time.Millisecond),
		ViewChangeMessageLog:    make(map[int64]map[string]*pb.SignedViewChangeMessage),
		ForwardedRequestsLog:    make([]*pb.SignedTransactionRequest, 0),
	}
}
