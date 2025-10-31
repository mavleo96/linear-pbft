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
	*models.Node
	PrivateKey []byte
	DB         *database.Database

	Peers   map[string]*models.Node
	F       int64
	N       int64
	Clients map[string]*models.Client

	Mutex                   sync.Mutex
	ViewNumber              int64
	LogRecords              map[int64]*LogRecord
	LastExecutedSequenceNum int64
	LastReply               *LastReply

	SafeTimer *SafeTimer
	// ExecuteSignalCh chan int64
	// Flag bool

	ViewChangePhase      bool
	ViewChangeMessageLog map[int64]map[string]*pb.SignedViewChangeMessage // v -> (id -> msg)
	ForwardedRequestsLog []*pb.SignedTransactionRequest

	*pb.UnimplementedLinearPBFTNodeServer
}

func CreateLinearPBFTNode(selfNode *models.Node, peerNodes map[string]*models.Node, clientMap map[string]*models.Client, bankDB *database.Database, privateKey []byte) *LinearPBFTNode {
	return &LinearPBFTNode{
		Node:                    selfNode,
		DB:                      bankDB,
		PrivateKey:              privateKey,
		Peers:                   peerNodes,
		Clients:                 clientMap,
		F:                       int64(len(peerNodes) / 3),
		N:                       int64(len(peerNodes) + 1),
		Mutex:                   sync.Mutex{},
		ViewNumber:              0,
		LogRecords:              make(map[int64]*LogRecord),
		LastReply:               &LastReply{Mutex: sync.RWMutex{}, ReplyMap: make(map[string]*pb.TransactionResponse)},
		LastExecutedSequenceNum: 0,
		SafeTimer:               CreateSafeTimer(500 * time.Millisecond),
		ViewChangePhase:         false,
		ViewChangeMessageLog:    make(map[int64]map[string]*pb.SignedViewChangeMessage),
		ForwardedRequestsLog:    make([]*pb.SignedTransactionRequest, 0),
		// Flag:                    false,
	}
}
