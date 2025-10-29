package linearpbft

import (
	"context"
	"sync"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

var NoOpTransactionRequest = &pb.TransactionRequest{
	Transaction: &pb.Transaction{
		Type:     "send",
		Sender:   "null",
		Receiver: "null",
		Amount:   0,
	},
	Timestamp: 0,
	Sender:    "null",
}

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
	LastReply               map[string]*pb.TransactionResponse

	SafeTimer *SafeTimer
	// ExecuteSignalCh chan int64
	// Flag bool

	SentViewChange       bool
	ViewChangeMessageLog map[int64]map[string]*pb.SignedViewChangeMessage // v -> (id -> msg)
	ForwardedRequestsLog []*pb.SignedTransactionRequest

	*pb.UnimplementedLinearPBFTNodeServer
}

func (n *LinearPBFTNode) TryExecute(sequenceNum int64) {
	// Check if sequence number is in executed log
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	record := n.LogRecords[sequenceNum]

	if record != nil && record.IsExecuted() {
		// Send reply if timestamp is same as last reply
		request := record.Request
		lastReply := n.LastReply[request.Sender]
		if lastReply != nil && request.Timestamp == lastReply.Timestamp {
			go n.SendReply(sequenceNum, request, lastReply.Result)
		}
		log.Infof("Sequence number %d already executed", sequenceNum)
	}

	// Get max sequence number in log record
	maxSequenceNum := int64(0)
	if utils.Max(utils.Keys(n.LogRecords)) != nil {
		maxSequenceNum = *utils.Max(utils.Keys(n.LogRecords))
	}

	// Try to execute as many transactions as possible
	for i := n.LastExecutedSequenceNum + 1; i <= maxSequenceNum; i++ {
		// Check if sequence is committed
		record := n.LogRecords[i]
		if record == nil || !record.IsCommitted() {
			log.Warnf("Sequence number %d not committed", i)
			break
		}

		// Execute transaction
		request := record.Request
		var result int64
		var err error
		if request.Transaction.Type == "read" {
			result, err = n.DB.GetBalance(request.Transaction.Sender)
			log.Infof("Read transaction result: %d", result)
		} else {
			var success bool
			success, err = n.DB.UpdateDB(request.Transaction)
			result = utils.BoolToInt64(success)

		}
		if err != nil {
			log.Fatal(err)
		}

		// Add to executed log
		record.SetExecuted()
		// TODO: make this elegant since leader doesn't have a safe timer running
		n.SafeTimer.DecrementWaitCountAndResetOrStopIfZero()
		log.Infof("Executed (v: %d, s: %d): %s", n.ViewNumber, i, utils.LoggingString(request.Transaction))
		go n.SendReply(i, request, result)
		n.LastExecutedSequenceNum = i
	}
}

func (n *LinearPBFTNode) ViewChangeRoutine(ctx context.Context) {
	log.Infof("Starting view change routine for %s", n.ID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.SafeTimer.TimeoutCh:
			log.Infof("View change routine: Timer expired")
			go n.SendViewChange()
		}
	}
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
		LastReply:               make(map[string]*pb.TransactionResponse),
		LastExecutedSequenceNum: 0,
		SafeTimer:               CreateSafeTimer(500 * time.Millisecond),
		ViewChangeMessageLog:    make(map[int64]map[string]*pb.SignedViewChangeMessage),
		ForwardedRequestsLog:    make([]*pb.SignedTransactionRequest, 0),
		// Flag:                    false,
	}
}
