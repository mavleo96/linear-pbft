package linearpbft

import (
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
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
	PrePreparedLog          map[int64]*LogRecord
	PreparedLog             map[int64]*LogRecord
	CommittedLog            map[int64]*LogRecord
	ExecutedLog             map[int64]*LogRecord
	LastExecutedSequenceNum int64
	LastReply               map[string]*pb.TransactionResponse

	TransactionMap map[[32]byte]*pb.TransactionRequest

	*pb.UnimplementedLinearPBFTNodeServer
}

type LogRecord struct {
	ViewNumber  int64
	SequenceNum int64
	Digest      []byte
}

func (n *LinearPBFTNode) TryExecute(sequenceNum int64) {
	// Check if sequence number is in executed log
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	executedRecord := n.ExecutedLog[sequenceNum]
	if executedRecord != nil {
		// Send reply if timestamp is same as last reply
		digest := executedRecord.Digest
		request := n.TransactionMap[utils.To32Bytes(digest)]
		lastReply := n.LastReply[request.Sender]
		if lastReply != nil && request.Timestamp == lastReply.Timestamp {
			go n.SendReply(sequenceNum, request, lastReply.Result)
		}
		log.Infof("Sequence number %d already executed", sequenceNum)
	}

	// Get max sequence number in committed log
	maxSequenceNum := int64(0)
	if utils.Max(utils.Keys(n.CommittedLog)) != nil {
		maxSequenceNum = *utils.Max(utils.Keys(n.CommittedLog))
	}

	// Try to execute as many transactions as possible
	for i := n.LastExecutedSequenceNum + 1; i <= maxSequenceNum; i++ {
		// Check if sequence in committed log
		committedRecord := n.CommittedLog[i]
		if committedRecord == nil {
			log.Warnf("Sequence number %d not committed", i)
			break
		}

		// Execute transaction
		digest := committedRecord.Digest
		request := n.TransactionMap[utils.To32Bytes(digest)]
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
		n.ExecutedLog[i] = &LogRecord{
			ViewNumber:  n.ViewNumber,
			SequenceNum: i,
			Digest:      committedRecord.Digest,
		}
		log.Infof("Executed (v: %d, s: %d): %s", n.ViewNumber, i, utils.LoggingString(request.Transaction))
		go n.SendReply(i, request, result)
		n.LastExecutedSequenceNum = i
	}
}
