package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	log "github.com/sirupsen/logrus"
)

// TryExecute tries to execute a transaction
func (n *LinearPBFTNode) TryExecute(sequenceNum int64) {
	// Get the record from log record or create new one
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	record := n.LogRecords[sequenceNum]

	// If record is not nil and already executed, send reply if timestamp is same as last reply
	if record != nil && record.IsExecuted() {
		request := n.TransactionMap.Get(record.Digest).Request
		lastReply := n.LastReply.Get(request.Sender)
		if lastReply != nil && request.Timestamp == lastReply.Timestamp {
			go n.SendReply(sequenceNum, request, lastReply.Result)
		}
		log.Infof("Sequence number %d already executed", sequenceNum)
	}

	// Get max sequence number in log record
	maxSequenceNum := utils.Max(utils.Keys(n.LogRecords))

	// Try to execute as many transactions as possible
	for i := n.LastExecutedSequenceNum + 1; i <= maxSequenceNum; i++ {
		// Check if sequence is committed
		record := n.LogRecords[i]
		if record == nil || !record.IsCommitted() {
			log.Warnf("Sequence number %d not committed", i)
			break
		}

		// Execute transaction
		request := n.TransactionMap.Get(record.Digest).Request
		var result int64
		var err error
		switch request.Transaction.Type {
		case "read":
			result, err = n.DB.GetBalance(request.Transaction.Sender)
			log.Infof("Read transaction result: %d", result)
		case "send":
			var success bool
			success, err = n.DB.UpdateDB(request.Transaction)
			result = utils.BoolToInt64(success)
		default:
			continue
		}
		if err != nil {
			log.Fatal(err)
		}

		// Add to executed log and send reply if transaction is not null
		record.SetExecuted()
		// TODO: make this elegant since leader doesn't have a safe timer running
		n.SafeTimer.DecrementWaitCountAndResetOrStopIfZero()
		log.Infof("Executed (v: %d, s: %d): %s", n.ViewNumber, i, utils.LoggingString(request.Transaction))
		if request.Transaction.Type != "null" {
			go n.SendReply(i, request, result)
		}
		n.LastExecutedSequenceNum = i
	}
}
