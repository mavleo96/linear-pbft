package linearpbft

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) AssignSequenceNumber(request *pb.TransactionRequest) int64 {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Compute digest of request
	digest := security.Digest(request)

	// Check if request is already in log record
	for _, record := range n.LogRecords {
		if record == nil {
			log.Fatal("Log record is nil")
		}
		if record != nil && cmp.Equal(record.Digest, digest) {
			return record.SequenceNum
		}
	}

	// If request is not in log record, assign new sequence number
	sequenceNum := int64(0)
	maxSequenceNum := utils.Max(utils.Keys(n.LogRecords))
	if maxSequenceNum == nil {
		sequenceNum = int64(1)
	} else {
		sequenceNum = *maxSequenceNum + 1
	}

	// Add to log record and transaction map and return sequence number
	n.LogRecords[sequenceNum] = CreateLogRecord(n.ViewNumber, sequenceNum, digest)

	return sequenceNum
}

func (n *LinearPBFTNode) ViewNumberToLeader(v int64) string {
	leaderID := v % n.N
	return fmt.Sprintf("n%d", leaderID+1)
}
