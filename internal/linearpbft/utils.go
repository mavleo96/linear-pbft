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

	// Check if request is already in preprepare log
	for _, preprepare := range n.PrePreparedLog {
		if preprepare == nil {
			log.Fatal("Preprepare log record is nil")
		}
		if preprepare != nil && cmp.Equal(preprepare.Digest, digest) {
			return preprepare.SequenceNum
		}
	}

	// If request is not in preprepare log, assign new sequence number
	sequenceNum := int64(0)
	maxSequenceNum := utils.Max(utils.Keys(n.PrePreparedLog))
	if maxSequenceNum == nil {
		sequenceNum = int64(1)
	} else {
		sequenceNum = *maxSequenceNum + 1
	}

	// Add to preprepare log and transaction map
	n.PrePreparedLog[sequenceNum] = &LogRecord{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      digest,
	}
	n.TransactionMap[utils.To32Bytes(digest)] = request

	return sequenceNum
}

func (n *LinearPBFTNode) ViewNumberToLeader(v int64) string {
	leaderID := v % n.N
	return fmt.Sprintf("n%d", leaderID+1)
}
