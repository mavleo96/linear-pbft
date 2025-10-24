package linearpbft

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

func (n *LinearPBFTNode) AssignSequenceNumber(request *pb.TransactionRequest) int64 {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Compute digest of request
	requestDigest := security.Digest(request)

	// Check if request is already in preprepare log
	for _, preprepare := range n.PrePrepareLog {
		if preprepare != nil && cmp.Equal(preprepare.Digest, requestDigest) {
			return preprepare.SequenceNum
		}
	}

	// If request is not in preprepare log, assign new sequence number
	// and add to transaction map
	sequenceNum := int64(0)
	maxSequenceNum := utils.Max(utils.Keys(n.PrePrepareLog))
	if maxSequenceNum == nil {
		sequenceNum = int64(1)
	} else {
		sequenceNum = *maxSequenceNum + 1
	}
	n.PrePrepareLog[sequenceNum] = nil
	n.TransactionMap[utils.To32Bytes(requestDigest)] = request

	return sequenceNum
}

func (n *LinearPBFTNode) ViewNumberToLeader(viewNumber int64) string {
	leaderID := viewNumber % int64(len(n.Peers))
	return fmt.Sprintf("n%d", leaderID+1)
}
