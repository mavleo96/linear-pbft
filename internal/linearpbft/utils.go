package linearpbft

import (
	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// GetOrAssignSequenceNumber gets the sequence number of a transaction request from the log record
// or assigns a new sequence number to the request
func (n *LinearPBFTNode) GetOrAssignSequenceNumber(request *pb.TransactionRequest) (int64, bool) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Compute digest of request
	digest := crypto.Digest(request)

	// Check if request is already in log record
	for _, record := range n.LogRecords {
		// TODO: remove this later
		if record == nil {
			log.Fatal("Log record is nil")
		}
		if record != nil && cmp.Equal(record.Digest, digest) {
			return record.SequenceNum, true
		}
	}

	// If request is not in log record, assign new sequence number
	sequenceNum := utils.Max(utils.Keys(n.LogRecords)) + 1
	return sequenceNum, false
}

// GetPublicKey returns the public key of a node
func (n *LinearPBFTNode) GetPublicKey(nodeID string) []byte {
	if nodeID == n.ID {
		return n.PublicKey
	}
	return n.Peers[nodeID].PublicKey
}
