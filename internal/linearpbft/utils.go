package linearpbft

import (
	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// AssignSequenceNumber assigns a sequence number to a transaction request and adds it to the log record
// If the request is already in the log record, it returns the sequence number of the existing request
func (n *LinearPBFTNode) AssignSequenceNumber(request *pb.TransactionRequest) int64 {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Compute digest of request
	digest := crypto.Digest(request)

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
	sequenceNum := utils.Max(utils.Keys(n.LogRecords)) + 1

	// Add to log record and transaction map and return sequence number
	n.LogRecords[sequenceNum] = CreateLogRecord(n.ViewNumber, sequenceNum, digest)

	return sequenceNum
}

// GetPublicKey returns the public key of a node
func (n *LinearPBFTNode) GetPublicKey(nodeID string) []byte {
	if nodeID == n.ID {
		return n.PublicKey
	}
	return n.Peers[nodeID].PublicKey
}
