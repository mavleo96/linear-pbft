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
func (n *LinearPBFTNode) GetOrAssignSequenceNumber(signedRequest *pb.SignedTransactionRequest) (int64, bool) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Compute digest of request
	digest := crypto.Digest(signedRequest)

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

// CreateMaliciousSignedPrePrepareMessage creates a malicious signed preprepare message
func (n *LinearPBFTNode) CreateMaliciousSignedPrePrepareMessage(signedMessage *pb.SignedPrePrepareMessage) *pb.SignedPrePrepareMessage {
	message := signedMessage.Message
	message.SequenceNum += 1
	return &pb.SignedPrePrepareMessage{
		Message:   message,
		Signature: crypto.Sign(message, n.PrivateKey),
		Request:   signedMessage.Request,
	}
}
