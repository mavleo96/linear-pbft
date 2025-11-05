package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// NoOpTransactionRequest is a no-op transaction request
var NoOpTransactionRequest = &pb.SignedTransactionRequest{
	Request: &pb.TransactionRequest{
		Transaction: &pb.Transaction{
			Type:     "null",
			Sender:   "null",
			Receiver: "null",
			Amount:   0,
		},
		Timestamp: 0,
		Sender:    "null",
	},
	Signature: []byte{},
}

// DigestNoOp is the digest of the no-op transaction request
var DigestNoOp = crypto.Digest(NoOpTransactionRequest)

// GetPublicKey returns the public key of a node
func (n *LinearPBFTNode) GetPublicKey(nodeID string) []byte {
	if nodeID == n.ID {
		return n.PublicKey
	}
	return n.Peers[nodeID].PublicKey
}
