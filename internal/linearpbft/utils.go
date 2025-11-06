package linearpbft

import (
	"github.com/herumi/bls-eth-go-binary/bls"
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

// GetPublicKey1 returns the public key 1 of a node
func (n *LinearPBFTNode) GetPublicKey1(nodeID string) *bls.PublicKey {
	if nodeID == n.ID {
		return n.PublicKey1
	}
	return n.Peers[nodeID].PublicKey1
}

// GetPublicKey2 returns the public key 2 of a node
func (n *LinearPBFTNode) GetPublicKey2(nodeID string) *bls.PublicKey {
	if nodeID == n.ID {
		return n.PublicKey2
	}
	return n.Peers[nodeID].PublicKey2
}
