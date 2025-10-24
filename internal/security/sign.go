package security

// TODO: maybe rename this to crypto

import (
	"crypto/ed25519"
	"fmt"

	"github.com/mavleo96/bft-mavleo96/pb"
)

func Sign[T any](message T, privateKey []byte) []byte {
	msgString := messageString(message)
	return ed25519.Sign(privateKey, []byte(msgString))
}

func Verify[T any](message T, publicKey []byte, signature []byte) bool {
	msgString := messageString(message)
	return ed25519.Verify(publicKey, []byte(msgString), signature)
}

func messageString(message any) string {
	switch v := message.(type) {
	case *pb.CommitMessage:
		return commitMessageString(v)
	case *pb.PrepareMessage:
		return prepareMessageString(v)
	case *pb.PrePrepareMessage:
		return prePrepareMessageString(v)
	case *pb.TransactionRequest:
		return transactionRequestString(v)
	case *pb.Transaction:
		return transactionString(v)
	default:
		return fmt.Sprintf("<%T>", message)
	}
}

func commitMessageString(c *pb.CommitMessage) string {
	return fmt.Sprintf("<COMMIT, %d, %d, %s, %s>", c.ViewNumber, c.SequenceNum, c.Digest, c.NodeID)
}

func prepareMessageString(p *pb.PrepareMessage) string {
	return fmt.Sprintf("<PREPARE, %d, %d, %s, %s>", p.ViewNumber, p.SequenceNum, p.Digest, p.NodeID)
}

func prePrepareMessageString(p *pb.PrePrepareMessage) string {
	return fmt.Sprintf("<PREPREPARE, %d, %d, %s>", p.ViewNumber, p.SequenceNum, p.Digest)
}

func transactionRequestString(t *pb.TransactionRequest) string {
	return fmt.Sprintf("<REQUEST, %s, %d, %s>", transactionString(t.Transaction), t.Timestamp, t.Sender)
}

func transactionString(t *pb.Transaction) string {
	if t.Type == "read" {
		return fmt.Sprintf("(%s)", t.Sender)
	}
	return fmt.Sprintf("(%s, %s, %d)", t.Sender, t.Receiver, t.Amount)
}
