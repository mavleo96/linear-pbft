package utils

import (
	"fmt"

	"github.com/mavleo96/bft-mavleo96/pb"
)

func MessageString(t any) string {
	switch v := t.(type) {
	case *pb.TransactionRequest:
		return transactionRequestString(v)
	case *pb.Transaction:
		return transactionString(v)
	default:
		return fmt.Sprintf("<%T>", t)
	}
}

func transactionRequestString(t *pb.TransactionRequest) string {
	return fmt.Sprintf("<REQUEST, %s, %d, %s>", transactionString(t.Transaction), t.Timestamp, t.Sender)
}

func transactionString(t *pb.Transaction) string {
	return fmt.Sprintf("(%s, %s, %d)", t.Sender, t.Receiver, t.Amount)
}
