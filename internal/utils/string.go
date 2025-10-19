package utils

import (
	"fmt"

	"github.com/mavleo96/bft-mavleo96/pb"
)

func TransactionRequestString(t *pb.TransactionRequest) string {
	return fmt.Sprintf("<REQUEST, %s, %d, %s>", TransactionString(t.Transaction), t.Timestamp, t.Sender)
}

func TransactionString(t *pb.Transaction) string {
	return fmt.Sprintf("(%s, %s, %d)", t.Sender, t.Receiver, t.Amount)
}
