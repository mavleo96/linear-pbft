package utils

import (
	"fmt"

	"github.com/mavleo96/bft-mavleo96/pb"
)

// func MessageString(t any) string {
// 	switch v := t.(type) {
// 	case *pb.PrepareMessage:
// 		return prepareMessageString(v)
// 	case *pb.PrePrepareMessage:
// 		return prePrepareMessageString(v)
// 	case *pb.TransactionRequest:
// 		return transactionRequestString(v)
// 	case *pb.Transaction:
// 		return transactionString(v)
// 	default:
// 		return fmt.Sprintf("<%T>", t)
// 	}
// }

// func prepareMessageString(p *pb.PrepareMessage) string {
// 	return fmt.Sprintf("<PREPARE, %d, %d, %s, %s>", p.ViewNumber, p.SequenceNum, p.Digest, p.NodeID)
// }

// func prePrepareMessageString(p *pb.PrePrepareMessage) string {
// 	return fmt.Sprintf("<PREPREPARE, %d, %d, %s>", p.ViewNumber, p.SequenceNum, p.Digest)
// }

func TransactionRequestString(t *pb.TransactionRequest) string {
	return fmt.Sprintf("<REQUEST, %s, %d, %s>", transactionString(t.Transaction), t.Timestamp, t.Sender)
}

func transactionString(t *pb.Transaction) string {
	if t.Type == "read" {
		return fmt.Sprintf("(%s)", t.Sender)
	}
	return fmt.Sprintf("(%s, %s, %d)", t.Sender, t.Receiver, t.Amount)
}
