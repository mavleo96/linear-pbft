package utils

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mavleo96/bft-mavleo96/pb"
)

func LoggingString(t any, request ...*pb.TransactionRequest) string {
	var req *pb.TransactionRequest
	if len(request) > 0 {
		req = request[0]
	}
	switch v := t.(type) {
	case *pb.TransactionResponse:
		return transactionResponseString(v)
	case *pb.NewViewMessage:
		return newViewMessageString(v)
	case *pb.ViewChangeMessage:
		return viewChangeMessageString(v)
	case *pb.CommitMessage:
		return commitMessageString(v, req)
	case *pb.PrepareMessage:
		return prepareMessageString(v, req)
	case *pb.PrePrepareMessage:
		return prePrepareMessageString(v, req)
	case *pb.TransactionRequest:
		return transactionRequestString(v)
	case *pb.Transaction:
		return transactionString(v)
	case *pb.GetRequestMessage:
		return getRequestMessageString(v)
	default:
		return fmt.Sprintf("<%T>", t)
	}
}

func transactionResponseString(r *pb.TransactionResponse) string {
	return fmt.Sprintf("<REPLY, %d, %d, %s, %s, %d>", r.ViewNumber, r.Timestamp, r.Sender, r.NodeID, r.Result)
}

func newViewMessageString(v *pb.NewViewMessage) string {
	viewChangeMessageStringSlice := make([]string, 0)
	for _, signedViewChangeMessage := range v.SignedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		nodeID := viewChangeMessage.NodeID
		viewChangeMessageStringSlice = append(viewChangeMessageStringSlice, fmt.Sprintf("VC(%s)", nodeID))
	}
	viewChangeMessagesString := strings.Join(viewChangeMessageStringSlice, ", ")
	viewChangeMessagesString = "{" + viewChangeMessagesString + "}"

	prePrepareMessageStringSlice := make([]string, 0)
	for _, signedPrePrepareMessage := range v.SignedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		prePrepareMessageStringSlice = append(prePrepareMessageStringSlice, fmt.Sprintf("PP%d", prePrepareMessage.SequenceNum))
	}
	prePrepareMessagesString := strings.Join(prePrepareMessageStringSlice, ", ")
	prePrepareMessagesString = "{" + prePrepareMessagesString + "}"

	return fmt.Sprintf("<NEWVIEW, %d, %s, %s>", v.ViewNumber, viewChangeMessagesString, prePrepareMessagesString)
}

func viewChangeMessageString(v *pb.ViewChangeMessage) string {
	prepareStringSlice := make([]string, 0)
	for _, prepareProof := range v.PreparedSet {
		sequenceNum := prepareProof.SignedPrePrepareMessage.Message.SequenceNum
		prepareStringSlice = append(prepareStringSlice, fmt.Sprintf("P%d", sequenceNum))
	}
	prepareString := "{" + strings.Join(prepareStringSlice, ", ") + "}"

	return fmt.Sprintf("<VIEWCHANGE, %d, %d, C, %s, %s>", v.ViewNumber, v.SequenceNum, prepareString, v.NodeID)
}

func commitMessageString(c *pb.CommitMessage, request *pb.TransactionRequest) string {
	return fmt.Sprintf("<COMMIT, %d, %d, D(%s), %s>", c.ViewNumber, c.SequenceNum, transactionRequestString(request), c.NodeID)
}

func prepareMessageString(p *pb.PrepareMessage, request *pb.TransactionRequest) string {
	return fmt.Sprintf("<PREPARE, %d, %d, D(%s), %s>", p.ViewNumber, p.SequenceNum, transactionRequestString(request), p.NodeID)
}

func prePrepareMessageString(p *pb.PrePrepareMessage, request *pb.TransactionRequest) string {
	if request == nil {
		return fmt.Sprintf("<PREPREPARE, %d, %d, D(message)>", p.ViewNumber, p.SequenceNum)
	}
	return fmt.Sprintf("<PREPREPARE, %d, %d, D(%s)>", p.ViewNumber, p.SequenceNum, transactionRequestString(request))
}

func transactionRequestString(t *pb.TransactionRequest) string {
	return fmt.Sprintf("<REQUEST, %s, %d, %s>", transactionString(t.Transaction), t.Timestamp, t.Sender)
}

func transactionString(t *pb.Transaction) string {
	if t.Type == "null" {
		return "(null)"
	}
	if t.Type == "read" {
		return fmt.Sprintf("(%s)", t.Sender)
	}
	return fmt.Sprintf("(%s, %s, %d)", t.Sender, t.Receiver, t.Amount)
}

func getRequestMessageString(g *pb.GetRequestMessage) string {
	return fmt.Sprintf("<GETREQUEST, %s>", hex.EncodeToString(g.Digest))
}
