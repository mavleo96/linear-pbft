package security

// TODO: maybe rename this to crypto

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"strings"

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
	case *pb.TransactionResponse:
		return transactionResponseString(v)
	case *pb.NewViewMessage:
		return newViewMessageString(v)
	case *pb.ViewChangeMessage:
		return viewChangeMessageString(v)
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
		// TODO: remove this
		log.Fatalf("Unknown message type: %T", message)
		return fmt.Sprintf("<%T>", message)
	}
}

func transactionResponseString(r *pb.TransactionResponse) string {
	return fmt.Sprintf("<REPLY, %d, %d, %s, %s, %d>", r.ViewNumber, r.Timestamp, r.Sender, r.NodeID, r.Result)
}

func newViewMessageString(v *pb.NewViewMessage) string {
	viewChangeMessageStringSlice := make([]string, 0)
	for _, signedViewChangeMessage := range v.SignedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		viewChangeMessageString := viewChangeMessageString(viewChangeMessage)
		viewChangeMessageStringSlice = append(viewChangeMessageStringSlice, viewChangeMessageString)
	}
	viewChangeMessagesString := strings.Join(viewChangeMessageStringSlice, ", ")
	viewChangeMessagesString = "{" + viewChangeMessagesString + "}"

	prePrepareMessageStringSlice := make([]string, 0)
	for _, signedPrePrepareMessage := range v.SignedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		prePrepareMessageString := prePrepareMessageString(prePrepareMessage)
		prePrepareMessageStringSlice = append(prePrepareMessageStringSlice, prePrepareMessageString)
	}
	prePrepareMessagesString := strings.Join(prePrepareMessageStringSlice, ", ")
	prePrepareMessagesString = "{" + prePrepareMessagesString + "}"

	return fmt.Sprintf("<NEWVIEW, %d, %s, %s>", v.ViewNumber, viewChangeMessagesString, prePrepareMessagesString)
}

func viewChangeMessageString(v *pb.ViewChangeMessage) string {
	prepareProofStringSlice := make([]string, 0)
	for _, prepareProof := range v.PreparedSet {
		prepareProofString := prepareProofString(prepareProof)
		prepareProofStringSlice = append(prepareProofStringSlice, prepareProofString)
	}
	prepareProofString := strings.Join(prepareProofStringSlice, ", ")
	prepareProofString = "{" + prepareProofString + "}"

	return fmt.Sprintf("<VIEWCHANGE, %d, %d, C, %s, %s>", v.ViewNumber, v.SequenceNum, prepareProofString, v.NodeID)
}

func prepareProofString(p *pb.PrepareProof) string {
	prePrepareMessageString := prePrepareMessageString(p.SignedPrePrepareMessage.Message)

	prepareMessageStringSlice := make([]string, 0)
	for _, prepareMessage := range p.SignedPrepareMessages {
		prepareMessageStringSlice = append(prepareMessageStringSlice, prepareMessageString(prepareMessage.Message))
	}
	prepareMessagesString := strings.Join(prepareMessageStringSlice, ", ")
	prepareMessagesString = "{" + prepareMessagesString + "}"

	return fmt.Sprintf("<PREPAREPROOF, %s, %s>", prePrepareMessageString, prepareMessagesString)
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
	if t.Type == "null" {
		return "(null)"
	}
	if t.Type == "read" {
		return fmt.Sprintf("(%s)", t.Sender)
	}
	return fmt.Sprintf("(%s, %s, %d)", t.Sender, t.Receiver, t.Amount)
}
