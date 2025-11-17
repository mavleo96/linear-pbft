package utils

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mavleo96/linear-pbft/pb"
)

func FormattedLoggingString(t any) string {
	switch v := t.(type) {
	case *pb.SignedPrePrepareMessage:
		return prePrepareMessageString(v, false)
	case *pb.SignedPrepareMessage:
		return prepareMessageString(v, false)
	case *pb.SignedCommitMessage:
		return commitMessageString(v, false)
	case *pb.SignedViewChangeMessage:
		return viewChangeMessageString(v, true, false, 0)
	case *pb.SignedNewViewMessage:
		return newViewMessageString(v, true, false)
	case *pb.SignedCheckpointMessage:
		return checkpointMessageString(v, false)
	case *pb.SignedTransactionRequest:
		return transactionRequestString(v)
	case *pb.SignedTransactionResponse:
		return transactionResponseString(v)
	case *pb.GetRequestMessage:
		return getRequestMessageString(v)
	case *pb.GetCheckpointMessage:
		return getCheckpointMessageString(v)
	case *pb.Checkpoint:
		return checkpointString(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func LoggingString(t any) string {
	switch v := t.(type) {
	case *pb.SignedPrePrepareMessage:
		return prePrepareMessageString(v, true)
	case *pb.SignedPrepareMessage:
		return prepareMessageString(v, true)
	case *pb.SignedCommitMessage:
		return commitMessageString(v, true)
	case *pb.SignedViewChangeMessage:
		return viewChangeMessageString(v, false, true, 0)
	case *pb.SignedNewViewMessage:
		return newViewMessageString(v, false, true)
	case *pb.SignedCheckpointMessage:
		return checkpointMessageString(v, true)
	case *pb.SignedTransactionRequest:
		return transactionRequestString(v)
	case *pb.SignedTransactionResponse:
		return transactionResponseString(v)
	case *pb.GetRequestMessage:
		return getRequestMessageString(v)
	case *pb.GetCheckpointMessage:
		return getCheckpointMessageString(v)
	case *pb.Checkpoint:
		return checkpointString(v)
	case *pb.Transaction:
		return transactionString(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func prePrepareMessageString(p *pb.SignedPrePrepareMessage, short bool) string {
	msg := p.Message
	requestString := ""
	if p.Request != nil {
		requestString = transactionRequestString(p.Request)
	}
	if short {
		return fmt.Sprintf("<PRE-PREPARE, %d, %d, D(%s)>", msg.ViewNumber, msg.SequenceNum, requestString)
	}
	return fmt.Sprintf("<<PRE-PREPARE, %d, %d, %s>, %s>", msg.ViewNumber, msg.SequenceNum, hex.EncodeToString(msg.Digest), requestString)
}

func prepareMessageString(p *pb.SignedPrepareMessage, short bool) string {
	msg := p.Message
	if short {
		return fmt.Sprintf("<PREPARE, %d, %d, D, %s>", msg.ViewNumber, msg.SequenceNum, msg.NodeID)
	}
	return fmt.Sprintf("<PREPARE, %d, %d, %s, %s>", msg.ViewNumber, msg.SequenceNum, hex.EncodeToString(msg.Digest), msg.NodeID)
}

func commitMessageString(c *pb.SignedCommitMessage, short bool) string {
	msg := c.Message
	if short {
		return fmt.Sprintf("<COMMIT, %d, %d, D, %s>", msg.ViewNumber, msg.SequenceNum, msg.NodeID)
	}
	return fmt.Sprintf("<COMMIT, %d, %d, %s, %s>", msg.ViewNumber, msg.SequenceNum, hex.EncodeToString(msg.Digest), msg.NodeID)
}

func viewChangeMessageString(v *pb.SignedViewChangeMessage, formatted bool, short bool, tabs int64) string {
	msg := v.Message
	checkpointStringSlice := make([]string, 0)
	for _, msg := range msg.CheckpointMessages {
		if short {
			checkpointStringSlice = append(checkpointStringSlice, fmt.Sprintf("C(%d, %s)", msg.Message.SequenceNum, msg.Message.NodeID))
		} else {
			checkpointStringSlice = append(checkpointStringSlice, checkpointMessageString(msg, short))
		}
	}
	checkpointString := "{" + strings.Join(checkpointStringSlice, ", ") + "}"
	if formatted {
		tabsString := strings.Repeat("\t", int(tabs))
		checkpointString = "\n" + tabsString + "{\t" + strings.Join(checkpointStringSlice, ",\n"+tabsString+"\t") + "\n" + tabsString + "}"
		if len(checkpointStringSlice) == 0 {
			checkpointString = "{}"
		}
	}

	prepareSetStringSlice := make([]string, 0)
	for _, prepareProof := range msg.PreparedSet {
		if short {
			prepareSetStringSlice = append(prepareSetStringSlice, fmt.Sprintf("P%d", prepareProof.SignedPrePrepareMessage.Message.SequenceNum))
		} else {
			prepareSetStringSlice = append(prepareSetStringSlice, prepareProofString(prepareProof, short))
		}
	}
	prepareSetString := "{" + strings.Join(prepareSetStringSlice, ", ") + "}"
	if formatted {
		tabsString := strings.Repeat("\t", int(tabs))
		prepareSetString = "\n" + tabsString + "{\n" + tabsString + "\t" + strings.Join(prepareSetStringSlice, ",\n"+tabsString+"\t") + "\n" + tabsString + "}"
		if len(prepareSetStringSlice) == 0 {
			prepareSetString = "{}"
		}
	}

	return fmt.Sprintf("<VIEW-CHANGE, %d, %d, %s, %s, %s>", msg.ViewNumber, msg.SequenceNum, checkpointString, prepareSetString, msg.NodeID)
}

func prepareProofString(p *pb.PrepareProof, short bool) string {
	return fmt.Sprintf("(%s, %s)", prePrepareMessageString(p.SignedPrePrepareMessage, short), prepareMessageString(p.SignedPrepareMessage, short))
}

func newViewMessageString(v *pb.SignedNewViewMessage, formatted bool, short bool) string {
	msg := v.Message
	viewChangeStringSlice := make([]string, 0)
	for _, signedViewChangeMessage := range msg.SignedViewChangeMessages {
		if short {
			viewChangeStringSlice = append(viewChangeStringSlice, fmt.Sprintf("VC(%d, %s)", signedViewChangeMessage.Message.SequenceNum, signedViewChangeMessage.Message.NodeID))
		} else {
			viewChangeStringSlice = append(viewChangeStringSlice, viewChangeMessageString(signedViewChangeMessage, formatted, false, 1))
		}
	}
	viewChangeString := "{" + strings.Join(viewChangeStringSlice, ", ") + "}"
	if formatted {
		viewChangeString = "\n{\t" + strings.Join(viewChangeStringSlice, ",\n\t") + "\n}"
		if len(viewChangeStringSlice) == 0 {
			viewChangeString = "{}"
		}
	}

	prePrepareStringSlice := make([]string, 0)
	for _, signedPrePrepareMessage := range msg.SignedPrePrepareMessages {
		if short {
			prePrepareStringSlice = append(prePrepareStringSlice, fmt.Sprintf("PP%d", signedPrePrepareMessage.Message.SequenceNum))
		} else {
			prePrepareStringSlice = append(prePrepareStringSlice, prePrepareMessageString(signedPrePrepareMessage, short))
		}
	}
	prePrepareMessagesString := "{" + strings.Join(prePrepareStringSlice, ", ") + "}"
	if formatted {
		prePrepareMessagesString = "\n{\t" + strings.Join(prePrepareStringSlice, ",\n\t") + "\n}"
		if len(prePrepareStringSlice) == 0 {
			prePrepareMessagesString = "{}"
		}
	}
	return fmt.Sprintf("<NEW-VIEW, %d, %s, %s>", msg.ViewNumber, viewChangeString, prePrepareMessagesString)
}

func checkpointMessageString(c *pb.SignedCheckpointMessage, short bool) string {
	msg := c.Message
	if short {
		return fmt.Sprintf("<CHECKPOINT, %d, %s, D>", msg.SequenceNum, msg.NodeID)
	}
	return fmt.Sprintf("<CHECKPOINT, %d, %s, %s>", msg.SequenceNum, hex.EncodeToString(msg.Digest), msg.NodeID)
}

func transactionRequestString(t *pb.SignedTransactionRequest) string {
	if t == nil {
		return "nil"
	}
	msg := t.Request
	return fmt.Sprintf("<REQUEST, %s, %d, %s>", transactionString(msg.Transaction), msg.Timestamp, msg.Sender)
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

func transactionResponseString(r *pb.SignedTransactionResponse) string {
	msg := r.Message
	return fmt.Sprintf("<REPLY, %d, %d, %s, %s, %d>", msg.ViewNumber, msg.Timestamp, msg.Sender, msg.NodeID, msg.Result)
}

func getRequestMessageString(g *pb.GetRequestMessage) string {
	return fmt.Sprintf("<GETREQUEST, %s, %s>", hex.EncodeToString(g.Digest), g.NodeID)
}

func getCheckpointMessageString(g *pb.GetCheckpointMessage) string {
	return fmt.Sprintf("<GETCHECKPOINT, %d, %s>", g.SequenceNum, g.NodeID)
}

func checkpointString(c *pb.Checkpoint) string {
	return fmt.Sprintf("<%s, %v>", hex.EncodeToString(c.Digest), c.Snapshot)
}
