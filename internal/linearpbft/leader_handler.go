package linearpbft

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/pb"
)

func (h *ProtocolHandler) LeaderTransactionRequestHandler(signedRequest *pb.SignedTransactionRequest) error {
	// request := signedRequest.Request

	// Get or assign sequence number
	sequenceNum, exists := h.state.StateLog.GetOrAssignSequenceNumber(signedRequest)
	if !exists {
		// Add request to log record
		h.state.StateLog.Set(sequenceNum, CreateLogRecord(h.state.GetViewNumber(), sequenceNum, crypto.Digest(signedRequest)))
	}
	record, _ := h.state.StateLog.Get(sequenceNum)

	// // Add request to transaction map
	// if n.State.TransactionMap.Get(crypto.Digest(signedRequest)) == nil {
	// 	log.Infof("Adding request to transaction map: %s", utils.LoggingString(request))
	// 	n.State.TransactionMap.Set(crypto.Digest(signedRequest), signedRequest)
	// }

	// Create signed preprepare message
	preprepare := &pb.PrePrepareMessage{
		ViewNumber:  h.state.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      crypto.Digest(signedRequest),
	}
	signedPreprepare := &pb.SignedPrePrepareMessage{
		Message:   preprepare,
		Signature: crypto.Sign(preprepare, h.privateKey1),
		Request:   signedRequest,
	}

	// // Byzantine node behavior: sign attack
	// if n.Byzantine && n.SignAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
	// 	signedPreprepare.Signature = []byte("invalid signature")
	// }

	// Preprepare the transaction
	record.AddPrePrepareMessage(signedPreprepare)

	h.preprepareCh <- signedPreprepare

	return nil
}

func (h *ProtocolHandler) LeaderPrepareMessageHandler(signedPrepareMessages []*pb.SignedPrepareMessage) error {
	sequenceNum := signedPrepareMessages[0].Message.SequenceNum
	record, _ := h.state.StateLog.Get(sequenceNum)

	// Aggregate signatures
	signatureMap := make(map[bls.ID][]byte)
	for _, signedPrepareMessage := range signedPrepareMessages {
		signatureMap[crypto.NodeIDToBLSMaskID(signedPrepareMessage.Message.NodeID)] = signedPrepareMessage.Signature
	}
	signature := crypto.RecoverSignature(signatureMap)

	// Create collected signed prepare message
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  h.state.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		NodeID:      h.id,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: signature,
	}

	// Add prepare message to log record
	record.AddPrepareMessages(signedPrepareMessage)

	// Byzantine node behavior: crash attack
	// if n.Byzantine && n.CrashAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
	// 	record.MaliciousUpdateLogState()
	// }

	h.prepareCh <- signedPrepareMessage

	return nil
}

func (h *ProtocolHandler) LeaderCommitMessageHandler(signedCommitMessages []*pb.SignedCommitMessage) error {
	sequenceNum := signedCommitMessages[0].Message.SequenceNum
	record, _ := h.state.StateLog.Get(sequenceNum)

	// Aggregate signatures
	signatureMap := make(map[bls.ID][]byte)
	for _, signedCommitMessage := range signedCommitMessages {
		signatureMap[crypto.NodeIDToBLSMaskID(signedCommitMessage.Message.NodeID)] = signedCommitMessage.Signature
	}
	signature := crypto.RecoverSignature(signatureMap)

	// Create collected signed commit message
	commitMessage := &pb.CommitMessage{
		ViewNumber:  h.state.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		NodeID:      h.id,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: signature,
	}

	// Add commit message to log record
	record.AddCommitMessages(signedCommitMessage)

	h.commitCh <- signedCommitMessage

	return nil
}
