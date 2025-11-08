package linearpbft

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// LeaderTransactionRequestHandler handles the transaction request for the leader
func (h *ProtocolHandler) LeaderTransactionRequestHandler(signedRequest *pb.SignedTransactionRequest) error {
	// request := signedRequest.Request

	// Get or assign sequence number
	sequenceNum, created := h.state.StateLog.AssignSequenceNumberAndCreateRecord(h.state.GetViewNumber(), crypto.Digest(signedRequest))

	// Ignore if already preprepared in current view
	if !created { //&& sequenceNum != 0 && h.state.StateLog.IsPrePrepared(sequenceNum) && h.state.StateLog.GetViewNumber(sequenceNum) == h.state.GetViewNumber() {
		log.Infof("Ignored: %s; already preprepared in current view", utils.LoggingString(signedRequest))
		return nil
	}

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

	// Byzantine node behavior: sign attack
	if h.byzantineConfig.Byzantine && h.byzantineConfig.SignAttack {
		signedPreprepare.Signature = []byte("invalid signature")
	}

	// Preprepare the transaction
	status := h.state.StateLog.AddPrePrepareMessage(sequenceNum, signedPreprepare)
	log.Infof("v: %d s: %d status: %s req: %s", preprepare.ViewNumber, preprepare.SequenceNum, status, utils.LoggingString(signedRequest.Request))

	h.preprepareToRouteCh <- signedPreprepare

	return nil
}

// LeaderPrepareMessageHandler handles the prepare message for the leader
func (h *ProtocolHandler) LeaderPrepareMessageHandler(signedPrepareMessages []*pb.SignedPrepareMessage) error {
	sequenceNum := signedPrepareMessages[0].Message.SequenceNum
	digest := signedPrepareMessages[0].Message.Digest
	// h.state.StateLog.CreateRecordIfNotExists(h.state.GetViewNumber(), sequenceNum, signedPrepareMessages[0].Message.Digest)

	// Aggregate signatures
	signatureMap := make(map[bls.ID][]byte)
	for _, signedPrepareMessage := range signedPrepareMessages {
		signatureMap[utils.NodeIDToBLSMaskID(signedPrepareMessage.Message.NodeID)] = signedPrepareMessage.Signature
	}
	signature := crypto.RecoverSignature(signatureMap)

	// Create collected signed prepare message
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  h.state.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      digest,
		NodeID:      h.id,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: signature,
	}

	// Add prepare message to log record
	// request := h.state.TransactionMap.Get(signedPrepareMessage.Message.Digest).Request/
	log.Infof("Logging prepare message: %s", utils.LoggingString(prepareMessage))
	status := h.state.StateLog.AddPrepareMessages(sequenceNum, signedPrepareMessage)
	log.Infof("v: %d s: %d status: %s", prepareMessage.ViewNumber, prepareMessage.SequenceNum, status)

	// Byzantine node behavior: crash attack
	// if n.Byzantine && n.CrashAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
	// 	record.MaliciousUpdateLogState()
	// }

	h.prepareToRouteCh <- signedPrepareMessage

	return nil
}

// LeaderCommitMessageHandler handles the commit message for the leader
func (h *ProtocolHandler) LeaderCommitMessageHandler(signedCommitMessages []*pb.SignedCommitMessage) error {
	sequenceNum := signedCommitMessages[0].Message.SequenceNum
	digest := signedCommitMessages[0].Message.Digest
	// h.state.StateLog.CreateRecordIfNotExists(h.state.GetViewNumber(), sequenceNum, signedCommitMessages[0].Message.Digest)

	// Aggregate signatures
	signatureMap := make(map[bls.ID][]byte)
	for _, signedCommitMessage := range signedCommitMessages {
		signatureMap[utils.NodeIDToBLSMaskID(signedCommitMessage.Message.NodeID)] = signedCommitMessage.Signature
	}
	signature := crypto.RecoverSignature(signatureMap)

	// Create collected signed commit message
	commitMessage := &pb.CommitMessage{
		ViewNumber:  h.state.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      digest,
		NodeID:      h.id,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: signature,
	}

	// Add commit message to log record
	// request := h.state.TransactionMap.Get(signedCommitMessage.Message.Digest).Request
	log.Infof("Logging commit message: %s", utils.LoggingString(commitMessage))
	status := h.state.StateLog.AddCommitMessages(sequenceNum, signedCommitMessage)
	log.Infof("v: %d s: %d status: %s", commitMessage.ViewNumber, commitMessage.SequenceNum, status)

	h.commitToRouteCh <- signedCommitMessage

	return nil
}
