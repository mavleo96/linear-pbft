package linearpbft

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
)

// LeaderTransactionRequestHandler handles the transaction request for the leader
func (h *ProtocolHandler) LeaderTransactionRequestHandler(signedRequest *pb.SignedTransactionRequest) error {
	// request := signedRequest.Request

	// Get or assign sequence number
	sequenceNum, created := h.state.StateLog.AssignSequenceNumberAndCreateRecord(h.state.GetViewNumber(), crypto.Digest(signedRequest))

	// Ignore if already preprepared in current view
	if !created {
		log.Infof("Ignored: %s; already preprepared in current view", utils.LoggingString(signedRequest))
		return nil
	}

	// Add request to transaction map
	log.Infof("Adding request to transaction map: %s", utils.LoggingString(signedRequest))
	h.state.TransactionMap.Set(crypto.Digest(signedRequest), signedRequest)

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
	log.Infof("v: %d s: %d status: %s req: %s", preprepare.ViewNumber, preprepare.SequenceNum, status, utils.LoggingString(signedRequest))

	h.preprepareToRouteCh <- signedPreprepare

	// Byzantine node behavior: equivocation attack
	if h.byzantineConfig.Byzantine && h.byzantineConfig.EquivocationAttack {
		// Create equivocation preprepare message
		equivocationPreprepare := &pb.PrePrepareMessage{
			ViewNumber:  h.state.GetViewNumber(),
			SequenceNum: sequenceNum + 1,
			Digest:      crypto.Digest(signedRequest),
		}
		signedEquivocationPreprepare := &pb.SignedPrePrepareMessage{
			Message:   equivocationPreprepare,
			Signature: crypto.Sign(equivocationPreprepare, h.privateKey1),
			Request:   signedRequest,
		}

		// Byzantine node behavior: sign attack
		if h.byzantineConfig.Byzantine && h.byzantineConfig.SignAttack {
			signedEquivocationPreprepare.Signature = []byte("invalid signature")
		}

		// Preprepare the transaction
		status := h.state.StateLog.AddPrePrepareMessage(sequenceNum+1, signedEquivocationPreprepare)
		log.Infof("v: %d s: %d status: %s req: %s", equivocationPreprepare.ViewNumber, equivocationPreprepare.SequenceNum, status, utils.LoggingString(signedRequest))

		// Route equivocation preprepare message to backup nodes
		h.byzantineConfig.GetEquivocationPrePrepareToRouteChannel() <- signedEquivocationPreprepare
	}

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
	signatureMap2 := make(map[bls.ID][]byte)
	for _, signedPrepareMessage := range signedPrepareMessages {
		signatureMap2[utils.NodeIDToBLSMaskID(signedPrepareMessage.Message.NodeID)] = signedPrepareMessage.Signature2
	}
	signature2 := crypto.RecoverSignature(signatureMap2)

	// Create collected signed prepare message
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  h.state.GetViewNumber(),
		SequenceNum: sequenceNum,
		Digest:      digest,
		NodeID:      "agg",
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:    prepareMessage,
		Signature:  signature,
		Signature2: signature2,
	}

	// Sfbt verified if all prepare messages are received
	sbftVerified := false
	if len(signedPrepareMessages) == int(h.config.N) {
		sbftVerified = true
	}

	// Add prepare message to log record
	// request := h.state.TransactionMap.Get(signedPrepareMessage.Message.Digest).Request/
	log.Infof("Logging prepare message: %s sbftVerified: %t", utils.LoggingString(signedPrepareMessage), sbftVerified)
	status := h.state.StateLog.AddPrepareMessages(sequenceNum, signedPrepareMessage, sbftVerified)
	log.Infof("v: %d s: %d status: %s", prepareMessage.ViewNumber, prepareMessage.SequenceNum, status)

	// Byzantine node behavior: crash attack
	if h.byzantineConfig.Byzantine && h.byzantineConfig.CrashAttack {
		return nil
	}

	if sbftVerified {
		log.Infof("Routing sbft prepare message to all nodes: %s", utils.LoggingString(signedPrepareMessage))
		h.sbftPrepareToRouteCh <- signedPrepareMessage
	} else {
		h.prepareToRouteCh <- signedPrepareMessage
	}

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
		NodeID:      "agg",
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: signature,
	}

	// Add commit message to log record
	log.Infof("Logging commit message: %s", utils.LoggingString(signedCommitMessage))
	status := h.state.StateLog.AddCommitMessages(sequenceNum, signedCommitMessage)
	log.Infof("v: %d s: %d status: %s", commitMessage.ViewNumber, commitMessage.SequenceNum, status)

	h.commitToRouteCh <- signedCommitMessage

	return nil
}
