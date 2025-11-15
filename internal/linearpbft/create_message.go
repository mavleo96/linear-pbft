package linearpbft

import (
	"github.com/mavleo96/pbft/internal/crypto"
	"github.com/mavleo96/pbft/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) CreateViewChangeMessage(viewNumber int64) *pb.SignedViewChangeMessage {
	lowerSequenceNum := n.config.GetLowWaterMark()

	// Get prepared message proof set
	preparedSet := n.state.StateLog.GetPrepareProof()

	// Get check point messages
	signedCheckpointMessages := n.executor.checkpointer.GetMessages(n.config.GetLowWaterMark())

	// Create signed view change message
	viewChangeMessage := &pb.ViewChangeMessage{
		ViewNumber:         viewNumber,
		SequenceNum:        lowerSequenceNum,
		CheckpointMessages: signedCheckpointMessages,
		PreparedSet:        preparedSet,
		NodeID:             n.ID,
	}
	signedViewChangeMessage := &pb.SignedViewChangeMessage{
		Message:   viewChangeMessage,
		Signature: crypto.Sign(viewChangeMessage, n.handler.privateKey1),
	}
	// Byzantine node behavior: sign attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
		signedViewChangeMessage.Signature = []byte("invalid signature")
	}
	return signedViewChangeMessage
}

func (n *LinearPBFTNode) CreateNewViewMessage(viewNumber int64) *pb.SignedNewViewMessage {
	// Get view change messages from view change message log
	signedViewChangeMessages := n.viewchanger.GetViewChangeMessages(viewNumber)

	// Determine lower watermark sequence number and max sequence number
	lowerWatermark := int64(0)
	maxSequenceNum := int64(0)
	for _, signedViewChangeMessage := range signedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		preparedSet := viewChangeMessage.PreparedSet

		// Update lower watermark sequence number from view change messages sequence numbers
		if viewChangeMessage.SequenceNum > lowerWatermark {
			lowerWatermark = viewChangeMessage.SequenceNum
		}

		// Update max sequence number from preprepare messages sequence numbers
		for _, prepareProof := range preparedSet {
			prepareMessage := prepareProof.SignedPrepareMessage.Message
			if prepareMessage.SequenceNum > maxSequenceNum {
				maxSequenceNum = prepareMessage.SequenceNum
			}
		}
	}
	log.Infof("Creating new view message for view number %d with lower watermark sequence number: %d, max sequence number: %d", viewNumber, lowerWatermark, maxSequenceNum)

	// Aggregate preprepare messages from view change messages and create preprepare message with current view number
	signedPrePrepareMessagesMap := make(map[int64]*pb.SignedPrePrepareMessage)
	for _, signedViewChangeMessage := range signedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		preparedSet := viewChangeMessage.PreparedSet

		// Loop thorugh prepare proofs and add to signed preprepare messages if not already added
		for _, prepareProof := range preparedSet {
			prePrepareMessage := prepareProof.SignedPrePrepareMessage.Message
			sequenceNum := prePrepareMessage.SequenceNum

			// Ignore if sequence number is already in map or below lower watermark
			if _, ok := signedPrePrepareMessagesMap[sequenceNum]; ok || sequenceNum < lowerWatermark {
				continue
			}

			// Create signed preprepare message
			newPrePrepareMessage := &pb.PrePrepareMessage{
				ViewNumber:  viewNumber,
				SequenceNum: sequenceNum,
				Digest:      prePrepareMessage.Digest,
			}
			signedPrePrepareMessages := &pb.SignedPrePrepareMessage{
				Message:   newPrePrepareMessage,
				Signature: crypto.Sign(newPrePrepareMessage, n.handler.privateKey1),
			}
			// Byzantine node behavior: sign attack
			if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
				signedPrePrepareMessages.Signature = []byte("invalid signature")
			}

			signedPrePrepareMessagesMap[sequenceNum] = signedPrePrepareMessages
		}
	}

	// Fill in missing preprepare messages with no op preprepare messages
	signedPrePrepareMessages := make([]*pb.SignedPrePrepareMessage, 0)
	for sequenceNum := lowerWatermark + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		signedPrePrepareMessage, ok := signedPrePrepareMessagesMap[sequenceNum]
		if !ok {
			NoOpPrePrepareMessage := &pb.PrePrepareMessage{
				ViewNumber:  viewNumber,
				SequenceNum: sequenceNum,
				Digest:      crypto.Digest(NoOpTransactionRequest),
			}
			SignedNoOpPrePrepareMessage := &pb.SignedPrePrepareMessage{
				Message:   NoOpPrePrepareMessage,
				Signature: crypto.Sign(NoOpPrePrepareMessage, n.handler.privateKey1),
			}

			// Byzantine node behavior: sign attack
			if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
				SignedNoOpPrePrepareMessage.Signature = []byte("invalid signature")
			}

			signedPrePrepareMessages = append(signedPrePrepareMessages, SignedNoOpPrePrepareMessage)
		} else {
			signedPrePrepareMessages = append(signedPrePrepareMessages, signedPrePrepareMessage)
		}
	}

	// Create signed new view message
	newViewMessage := &pb.NewViewMessage{
		ViewNumber:               viewNumber,
		SignedViewChangeMessages: signedViewChangeMessages,
		SignedPrePrepareMessages: signedPrePrepareMessages,
	}
	signedNewViewMessage := &pb.SignedNewViewMessage{
		Message:   newViewMessage,
		Signature: crypto.Sign(newViewMessage, n.handler.privateKey1),
	}

	// Byzantine node behavior: sign attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
		signedNewViewMessage.Signature = []byte("invalid signature")
	}

	return signedNewViewMessage
}

// CreateCheckpointMessage creates a check point message for a given sequence number
func (n *LinearPBFTNode) CreateCheckpointMessage(sequenceNum int64) *pb.SignedCheckpointMessage {
	checkpoint := n.executor.checkpointer.GetCheckpoint(sequenceNum)
	checkpointMessage := &pb.CheckpointMessage{
		SequenceNum: sequenceNum,
		Digest:      checkpoint.Digest,
		NodeID:      n.ID,
	}
	signedCheckpointMessage := &pb.SignedCheckpointMessage{
		Message:   checkpointMessage,
		Signature: crypto.Sign(checkpointMessage, n.handler.privateKey1),
	}

	// Byzantine node behavior: sign attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
		signedCheckpointMessage.Signature = []byte("invalid signature")
	}

	return signedCheckpointMessage
}
