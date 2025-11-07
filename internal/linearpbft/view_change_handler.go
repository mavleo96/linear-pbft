package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// ViewChangeRequestHandler handles the view change request
func (v *ViewChangeManager) ViewChangeRequestHandler(signedViewChangeMessage *pb.SignedViewChangeMessage) {
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber

	// Log the view change message
	log.Infof("Logged: %s", utils.LoggingString(viewChangeMessage))
	v.AddViewChangeMessage(signedViewChangeMessage)

	// Send view change message to all nodes if f + 1 view change messages are collected
	if v.state.GetViewChangeViewNumber() < viewNumber && len(v.viewChangeLog[viewNumber]) == int(v.config.F+1) {
		alreadyExpired := v.SafeTimer.Cleanup()
		if !alreadyExpired || utils.ViewNumberToPrimaryID(viewNumber, v.config.N) != v.id {
			// log.Infof("Sending view change message to all nodes since f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			// go v.SendViewChange(viewNumber)
			// TODO: signal view change request channel
			log.Infof("Signaling view change request channel since f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			v.viewChangeRequestCh <- true
		} else {
			log.Infof("View change timer already expired at v %d vc %d", v.state.GetViewNumber(), v.state.GetViewChangeViewNumber())
		}
	}

	// If 2f + 1 view change messages are collected and next primary then send new view message
	if len(v.viewChangeLog[viewNumber]) == int(2*v.config.F+1) {
		if utils.ViewNumberToPrimaryID(viewNumber, v.config.N) == v.id {
			// // Byzantine node behavior: crash attack
			// if v.byzantine && v.crashAttack {
			// 	// log.Infof("Node %s is Byzantine and is performing crash attack", v.id)
			// 	return
			// }
			// TODO: signal new view request channel
			log.Infof("Signaling new view request channel since 2f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			v.newViewRequestCh <- true
		} else {
			// else start view change timer
			log.Infof("Starting view change timer since 2f + 1 view change messages are collected but not next primary: %s", utils.LoggingString(viewChangeMessage))
			v.SafeTimer.StartViewTimerIfNotRunning()
		}
	}

}

func (v *ViewChangeManager) BackupNewViewRequestHandler(signedNewViewMessage *pb.SignedNewViewMessage) error {
	newViewMessage := signedNewViewMessage.Message
	viewNumber := newViewMessage.ViewNumber

	// Log the new view message
	log.Infof("Logged: %s", utils.LoggingString(newViewMessage))
	v.AddNewViewMessage(signedNewViewMessage)

	// Update state
	v.state.SetViewNumber(viewNumber)
	v.state.SetViewChangeViewNumber(viewNumber)
	v.state.SetViewChangePhase(false)
	log.Infof("Accepted %s", utils.LoggingString(newViewMessage))

	// // Byzantine node behavior: dark attack
	// if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, primaryID) {
	// 	// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, primaryID)
	// 	return status.Errorf(codes.Unavailable, "node not alive")
	// }

	// TODO: Install latest stable checkpoint
	return nil
}

func (v *ViewChangeManager) LeaderNewViewRequestHandler(signedNewViewMessage *pb.SignedNewViewMessage) error {
	newViewMessage := signedNewViewMessage.Message
	viewNumber := newViewMessage.ViewNumber
	signedPrePrepareMessages := newViewMessage.SignedPrePrepareMessages

	// Log the new view message
	log.Infof("Logged: %s", utils.LoggingString(newViewMessage))
	v.AddNewViewMessage(signedNewViewMessage)

	// Update state
	v.state.SetViewNumber(viewNumber)
	// v.state.SetViewChangeViewNumber(viewNumber)
	v.state.SetViewChangePhase(false) // TODO: maybe not safe before updating the logs
	log.Infof("Accepted %s", utils.LoggingString(newViewMessage))

	// TODO: Install latest stable checkpoint for lower watermark sequence number

	// Primary needs to first preprepare the requests in its own log record
	maxSequenceNum := int64(0)
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		sequenceNum := prePrepareMessage.SequenceNum

		// Update max sequence number
		if sequenceNum > maxSequenceNum {
			maxSequenceNum = sequenceNum
		}

		// // If request is not in the transaction map then send a get request to all nodes
		signedRequest := v.state.TransactionMap.Get(prePrepareMessage.Digest)
		// if signedRequest == nil {
		// 	response, err := v.SendGetRequest(prePrepareMessage.Digest)
		// }

		// Update state log
		v.state.StateLog.CreateRecordIfNotExists(viewNumber, sequenceNum, prePrepareMessage.Digest)
		log.Infof("Logging preprepare message: %s", utils.LoggingString(prePrepareMessage))
		status := v.state.StateLog.AddPrePrepareMessage(sequenceNum, signedPrePrepareMessage)
		log.Infof("v: %d s: %d status: %s req: %s", prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, status, utils.LoggingString(signedRequest.Request))
	}

	// Purge log records greater than max sequence number
	for i := maxSequenceNum + 1; i <= v.state.StateLog.MaxSequenceNum(); i++ {
		v.state.StateLog.Delete(i)
	}

	// Return nil
	return nil
}

func (n *LinearPBFTNode) CreateViewChangeMessage(viewNumber int64) *pb.SignedViewChangeMessage {
	lowerSequenceNum := n.config.LowWaterMark

	// Get prepared message proof set
	preparedSet := n.State.StateLog.GetPrepareProof()

	// Get check point messages
	signedCheckPointMessages := n.CheckPointManager.GetMessages(n.config.LowWaterMark)

	// Create signed view change message
	viewChangeMessage := &pb.ViewChangeMessage{
		ViewNumber:         viewNumber,
		SequenceNum:        lowerSequenceNum,
		CheckPointMessages: signedCheckPointMessages,
		PreparedSet:        preparedSet,
		NodeID:             n.ID,
	}
	signedViewChangeMessage := &pb.SignedViewChangeMessage{
		Message:   viewChangeMessage,
		Signature: crypto.Sign(viewChangeMessage, n.Handler.privateKey1),
	}
	// // Byzantine node behavior: sign attack
	// if n.Byzantine && n.SignAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
	// 	signedViewChangeMessage.Signature = []byte("invalid signature")
	// }
	return signedViewChangeMessage
}

func (n *LinearPBFTNode) CreateNewViewMessage(viewNumber int64) *pb.SignedNewViewMessage {
	// Get view change messages from view change message log
	signedViewChangeMessages := n.ViewChangeManager.GetViewChangeMessages(viewNumber)

	// Determine lower watermark sequence number and max sequence number
	lowerWatermark := int64(0)
	maxSequenceNum := int64(0)
	for _, signedViewChangeMessage := range signedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		preparedSet := viewChangeMessage.PreparedSet

		// Update lower watermark sequence number from view change messages sequence numbers
		if viewChangeMessage.SequenceNum < lowerWatermark {
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
				Signature: crypto.Sign(newPrePrepareMessage, n.Handler.privateKey1),
			}
			// // Byzantine node behavior: sign attack
			// if n.Byzantine && n.SignAttack {
			// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
			// 	signedPrePrepareMessagesMap[sequenceNum].Signature = []byte("invalid signature")
			// }
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
				Signature: crypto.Sign(NoOpPrePrepareMessage, n.Handler.privateKey1),
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
		Signature: crypto.Sign(newViewMessage, n.Handler.privateKey1),
	}
	// // Byzantine node behavior: sign attack
	// if n.Byzantine && n.SignAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
	// 	signedNewViewMessage.Signature = []byte("invalid signature")
	// }
	return signedNewViewMessage
}
