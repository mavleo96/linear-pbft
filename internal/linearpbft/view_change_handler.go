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
	if v.state.GetViewChangeViewNumber() < viewNumber && len(v.log[viewNumber]) == int(v.f+1) {
		alreadyExpired := v.SafeTimer.Cleanup()
		if !alreadyExpired || utils.ViewNumberToPrimaryID(viewNumber, v.n) != v.id {
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
	if len(v.log[viewNumber]) == int(2*v.f+1) {
		if utils.ViewNumberToPrimaryID(viewNumber, v.n) == v.id {
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

func (n *LinearPBFTNode) CreateViewChangeMessage(viewNumber int64) *pb.SignedViewChangeMessage {
	maxSequenceNum := n.State.StateLog.MaxSequenceNum()
	lowerSequenceNum := n.config.lowWaterMark

	// Get prepared message proof set
	preparedSet := make([]*pb.PrepareProof, 0)
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		record, exists := n.State.StateLog.Get(sequenceNum)
		if !exists {
			continue
		}
		if record == nil || !record.IsPrepared() {
			continue
		}
		prepareProof := record.GetPrepareProof()
		preparedSet = append(preparedSet, prepareProof)
	}

	// Get check point messages
	stableCheckpointSequenceNum := n.CheckPointLog.GetStableCheckpointSequenceNum()
	signedCheckPointMessages := n.CheckPointLog.GetMessages(stableCheckpointSequenceNum)

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
