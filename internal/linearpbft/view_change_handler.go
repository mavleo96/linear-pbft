package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// ViewChangeMessageHandler handles the view change message
func (v *ViewChangeManager) ViewChangeMessageHandler(signedViewChangeMessage *pb.SignedViewChangeMessage) {
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber

	// Log the view change message
	log.Infof("Logged: %s", utils.LoggingString(signedViewChangeMessage))
	v.AddViewChangeMessage(signedViewChangeMessage)

	// Send view change message to all nodes if f + 1 view change messages are collected
	if v.state.GetViewChangeViewNumber() < viewNumber && len(v.GetViewChangeMessages(viewNumber)) == int(v.config.F+1) {
		alreadyExpired := v.SafeTimer.Cleanup()
		log.Infof("Signaling view change request channel since f + 1 view change messages are collected and time status was %t: %s", alreadyExpired, utils.LoggingString(signedViewChangeMessage))
		v.viewChangeTriggerCh <- viewNumber
	}

	// If 2f + 1 view change messages are collected and next primary then send new view message
	if len(v.GetViewChangeMessages(viewNumber)) == int(2*v.config.F+1) {
		v.newViewTriggerCh <- viewNumber
	}
}

func (v *ViewChangeManager) BackupNewViewRequestHandler(signedNewViewMessage *pb.SignedNewViewMessage) error {
	newViewMessage := signedNewViewMessage.Message
	viewNumber := newViewMessage.ViewNumber

	// Log the new view message
	log.Infof("Logged: %s", utils.LoggingString(signedNewViewMessage))
	v.AddNewViewMessage(signedNewViewMessage)

	// Update state
	v.state.SetViewNumber(viewNumber)
	v.state.SetViewChangeViewNumber(viewNumber)
	v.state.SetViewChangePhase(false)
	log.Infof("Accepted %s", utils.LoggingString(signedNewViewMessage))
	v.state.ResetForwardedRequestsLog()

	// Determine the lower watermark sequence number from highest sequence number in view change messages
	lowerWatermark := int64(0)
	signedCheckpointMessages := make([]*pb.SignedCheckpointMessage, 0)
	for _, signedViewChangeMessage := range v.GetViewChangeMessages(viewNumber) {
		viewChangeMessage := signedViewChangeMessage.Message
		if viewChangeMessage.SequenceNum > lowerWatermark {
			lowerWatermark = viewChangeMessage.SequenceNum
			signedCheckpointMessages = append(signedCheckpointMessages, viewChangeMessage.CheckpointMessages...)
		}
	}

	// If lower watermark is greater than low water mark then add checkpoint messages to check point log and purge old checkpoints and messages
	if lowerWatermark > v.config.GetLowWaterMark() {
		for _, signedCheckpointMessage := range signedCheckpointMessages {
			v.checkpointer.AddMessage(signedCheckpointMessage.Message.SequenceNum, signedCheckpointMessage.Message.NodeID, signedCheckpointMessage)
		}
		v.checkpointInstallRequestCh <- lowerWatermark
		log.Infof("Signalling install check point channel with lower watermark sequence number: %d", lowerWatermark)
	}

	return nil
}

func (v *ViewChangeManager) LeaderNewViewRequestHandler(signedNewViewMessage *pb.SignedNewViewMessage) error {
	newViewMessage := signedNewViewMessage.Message
	viewNumber := newViewMessage.ViewNumber
	signedPrePrepareMessages := newViewMessage.SignedPrePrepareMessages

	// Log the new view message
	log.Infof("Logged: %s", utils.LoggingString(signedNewViewMessage))
	v.AddNewViewMessage(signedNewViewMessage)

	// Update state
	v.state.SetViewNumber(viewNumber)
	// v.state.SetViewChangeViewNumber(viewNumber)
	v.state.SetViewChangePhase(false) // TODO: maybe not safe before updating the logs
	log.Infof("Accepted %s", utils.LoggingString(signedNewViewMessage))

	// Determine the lower watermark sequence number and digest from view change messages
	lowerWatermark := int64(0)
	signedCheckpointMessages := make([]*pb.SignedCheckpointMessage, 0)
	for _, signedViewChangeMessage := range v.GetViewChangeMessages(viewNumber) {
		viewChangeMessage := signedViewChangeMessage.Message
		if viewChangeMessage.SequenceNum > lowerWatermark {
			lowerWatermark = viewChangeMessage.SequenceNum
			signedCheckpointMessages = append(signedCheckpointMessages, viewChangeMessage.CheckpointMessages...)
		}
	}

	// Install latest stable checkpoint for lower watermark sequence number
	if lowerWatermark > v.config.GetLowWaterMark() {
		for _, signedCheckpointMessage := range signedCheckpointMessages {
			v.checkpointer.AddMessage(signedCheckpointMessage.Message.SequenceNum, signedCheckpointMessage.Message.NodeID, signedCheckpointMessage)
		}
		v.checkpointInstallRequestCh <- lowerWatermark
		log.Infof("Signalling install check point channel with lower watermark sequence number: %d", lowerWatermark)
	}

	// TODO: get missing requests

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
		log.Infof("Logging preprepare message: %s", utils.LoggingString(signedPrePrepareMessage))
		status := v.state.StateLog.AddPrePrepareMessage(sequenceNum, signedPrePrepareMessage)
		if signedRequest != nil && signedRequest.Request != nil {
			log.Infof("v: %d s: %d status: %s req: %s", prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, status, utils.LoggingString(signedRequest))
		} else {
			log.Infof("v: %d s: %d status: %s req: nil", prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, status)
		}
	}

	// Purge log records greater than max sequence number
	for i := maxSequenceNum + 1; i <= v.state.StateLog.MaxSequenceNum(); i++ {
		v.state.StateLog.Delete(i)
	}

	// Return nil
	return nil
}
