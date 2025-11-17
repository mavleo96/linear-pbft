package linearpbft

import (
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
)

// CheckpointMessageHandler handles incoming check point messages and routes it to the check point manager
func (c *CheckpointManager) CheckpointMessageHandler(signedCheckpointMessage *pb.SignedCheckpointMessage) {
	checkpointMessage := signedCheckpointMessage.Message
	sequenceNum := checkpointMessage.SequenceNum
	nodeID := checkpointMessage.NodeID

	// Add check point message to check point log if higher or equal to low water mark
	if sequenceNum < c.config.GetLowWaterMark() {
		log.Warnf("Check point message for sequence number %d is below low water mark (%d)", sequenceNum, c.config.GetLowWaterMark())
		return
	}
	log.Infof("Logged: %s", utils.LoggingString(signedCheckpointMessage))
	c.AddMessage(sequenceNum, nodeID, signedCheckpointMessage)

	// Signal the checkpoint routine if 2f + 1 or more check point messages are collected and self's check point message is included
	hasSelfCheckpointMessage := false
	for _, checkpointMessage := range c.GetMessages(sequenceNum) {
		if checkpointMessage.Message.NodeID == c.id {
			hasSelfCheckpointMessage = true
			break
		}
	}
	if len(c.GetMessages(sequenceNum)) >= int(2*c.config.F+1) && hasSelfCheckpointMessage && c.config.SequenceNumberInRange(sequenceNum) {
		log.Infof("Received 2f + 1 check point messages for sequence number %d", sequenceNum)
		c.checkpointPurgeCh <- sequenceNum
	}
}
