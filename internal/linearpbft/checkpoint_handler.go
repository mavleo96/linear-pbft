package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// CheckPointMessageHandler handles incoming check point messages and routes it to the check point manager
func (c *CheckPointManager) CheckPointMessageHandler(signedCheckPointMessage *pb.SignedCheckPointMessage) {
	checkPointMessage := signedCheckPointMessage.Message
	sequenceNum := checkPointMessage.SequenceNum
	nodeID := checkPointMessage.NodeID

	// Add check point message to check point log if higher than low water mark
	if sequenceNum < c.config.lowWaterMark {
		log.Warnf("Check point message for sequence number %d is lower than low water mark", sequenceNum)
		return
	}
	log.Infof("Logged: %s", utils.LoggingString(checkPointMessage))
	c.AddMessage(sequenceNum, nodeID, signedCheckPointMessage)

	// Signal the checkpoint routine if 2f + 1 or more check point messages are collected and self's check point message is included
	hasSelfCheckPointMessage := false
	for _, checkPointMessage := range c.GetMessages(sequenceNum) {
		if checkPointMessage.Message.NodeID == nodeID {
			hasSelfCheckPointMessage = true
			break
		}
	}
	if len(c.GetMessages(sequenceNum)) >= int(2*c.f+1) && hasSelfCheckPointMessage {
		log.Infof("Received 2f + 1 check point messages for sequence number %d", sequenceNum)
		c.checkPointRequestCh <- sequenceNum
	}
}

// CreateCheckPointMessage creates a check point message for a given sequence number
func (n *LinearPBFTNode) CreateCheckPointMessage(sequenceNum int64) *pb.SignedCheckPointMessage {
	digest := n.CheckPointManager.GetDigest(sequenceNum)
	checkPointMessage := &pb.CheckPointMessage{
		SequenceNum: sequenceNum,
		Digest:      digest,
		NodeID:      n.ID,
	}
	signedCheckPointMessage := &pb.SignedCheckPointMessage{
		Message:   checkPointMessage,
		Signature: crypto.Sign(checkPointMessage, n.Handler.privateKey1),
	}
	return signedCheckPointMessage
}
