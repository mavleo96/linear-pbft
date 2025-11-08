package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// CollectPrepareMessages collects prepare messages from all nodes and sends to handler
func (n *LinearPBFTNode) CollectPrepareMessages(responseCh <-chan *pb.SignedPrepareMessage) {
	signedPrepareMessageMap := make(map[int64]map[string]*pb.SignedPrepareMessage) // sequence number -> node ID -> signed prepare message

	// Keep looping and send to handler once we have 2f + 1 prepare messages for a sequence number
	for {
		// Keep collecting until the channel is closed
		signedPrepareMessage, ok := <-responseCh
		if !ok {
			break
		}
		prepareMessage := signedPrepareMessage.Message
		sequenceNum := prepareMessage.SequenceNum
		if _, ok := signedPrepareMessageMap[sequenceNum]; !ok {
			signedPrepareMessageMap[sequenceNum] = make(map[string]*pb.SignedPrepareMessage)
		}

		// Log the prepare message in collection map
		signedPrepareMessageMap[sequenceNum][prepareMessage.NodeID] = signedPrepareMessage

		// If we have 2f prepare messages for a sequence number, send to handler
		if len(signedPrepareMessageMap[sequenceNum]) == int(2*n.config.F) {
			log.Infof("New view prepare collector: Collected 2f prepare messages for sequence number %d", sequenceNum)
			// Convert map to slice of signed prepare messages and add self's prepare message to support TSS
			signedPrepareMessages := utils.Values(signedPrepareMessageMap[sequenceNum])
			prepareMessage := &pb.PrepareMessage{
				ViewNumber:  signedPrepareMessage.Message.ViewNumber,
				SequenceNum: sequenceNum,
				Digest:      signedPrepareMessage.Message.Digest,
				NodeID:      n.ID,
			}
			signedPrepareMessage := &pb.SignedPrepareMessage{
				Message:   prepareMessage,
				Signature: crypto.Sign(prepareMessage, n.handler.privateKey1),
			}
			signedPrepareMessages = append(signedPrepareMessages, signedPrepareMessage)
			go n.handler.LeaderPrepareMessageHandler(signedPrepareMessages)
		}
	}
}

// CollectCommitMessages collects commit messages from all nodes and sends to handler
func (n *LinearPBFTNode) CollectCommitMessages(responseCh <-chan *pb.SignedCommitMessage) {
	signedCommitMessageMap := make(map[int64]map[string]*pb.SignedCommitMessage) // sequence number -> node ID -> signed commit message

	// Keep looping and send to handler once we have 2f + 1 commit messages for a sequence number
	for {
		// Keep collecting until the channel is closed
		signedCommitMessage, ok := <-responseCh
		if !ok {
			break
		}
		commitMessage := signedCommitMessage.Message
		sequenceNum := commitMessage.SequenceNum
		if _, ok := signedCommitMessageMap[sequenceNum]; !ok {
			signedCommitMessageMap[sequenceNum] = make(map[string]*pb.SignedCommitMessage)
			// Log self's commit message
			commitMessage := &pb.CommitMessage{
				ViewNumber:  commitMessage.ViewNumber,
				SequenceNum: sequenceNum,
				Digest:      commitMessage.Digest,
				NodeID:      n.ID,
			}
			signedCommitMessage := &pb.SignedCommitMessage{
				Message:   commitMessage,
				Signature: crypto.Sign(commitMessage, n.handler.privateKey1),
			}
			signedCommitMessageMap[sequenceNum][n.ID] = signedCommitMessage
		}

		// Log the commit message in collection map
		signedCommitMessageMap[sequenceNum][commitMessage.NodeID] = signedCommitMessage

		// If we have 2f + 1 commit messages for a sequence number, send to handler
		if len(signedCommitMessageMap[sequenceNum]) == int(2*n.config.F+1) {
			log.Infof("New view commit collector: Collected 2f + 1 commit messages for sequence number %d", sequenceNum)
			// Convert map to slice of signed commit messages
			signedCommitMessages := utils.Values(signedCommitMessageMap[sequenceNum])
			go n.handler.LeaderCommitMessageHandler(signedCommitMessages)
		}
	}
}
