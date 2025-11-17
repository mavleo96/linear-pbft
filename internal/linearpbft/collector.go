package linearpbft

import (
	"time"

	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
)

// CollectPrepareMessages collects prepare messages from all nodes and sends to handler
func (n *LinearPBFTNode) CollectPrepareMessages(responseCh <-chan *pb.SignedPrepareMessage) {
	signedPrepareMessageMap := make(map[int64]map[string]*pb.SignedPrepareMessage) // sequence number -> node ID -> signed prepare message
	sbftSignalChMap := make(map[int64]chan bool)                                   // sequence number -> sbft signal channel

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
			// Add self's prepare message to support TSS
			prepareMessage := &pb.PrepareMessage{
				ViewNumber:  signedPrepareMessage.Message.ViewNumber,
				SequenceNum: sequenceNum,
				Digest:      signedPrepareMessage.Message.Digest,
				NodeID:      n.ID,
			}
			signedPrepareMessage := &pb.SignedPrepareMessage{
				Message:    prepareMessage,
				Signature:  crypto.Sign(prepareMessage, n.handler.privateKey1),
				Signature2: crypto.Sign(prepareMessage, n.handler.privateKey2),
			}

			// Byzantine node behavior: sign attack
			if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
				signedPrepareMessage.Signature = []byte("invalid signature")
				signedPrepareMessage.Signature2 = []byte("invalid signature")
			}
			signedPrepareMessageMap[sequenceNum][n.ID] = signedPrepareMessage

			sbftSignalChMap[sequenceNum] = make(chan bool)
			defer close(sbftSignalChMap[sequenceNum])
			go func(sequenceNum int64, sbftSignalCh chan bool) {
				select {
				case <-time.After(SBFTTimeout):
					log.Infof("SBFT timeout for sequence number %d", sequenceNum)
				case <-sbftSignalCh:
					log.Infof("SBFT signal received for sequence number %d", sequenceNum)
				}
				n.handler.LeaderPrepareMessageHandler(utils.Values(signedPrepareMessageMap[sequenceNum]))
			}(sequenceNum, sbftSignalChMap[sequenceNum])
		}

		if len(signedPrepareMessageMap[sequenceNum]) == int(n.config.N) {
			sbftSignalChMap[sequenceNum] <- true
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

			// Byzantine node behavior: sign attack
			if n.byzantineConfig.Byzantine && n.byzantineConfig.SignAttack {
				signedCommitMessage.Signature = []byte("invalid signature")
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
