package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (h *ProtocolHandler) ServiceRoutine(ctx context.Context) {
	log.Infof("Service routine started")
	for {
		// TODO: need to stop this service routine if not primary and drain the channels
		select {
		case <-ctx.Done():
			return
		// Send preprepare message on receiving transaction request
		case signedRequest := <-h.requestCh:
			// request := signedRequest.Request

			// Get or assign sequence number
			sequenceNum, exists := h.state.StateLog.GetOrAssignSequenceNumber(signedRequest)
			if !exists {
				// Add request to log record
				h.state.StateLog.Set(sequenceNum, CreateLogRecord(h.state.GetViewNumber(), sequenceNum, crypto.Digest(signedRequest)))
			}
			record, _ := h.state.StateLog.Get(sequenceNum)

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
			// // Byzantine node behavior: sign attack
			// if n.Byzantine && n.SignAttack {
			// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
			// 	signedPreprepare.Signature = []byte("invalid signature")
			// }

			// Preprepare the transaction
			record.AddPrePrepareMessage(signedPreprepare)

			// Multicast preprepare message to all nodes
			go func() {
				err := h.SendPrePrepare(signedPreprepare, sequenceNum)
				if err != nil {
					return
				}
			}()

		case signedPrepareMessages := <-h.prepareCh:
			// Add prepare messages to log record
			sequenceNum := signedPrepareMessages[0].Message.SequenceNum
			record, _ := h.state.StateLog.Get(sequenceNum)
			record.AddPrepareMessages(signedPrepareMessages)
			// Byzantine node behavior: crash attack
			// if n.Byzantine && n.CrashAttack {
			// 	// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
			// 	record.MaliciousUpdateLogState()
			// }

			// Create collected signed prepare message
			collectedSignedPrepareMessages := &pb.CollectedSignedPrepareMessage{
				ViewNumber:  h.state.GetViewNumber(),
				SequenceNum: sequenceNum,
				Digest:      record.Digest,
				Messages:    signedPrepareMessages,
			}

			// Multicast prepare message to all nodes
			go func() {
				err := h.SendPrepare(collectedSignedPrepareMessages)
				if err != nil {
					return
				}
			}()

		case signedCommitMessages := <-h.commitCh:
			// Add commit messages to log record
			sequenceNum := signedCommitMessages[0].Message.SequenceNum
			record, _ := h.state.StateLog.Get(sequenceNum)
			record.AddCommitMessages(signedCommitMessages)

			// Create collected signed commit message
			collectedSignedCommitMessage := &pb.CollectedSignedCommitMessage{
				ViewNumber:  h.state.GetViewNumber(),
				SequenceNum: sequenceNum,
				Digest:      record.Digest,
				Messages:    signedCommitMessages,
			}

			// Multicast commit message to all nodes
			go func() {
				err := h.SendCommit(collectedSignedCommitMessage)
				if err != nil {
					return
				}
			}()
		}
		h.executeCh <- 0

	}
}
