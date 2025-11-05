package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) ServiceRoutine(ctx context.Context) {
	log.Infof("Service routine started")
	for {
		// TODO: need to stop this service routine if not primary and drain the channels
		select {
		case <-ctx.Done():
			return
		// Send preprepare message on receiving transaction request
		case signedRequest := <-n.RequestCh:
			request := signedRequest.Request

			// Get or assign sequence number
			sequenceNum, exists := n.State.StateLog.GetOrAssignSequenceNumber(signedRequest)
			if !exists {
				// Add request to log record
				n.State.StateLog.Set(sequenceNum, CreateLogRecord(n.State.GetViewNumber(), sequenceNum, crypto.Digest(signedRequest)))
			}
			record, _ := n.State.StateLog.Get(sequenceNum)

			// Add request to transaction map
			if n.State.TransactionMap.Get(crypto.Digest(signedRequest)) == nil {
				log.Infof("Adding request to transaction map: %s", utils.LoggingString(request))
				n.State.TransactionMap.Set(crypto.Digest(signedRequest), signedRequest)
			}

			// Create signed preprepare message
			preprepare := &pb.PrePrepareMessage{
				ViewNumber:  n.State.GetViewNumber(),
				SequenceNum: sequenceNum,
				Digest:      crypto.Digest(signedRequest),
			}
			signedPreprepare := &pb.SignedPrePrepareMessage{
				Message:   preprepare,
				Signature: crypto.Sign(preprepare, n.PrivateKey),
				Request:   signedRequest,
			}
			// Byzantine node behavior: sign attack
			if n.Byzantine && n.SignAttack {
				// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
				signedPreprepare.Signature = []byte("invalid signature")
			}

			// Preprepare the transaction
			record.AddPrePrepareMessage(signedPreprepare)

			// Multicast preprepare message to all nodes
			go func() {
				err := n.SendPrePrepare(signedPreprepare, sequenceNum)
				if err != nil {
					return
				}
			}()

		case signedPrepareMessages := <-n.PrepareCh:
			// Add prepare messages to log record
			sequenceNum := signedPrepareMessages[0].Message.SequenceNum
			record, _ := n.State.StateLog.Get(sequenceNum)
			record.AddPrepareMessages(signedPrepareMessages)
			// Byzantine node behavior: crash attack
			if n.Byzantine && n.CrashAttack {
				// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
				record.MaliciousUpdateLogState()
			}

			// Create collected signed prepare message
			collectedSignedPrepareMessages := &pb.CollectedSignedPrepareMessage{
				ViewNumber:  n.State.GetViewNumber(),
				SequenceNum: sequenceNum,
				Digest:      record.Digest,
				Messages:    signedPrepareMessages,
			}

			// Multicast prepare message to all nodes
			go func() {
				err := n.SendPrepare(collectedSignedPrepareMessages)
				if err != nil {
					return
				}
			}()

		case signedCommitMessages := <-n.CommitCh:
			// Add commit messages to log record
			sequenceNum := signedCommitMessages[0].Message.SequenceNum
			record, _ := n.State.StateLog.Get(sequenceNum)
			record.AddCommitMessages(signedCommitMessages)

			// Create collected signed commit message
			collectedSignedCommitMessage := &pb.CollectedSignedCommitMessage{
				ViewNumber:  n.State.GetViewNumber(),
				SequenceNum: sequenceNum,
				Digest:      record.Digest,
				Messages:    signedCommitMessages,
			}

			// Multicast commit message to all nodes
			go func() {
				err := n.SendCommit(collectedSignedCommitMessage)
				if err != nil {
					return
				}
			}()
		}
		n.TryExecute(0)

	}
}
