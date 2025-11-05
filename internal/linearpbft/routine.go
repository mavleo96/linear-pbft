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

			// Preprepare the transaction
			record.AddPrePrepareMessage(signedPreprepare)

			// Send preprepare message to all nodes and collect prepare messages
			go func() {
				prepareMsgs, err := n.SendPrePrepare(signedPreprepare, sequenceNum)
				if err != nil || prepareMsgs == nil {
					return
				}
				n.PrepareCh <- prepareMsgs
			}()

		case signedPrepareMessages := <-n.PrepareCh:

			sequenceNum := signedPrepareMessages[0].Message.SequenceNum
			go func() {
				commitMsgs, err := n.SendPrepare(signedPrepareMessages, sequenceNum)
				if err != nil || commitMsgs == nil {
					return
				}
				n.CommitCh <- commitMsgs
			}()

		case signedCommitMessages := <-n.CommitCh:
			sequenceNum := signedCommitMessages[0].Message.SequenceNum

			go func() {
				err := n.SendCommit(signedCommitMessages, sequenceNum)
				if err != nil {
					return
				}
			}()
		}
		n.TryExecute(0)

	}
}
