package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) ServiceRoutine(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		// Send preprepare message on receiving transaction request
		case signedRequest := <-n.RequestCh:
			request := signedRequest.Request

			// Get or assign sequence number
			sequenceNum, exists := n.GetOrAssignSequenceNumber(signedRequest)
			if !exists {
				// Add request to log record
				n.Mutex.Lock()
				n.StateLog.Set(sequenceNum, CreateLogRecord(n.ViewNumber, sequenceNum, crypto.Digest(signedRequest)))
				n.Mutex.Unlock()
			}
			record, _ := n.StateLog.Get(sequenceNum)

			// Add request to transaction map
			if n.TransactionMap.Get(crypto.Digest(signedRequest)) == nil {
				log.Infof("Adding request to transaction map: %s", utils.LoggingString(request))
				n.TransactionMap.Set(crypto.Digest(signedRequest), signedRequest)
			}

			// Create signed preprepare message
			preprepare := &pb.PrePrepareMessage{
				ViewNumber:  n.ViewNumber,
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
		log.Infof("DEBUG: Trying to execute sequence number %d", n.LastExecutedSequenceNum)
		n.TryExecute(0)
		log.Infof("DEBUG: Executed sequence number %d", n.LastExecutedSequenceNum)

	}
}
