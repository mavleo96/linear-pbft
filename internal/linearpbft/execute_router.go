package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/utils"
	log "github.com/sirupsen/logrus"
)

func (e *Executor) ExecuteRoutine(ctx context.Context) {
executeLoop:
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-e.executionTriggerCh:
			log.Infof("Received execute signal for sequence number %d", s)
			sequenceNum := e.state.GetLastExecutedSequenceNum()
			maxSequenceNum := e.state.StateLog.MaxSequenceNum()
			if sequenceNum == maxSequenceNum {
				continue executeLoop
			}

		tryLoop:
			for i := sequenceNum + 1; i <= maxSequenceNum; i++ {
				if !e.state.StateLog.IsCommitted(i) {
					break tryLoop
				}
				if e.state.StateLog.IsExecuted(i) {
					log.Fatalf("Sequence number %d was executed but state maxexecuted sequence number is %d", i, e.state.GetLastExecutedSequenceNum())
					continue tryLoop
				}

				// Execute transaction
				signedRequest := e.state.TransactionMap.Get(e.state.StateLog.GetDigest(i))
				request := signedRequest.Request
				var result int64
				var err error
				switch request.Transaction.Type {
				case "read":
					result, err = e.db.GetBalance(request.Transaction.Sender)
					log.Infof("Read transaction result: %d", result)
				case "send":
					var success bool
					success, err = e.db.UpdateDB(request.Transaction)
					result = utils.BoolToInt64(success)
				default:
					log.Infof("Null transaction type at sequence number %d", i)
				}
				if err != nil {
					log.Fatal(err)
				}

				// Add to executed log and send reply if transaction is not null
				e.state.StateLog.SetExecuted(i)
				e.state.StateLog.SetResult(i, result)
				// TODO: make this elegant since primary doesn't have a safe timer running
				e.timer.DecrementWaitCountAndResetOrStopIfZero()
				log.Infof("Executed (v: %d, s: %d): %s", e.state.GetViewNumber(), i, utils.LoggingString(request.Transaction))
				if request.Transaction.Type != "null" {
					// e.sendReplyCh <- i
					go e.sendReply(signedRequest, result)
				}
				e.state.SetLastExecutedSequenceNum(i)

				// Signal the checkpoint routine if the last executed sequence number is a multiple of k
				if i%e.config.K == 0 {
					dbState, err := e.db.GetDBState()
					if err != nil {
						log.Fatal(err)
					}
					e.checkpointer.AddCheckpoint(i, dbState)
					log.Infof("Signal to create check point message for sequence number %d", i)
					e.checkpointer.GetCheckpointCreateChannel() <- i
				}
			}
		case sequenceNum := <-e.checkpointInstallCh:
			checkpoint := e.checkpointer.GetCheckpoint(sequenceNum)
			if checkpoint == nil || checkpoint.Snapshot == nil {
				log.Fatalf("Checkpoint not found or snapshot is nil for sequence number %d", sequenceNum)
			}
			if sequenceNum < e.state.GetLastExecutedSequenceNum() {
				log.Infof("Skipping installation of snapshot for sequence number %d since it is less than the last executed sequence number %d", sequenceNum, e.state.GetLastExecutedSequenceNum())
				continue
			}
			for clientID, balance := range checkpoint.Snapshot {
				e.db.SetBalance(clientID, balance)
			}
			e.state.SetLastExecutedSequenceNum(sequenceNum)
			log.Infof("Installed snapshot for sequence number %d and last executed sequence number is now %d", sequenceNum, e.state.GetLastExecutedSequenceNum())
			e.executionTriggerCh <- sequenceNum
			log.Infof("Signaled execute channel for sequence number %d", sequenceNum)
			e.checkpointer.GetCheckpointPurgeChannel() <- sequenceNum
			log.Infof("Signalled checkpoint purge channel for sequence number %d", sequenceNum)
		}
	}
}
