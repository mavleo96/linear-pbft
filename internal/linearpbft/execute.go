package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

type Executor struct {
	db           *database.Database
	safeTimer    *SafeTimer
	state        *ServerState
	config       *ServerConfig
	executeCh    chan int64
	sendReply    func(signedRequest *pb.SignedTransactionRequest, result int64)
	checkPointCh chan bool
}

func (e *Executor) GetExecuteChannel() chan<- int64 {
	return e.executeCh
}

func (e *Executor) ExecuteRoutine(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-e.executeCh:
			log.Infof("Received execute signal for sequence number %d", s)
			sequenceNum := e.state.GetLastExecutedSequenceNum()
			maxSequenceNum := e.state.StateLog.MaxSequenceNum()
			if sequenceNum == maxSequenceNum {
				continue
			}

		tryLoop:
			for i := sequenceNum + 1; i <= maxSequenceNum; i++ {
				if !e.state.StateLog.IsCommitted(i) {
					break tryLoop
				}
				if e.state.StateLog.IsExecuted(i) {
					// e.state.SetLastExecutedSequenceNum(i)
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
					continue
				}
				if err != nil {
					log.Fatal(err)
				}

				// Add to executed log and send reply if transaction is not null
				e.state.StateLog.SetExecuted(i)
				// TODO: make this elegant since primary doesn't have a safe timer running
				e.safeTimer.DecrementWaitCountAndResetOrStopIfZero()
				log.Infof("Executed (v: %d, s: %d): %s", e.state.GetViewNumber(), i, utils.LoggingString(request.Transaction))
				if request.Transaction.Type != "null" {
					go e.sendReply(signedRequest, result)
				}
				e.state.SetLastExecutedSequenceNum(i)

				// Signal the checkpoint routine if the last executed sequence number is a multiple of k
				if i%e.config.k == 0 {
					e.checkPointCh <- true
				}
			}
		}
	}
}
