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
	sendReply    func(sequenceNum int64, request *pb.TransactionRequest, result int64)
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
		case <-e.executeCh:
			sequenceNum := e.state.GetLastExecutedSequenceNum() + 1
			maxSequenceNum := e.state.StateLog.MaxSequenceNum()

			for i := sequenceNum; i <= maxSequenceNum; i++ {
				record, exists := e.state.StateLog.Get(i)
				if !exists {
					break
				}
				if record == nil || !record.IsCommitted() {
					break
				}

				// Execute transaction
				request := e.state.TransactionMap.Get(record.Digest).Request
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
				record.SetExecuted()
				// TODO: make this elegant since primary doesn't have a safe timer running
				e.safeTimer.DecrementWaitCountAndResetOrStopIfZero()
				log.Infof("Executed (v: %d, s: %d): %s", e.state.GetViewNumber(), i, utils.LoggingString(request.Transaction))
				if request.Transaction.Type != "null" {
					go e.sendReply(i, request, result)
				}
				e.state.SetLastExecutedSequenceNum(i)

				// Signal the checkpoint routine if the last executed sequence number is a multiple of k
				if i%e.config.k == 0 {
					// n.Mutex.Unlock()
					e.checkPointCh <- true
					// n.Mutex.Lock()
				}
			}
		}
	}
}
