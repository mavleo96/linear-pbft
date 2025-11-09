package linearpbft

import (
	"context"
	"fmt"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	log "github.com/sirupsen/logrus"
)

// BenchmarkExecuteRoutine is the routine for executing YCSB benchmark transactions
func (e *Executor) BenchmarkExecuteRoutine(ctx context.Context) {
executeLoop:
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-e.benchmarkExecutionTriggerCh:
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
				case "ycsb_write", "ycsb_update":
					// Key-value write/update operations
					table := request.Transaction.Table
					key := request.Transaction.Key
					values := request.Transaction.Values

					if table == "" || key == "" {
						err = fmt.Errorf("table and key are required for write/update operations")
						break
					}

					// Get encoded data from values map
					encodedData, ok := values["data"]
					if !ok || len(encodedData) == 0 {
						err = fmt.Errorf("no data provided for write/update")
						break
					}

					if request.Transaction.Type == "ycsb_write" {
						err = e.db.PutKeyValue(table, key, encodedData)
					} else {
						err = e.db.UpdateKeyValue(table, key, encodedData)
					}

					if err != nil {
						log.Warnf("Write/Update operation failed: %v", err)
						result = 0 // Failure
					} else {
						result = 1 // Success
					}
					e.benchmarkHandler.GetSendSignalCh(crypto.Digest(signedRequest)) <- result

				case "ycsb_delete":
					table := request.Transaction.Table
					key := request.Transaction.Key

					if table == "" || key == "" {
						err = fmt.Errorf("table and key are required for delete operation")
						break
					}

					err = e.db.DeleteKeyValue(table, key)
					if err != nil {
						log.Warnf("Delete operation failed: %v", err)
						result = 0
					} else {
						result = 1
					}
					e.benchmarkHandler.GetSendSignalCh(crypto.Digest(signedRequest)) <- result

				case "ycsb_scan":
					table := request.Transaction.Table
					startKey := request.Transaction.StartKey
					count := request.Transaction.ScanCount

					results, err := e.db.ScanKeyValue(table, startKey, int(count))
					if err != nil {
						log.Warnf("Scan operation failed: %v", err)
						// Send empty results on error
						e.benchmarkHandler.GetSendSignalCh(crypto.Digest(signedRequest)) <- []map[string][]byte{}
					} else {
						// Convert []struct{Key, Value} to []map[string][]byte for easier handling
						scanResults := make([]map[string][]byte, 0, len(results))
						for _, r := range results {
							scanResults = append(scanResults, map[string][]byte{"value": r.Value})
						}
						e.benchmarkHandler.GetSendSignalCh(crypto.Digest(signedRequest)) <- scanResults
					}

				case "ycsb_read":
					table := request.Transaction.Table
					key := request.Transaction.Key

					value, err := e.db.GetKeyValue(table, key)
					if err != nil {
						log.Warnf("Read operation failed: %v", err)
						result = 0
						// Send empty result data on error
						e.benchmarkHandler.GetSendSignalCh(crypto.Digest(signedRequest)) <- map[string][]byte{}
					} else {
						// Convert []byte to map[string][]byte for consistency
						resultData := map[string][]byte{"value": value}
						e.benchmarkHandler.GetSendSignalCh(crypto.Digest(signedRequest)) <- resultData
					}
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
		}
	}
}
