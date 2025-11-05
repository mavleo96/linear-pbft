package clientapp

import (
	"cmp"
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// ResponseCollector collects responses and determines consensus
type ResponseCollector struct {
	clientID string
	state    *ClientState
	f        int64

	// Channels
	resultCh   chan<- Result
	responseCh chan *pb.TransactionResponse
}

// GetSendResponseChannel returns the channel for sending responses to the response collector
func (rc *ResponseCollector) GetSendResponseChannel() chan<- *pb.TransactionResponse {
	return rc.responseCh
}

// CollectResponses collects responses and determines consensus
func (rc *ResponseCollector) CollectResponses(ctx context.Context) {
	majorityReached := false // Whether f+1 matching values have been received
collectionLoop:
	for {
		select {
		case <-ctx.Done():
			return
		case resp := <-rc.responseCh:
			// Check timestamp and view number
			switch cmp.Compare(resp.Timestamp, rc.state.GetTimestamp()) {
			case -1: // old timestamp - ignore
				continue collectionLoop
			case 0: // current timestamp
				if majorityReached {
					continue collectionLoop
				}
				// TODO: this maybe be redundant since result is (v, r)
				// If new view started while receiving replies, reset
				if resp.ViewNumber > rc.state.GetViewNumber() {
					rc.state.UpdateViewNumber(resp.ViewNumber)
					rc.state.ResetResponseMap()
					majorityReached = false
				}
			case 1: // new timestamp
				rc.state.UpdateTimestamp(resp.Timestamp)
				rc.state.UpdateViewNumber(resp.ViewNumber)
				rc.state.ResetResponseMap()
				majorityReached = false
			}

			// Record reply
			rc.state.AddResponse(resp.NodeID, Result{ViewNumber: resp.ViewNumber, Result: resp.Result})

			// Check if f+1 matching values have been received
			responseCounter := rc.state.GetResponseMap()
			maxVal, maxCnt := utils.MaxByValue(utils.CountMap(utils.Values(responseCounter)))
			if maxCnt >= rc.f+1 {
				majorityReached = true
				rc.resultCh <- maxVal
			}
		}
	}
}
