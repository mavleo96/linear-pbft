package linearpbft

import (
	"context"
	"fmt"
	"sort"

	"github.com/mavleo96/bft-mavleo96/internal/utils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// PrintLog prints the log
func (n *LinearPBFTNode) PrintLog(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	fmt.Println("Printing log records:")
	maxSequenceNum := utils.Max(utils.Keys(n.LogRecords))
	for i := int64(1); i <= maxSequenceNum; i++ {
		record, ok := n.LogRecords[i]
		if ok {
			signedRequest := n.TransactionMap.Get(record.Digest)
			fmt.Printf(
				"%s, v: %d, s: %d, %s\n",
				utils.LoggingString(signedRequest.Request),
				record.ViewNumber, record.SequenceNum,
				recordStatus(record))
		}
	}
	fmt.Println("")

	return &emptypb.Empty{}, nil
}

// PrintDB prints the database
func (n *LinearPBFTNode) PrintDB(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	fmt.Println("Printing database:")
	db_state, err := n.DB.PrintDB()
	if err != nil {
		log.Fatal(err)
	}

	// Sort client ids
	clientIDs := utils.Keys(db_state)
	sort.Strings(clientIDs)

	// Print by client id
	for _, clientID := range clientIDs {
		fmt.Printf("Balance: %s: %d\n", clientID, db_state[clientID])
	}
	fmt.Println("")
	return &emptypb.Empty{}, nil
}

// PrintStatus prints the status of a sequence number
func (n *LinearPBFTNode) PrintStatus(ctx context.Context, req *wrapperspb.Int64Value) (*emptypb.Empty, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	fmt.Println("Printing status:")

	sequenceNum := req.Value
	record, ok := n.LogRecords[sequenceNum]

	if !ok {
		fmt.Printf("Sequence Number: %d, Status: X\n", sequenceNum)
		return &emptypb.Empty{}, nil
	}

	signedRequest := n.TransactionMap.Get(record.Digest)
	if signedRequest == nil {
		fmt.Printf("Request not found in transaction map for sequence number %d\n", sequenceNum)
		return &emptypb.Empty{}, nil
	}
	fmt.Printf("Sequence Number: %d, Status: %s, Message: %s\n", sequenceNum, recordStatus(record), utils.LoggingString(signedRequest.Request))
	fmt.Println("")
	return &emptypb.Empty{}, nil
}

// recordStatus returns the status of a log record
func recordStatus(record *LogRecord) string {
	if record.IsExecuted() {
		return "E"
	} else if record.IsCommitted() {
		return "C"
	} else if record.IsPrepared() {
		return "P"
	} else {
		return "PP"
	}
}
