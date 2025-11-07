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
	log.Infof("Print log command received")
	fmt.Println("Printing log records:")
	maxSequenceNum := n.State.StateLog.MaxSequenceNum()
	for i := int64(1); i <= maxSequenceNum; i++ {
		record := n.State.StateLog.GetLogRecord(i)
		if record == nil {
			continue
		}
		signedRequest := n.State.TransactionMap.Get(record.digest)
		fmt.Printf(
			"%s, v: %d, s: %d, %s\n",
			utils.LoggingString(signedRequest.Request),
			record.viewNumber, record.sequenceNum,
			recordStatus(record))
	}
	fmt.Println("")

	return &emptypb.Empty{}, nil
}

// PrintDB prints the database
func (n *LinearPBFTNode) PrintDB(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	log.Infof("Print database command received")
	fmt.Println("Printing database:")
	db_state, err := n.Executor.db.PrintDB()
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
	log.Infof("Print status command received")
	fmt.Println("Printing status:")

	sequenceNum := req.Value
	record := n.State.StateLog.GetLogRecord(sequenceNum)
	if record == nil {
		fmt.Printf("Sequence Number: %d, Status: X\n", sequenceNum)
		return &emptypb.Empty{}, nil
	}

	signedRequest := n.State.TransactionMap.Get(record.digest)
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
	if record.executed {
		return "E"
	} else if record.committed {
		return "C"
	} else if record.prepared {
		return "P"
	} else {
		return "PP"
	}
}
