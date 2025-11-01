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

	if record.IsExecuted() {
		fmt.Printf("Sequence Number: %d, Status: E, Message: %s\n", sequenceNum, utils.LoggingString(signedRequest.Request))
	} else if record.IsCommitted() {
		fmt.Printf("Sequence Number: %d, Status: C, Message: %s\n", sequenceNum, utils.LoggingString(signedRequest.Request))
	} else if record.IsPrepared() {
		fmt.Printf("Sequence Number: %d, Status: P, Message: %s\n", sequenceNum, utils.LoggingString(signedRequest.Request))
	} else {
		fmt.Printf("Sequence Number: %d, Status: PP, Message: %s\n", sequenceNum, utils.LoggingString(signedRequest.Request))
	}
	fmt.Println("")
	return &emptypb.Empty{}, nil
}
