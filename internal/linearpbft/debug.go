package linearpbft

import (
	"context"
	"fmt"
	"sort"

	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// PrintLog prints the log
func (n *LinearPBFTNode) PrintLog(ctx context.Context, req *wrapperspb.Int64Value) (*emptypb.Empty, error) {
	log.Infof("Print log command received")

	fmt.Println("LOGS FOR TEST SET:", req.Value)

	fmt.Println("Sent preprepare messages:")
	for _, signedPrePrepareMessage := range n.logger.GetSentPrePrepareMessages() {
		fmt.Println(utils.FormattedLoggingString(signedPrePrepareMessage))
	}
	fmt.Println("")

	fmt.Println("Received preprepare messages:")
	for _, signedPrePrepareMessage := range n.logger.GetReceivedPrePrepareMessages() {
		fmt.Println(utils.FormattedLoggingString(signedPrePrepareMessage))
	}
	fmt.Println("")

	fmt.Println("Sent prepare messages:")
	for _, signedPrepareMessage := range n.logger.GetSentPrepareMessages() {
		fmt.Println(utils.FormattedLoggingString(signedPrepareMessage))
	}
	fmt.Println("")

	fmt.Println("Received prepare messages:")
	for _, signedPrepareMessage := range n.logger.GetReceivedPrepareMessages() {
		fmt.Println(utils.FormattedLoggingString(signedPrepareMessage))
	}
	fmt.Println("")

	fmt.Println("Collected prepare messages:")
	for _, signedPrepareMessage := range n.logger.GetCollectedPrepareMessages() {
		fmt.Println(utils.FormattedLoggingString(signedPrepareMessage))
	}
	fmt.Println("")

	fmt.Println("Sent aggregated prepare messages:")
	for _, signedPrepareMessage := range n.logger.GetSentAggregatedPrepareMessages() {
		fmt.Println(utils.FormattedLoggingString(signedPrepareMessage))
	}
	fmt.Println("")

	fmt.Println("Sent commit messages:")
	for _, signedCommitMessage := range n.logger.GetSentCommitMessages() {
		fmt.Println(utils.FormattedLoggingString(signedCommitMessage))
	}
	fmt.Println("")

	fmt.Println("Received commit messages:")
	for _, signedCommitMessage := range n.logger.GetReceivedCommitMessages() {
		fmt.Println(utils.FormattedLoggingString(signedCommitMessage))
	}
	fmt.Println("")

	fmt.Println("Collected commit messages:")
	for _, signedCommitMessage := range n.logger.GetCollectedCommitMessages() {
		fmt.Println(utils.FormattedLoggingString(signedCommitMessage))
	}
	fmt.Println("")

	fmt.Println("Sent aggregated commit messages:")
	for _, signedCommitMessage := range n.logger.GetSentAggregatedCommitMessages() {
		fmt.Println(utils.FormattedLoggingString(signedCommitMessage))
	}
	fmt.Println("")

	fmt.Println("Sent view change messages:")
	for _, signedViewChangeMessage := range n.logger.GetSentViewChangeMessages() {
		fmt.Println(utils.FormattedLoggingString(signedViewChangeMessage))
	}
	fmt.Println("")

	fmt.Println("Received view change messages:")
	for _, signedViewChangeMessage := range n.logger.GetReceivedViewChangeMessages() {
		fmt.Println(utils.FormattedLoggingString(signedViewChangeMessage))
	}
	fmt.Println("")

	fmt.Println("Sent Checkpoint messages:")
	for _, signedCheckpointMessage := range n.logger.GetSentCheckpointMessages() {
		fmt.Println(utils.FormattedLoggingString(signedCheckpointMessage))
	}
	fmt.Println("")

	fmt.Println("Received Checkpoint messages:")
	for _, signedCheckpointMessage := range n.logger.GetReceivedCheckpointMessages() {
		fmt.Println(utils.FormattedLoggingString(signedCheckpointMessage))
	}
	fmt.Println("")

	fmt.Println("Received Transaction requests:")
	for _, signedTransactionRequest := range n.logger.GetReceivedTransactionRequests() {
		fmt.Println(utils.FormattedLoggingString(signedTransactionRequest))
	}
	fmt.Println("")

	fmt.Println("Received Read-only requests:")
	for _, signedTransactionRequest := range n.logger.GetReceivedReadOnlyRequests() {
		fmt.Println(utils.FormattedLoggingString(signedTransactionRequest))
	}
	fmt.Println("")

	fmt.Println("Forwarded Transaction requests:")
	for _, signedTransactionRequest := range n.logger.GetForwardedTransactionRequests() {
		fmt.Println(utils.FormattedLoggingString(signedTransactionRequest))
	}
	fmt.Println("")

	fmt.Println("Sent Transaction responses:")
	for _, signedTransactionResponse := range n.logger.GetSentTransactionResponses() {
		fmt.Println(utils.FormattedLoggingString(signedTransactionResponse))
	}
	fmt.Println("")

	fmt.Println("Sent Read-only responses:")
	for _, signedReadOnlyResponse := range n.logger.GetSentReadOnlyResponses() {
		fmt.Println(utils.FormattedLoggingString(signedReadOnlyResponse))
	}
	fmt.Println("")

	return &emptypb.Empty{}, nil
}

// PrintDB prints the database
func (n *LinearPBFTNode) PrintDB(ctx context.Context, req *wrapperspb.Int64Value) (*emptypb.Empty, error) {
	log.Infof("Print database command received")

	fmt.Println("DATABASE FOR TEST SET:", req.Value)
	db_state, err := n.executor.db.GetDBState()
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
func (n *LinearPBFTNode) PrintStatus(ctx context.Context, req *pb.StatusRequest) (*emptypb.Empty, error) {
	log.Infof("Print status command received")
	fmt.Println("STATUS FOR TEST SET:", req.TestSet)

	printRange := []int64{req.SequenceNum}
	if req.SequenceNum == 0 {
		printRange = utils.Range(n.config.GetLowWaterMark()+1, n.state.StateLog.MaxSequenceNum()+1)
	}
	for _, i := range printRange {
		if !n.state.StateLog.Exists(i) {
			fmt.Println(n.state.StateLog.GetLogString(i), "nil")
			continue
		}
		digest := n.state.StateLog.GetDigest(i)
		fmt.Println(n.state.StateLog.GetLogString(i), utils.LoggingString(n.state.TransactionMap.Get(digest)))
	}
	fmt.Println("")

	return &emptypb.Empty{}, nil
}

// PrintView prints the new view message
func (n *LinearPBFTNode) PrintView(ctx context.Context, req *wrapperspb.Int64Value) (*emptypb.Empty, error) {
	log.Infof("Print view command received")

	fmt.Println("NEW VIEW MESSAGES FOR TEST SET:", req.Value)

	fmt.Println("Sent new view messages:")
	for _, signedNewViewMessage := range n.logger.GetSentNewViewMessages() {
		fmt.Println(utils.FormattedLoggingString(signedNewViewMessage))
	}
	fmt.Println("")

	fmt.Println("Received new view messages:")
	for _, signedNewViewMessage := range n.logger.GetReceivedNewViewMessages() {
		fmt.Println(utils.FormattedLoggingString(signedNewViewMessage))
	}
	fmt.Println("")

	return &emptypb.Empty{}, nil
}
