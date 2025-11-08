package linearpbft

import (
	"context"
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// PrePrepareRequest validates incoming preprepare messages and routes it to the protocol handler
func (n *LinearPBFTNode) PrePrepareRequest(ctx context.Context, signedMessage *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error) {
	prePrepareMessage := signedMessage.Message
	signedRequest := signedMessage.Request

	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.state.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if prePrepareMessage.ViewNumber != n.state.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(prePrepareMessage), n.state.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify if sequence number is within low and high water mark
	if !n.config.SequenceNumberInRange(prePrepareMessage.SequenceNum) {
		log.Warnf("Rejected: %s; sequence number out of range (expected: %d to %d)", utils.LoggingString(prePrepareMessage), n.config.GetLowWaterMark(), n.config.GetHighWaterMark())
		return nil, status.Errorf(codes.InvalidArgument, "sequence number out of range")
	}

	// Verify Node's signature
	currentPrimaryID := utils.ViewNumberToPrimaryID(n.state.GetViewNumber(), n.config.N)
	ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(currentPrimaryID), signedMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify Client's signature if request is not nil
	if signedRequest != nil && signedRequest.Request != nil &&
		!cmp.Equal(prePrepareMessage.Digest, DigestNoOp) &&
		!crypto.Verify(signedRequest.Request, n.clients[signedRequest.Request.Sender].PublicKey, signedRequest.Signature) {
		log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(signedRequest.Request))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature on request")
	}

	// Handle preprepare message
	signedPrepareMessage, err := n.handler.BackupPrePrepareRequestHandler(signedMessage)

	// Byzantine node behavior: dark attack
	primaryID := utils.ViewNumberToPrimaryID(prePrepareMessage.ViewNumber, n.config.N)
	if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, primaryID) {
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	return signedPrepareMessage, err
}

// PrepareRequest validates incoming prepare messages and routes it to the protocol handler
func (n *LinearPBFTNode) PrepareRequest(ctx context.Context, signedPrepareMessage *pb.SignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	prepareMessage := signedPrepareMessage.Message
	viewNumber := prepareMessage.ViewNumber

	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.state.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedPrepareMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.state.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedPrepareMessage), n.state.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify if sequence number is within low and high water mark
	if !n.config.SequenceNumberInRange(prepareMessage.SequenceNum) {
		log.Warnf("Rejected: %s; sequence number out of range (expected: %d to %d)", utils.LoggingString(prepareMessage), n.config.GetLowWaterMark(), n.config.GetHighWaterMark())
		return nil, status.Errorf(codes.InvalidArgument, "sequence number out of range")
	}

	// Verify Signature
	ok := crypto.Verify(prepareMessage, n.handler.masterPublicKey1, signedPrepareMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(signedPrepareMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Handle prepare message
	signedCommitMessage, err := n.handler.BackupPrepareRequestHandler(signedPrepareMessage)

	// Byzantine node behavior: dark attack
	primaryID := utils.ViewNumberToPrimaryID(prepareMessage.ViewNumber, n.config.N)
	if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, primaryID) {
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Byzantine node behavior: crash attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.CrashAttack {
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	return signedCommitMessage, err

}

// CommitRequest validates incoming commit messages and routes it to the protocol handler
func (n *LinearPBFTNode) CommitRequest(ctx context.Context, signedCommitMessage *pb.SignedCommitMessage) (*emptypb.Empty, error) {
	commitMessage := signedCommitMessage.Message
	viewNumber := commitMessage.ViewNumber

	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.state.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedCommitMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.state.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedCommitMessage), n.state.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify if sequence number is within low and high water mark
	if !n.config.SequenceNumberInRange(commitMessage.SequenceNum) {
		log.Warnf("Rejected: %s; sequence number out of range (expected: %d to %d)", utils.LoggingString(commitMessage), n.config.GetLowWaterMark(), n.config.GetHighWaterMark())
		return nil, status.Errorf(codes.InvalidArgument, "sequence number out of range")
	}

	// Verify Signature
	ok := crypto.Verify(commitMessage, n.handler.masterPublicKey1, signedCommitMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(signedCommitMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	return n.handler.BackupCommitRequestHandler(signedCommitMessage)
}

// ViewChangeRequest validates incoming view change messages and routes it to the view change manager
func (n *LinearPBFTNode) ViewChangeRequest(ctx context.Context, signedViewChangeMessage *pb.SignedViewChangeMessage) (*emptypb.Empty, error) {
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber
	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify view number
	if viewNumber <= n.state.GetViewNumber() {
		log.Warnf("Rejected: %s; lower view number (expected: %d)", utils.LoggingString(viewChangeMessage), n.state.GetViewNumber())
		return nil, status.Errorf(codes.FailedPrecondition, "invalid view number")
	}

	// Verify signature
	ok := crypto.Verify(viewChangeMessage, n.GetPublicKey1(viewChangeMessage.NodeID), signedViewChangeMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(viewChangeMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify check point messages signatures
	// TODO: need to verify digest
	for _, signedCheckpointMessage := range viewChangeMessage.CheckpointMessages {
		checkpointMessage := signedCheckpointMessage.Message
		ok := crypto.Verify(checkpointMessage, n.GetPublicKey1(checkpointMessage.NodeID), signedCheckpointMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on checkpoint message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on checkpoint message")
		}
	}

	// Verify prepare set
	for _, prepareProof := range viewChangeMessage.PreparedSet {
		signedPrePrepareMessage := prepareProof.SignedPrePrepareMessage
		prePrepareMessage := signedPrePrepareMessage.Message
		signedPrepareMessage := prepareProof.SignedPrepareMessage
		prepareMessage := signedPrepareMessage.Message

		// Verify preprepare message signature
		proposerID := utils.ViewNumberToPrimaryID(prePrepareMessage.ViewNumber, n.config.N)
		ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(proposerID), signedPrePrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on preprepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on preprepare message")
		}

		// Verify prepare message signature
		ok = crypto.Verify(prepareMessage, n.handler.masterPublicKey1, signedPrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on prepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on prepare message")
		}

		// Verify prepare message digest, view number and sequence number against corresponding preprepare message
		if prepareMessage.ViewNumber != prePrepareMessage.ViewNumber ||
			prepareMessage.SequenceNum != prePrepareMessage.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, prePrepareMessage.Digest) {
			log.Warnf("Rejected: %s; invalid digest on prepare message for sequence number %d", utils.LoggingString(viewChangeMessage), prepareMessage.SequenceNum)
			return nil, status.Errorf(codes.FailedPrecondition, "invalid digest on prepare message")
		}
	}

	go n.viewchanger.ViewChangeRequestHandler(signedViewChangeMessage)

	return &emptypb.Empty{}, nil
}

// NewViewRequest validates incoming new view messages and routes it to the view change manager
// If new view handler returns an error, the error is returned to the primary else prepare messages are streamed to the primary
func (n *LinearPBFTNode) NewViewRequest(signedNewViewMessage *pb.SignedNewViewMessage, stream pb.LinearPBFTNode_NewViewRequestServer) error {
	newViewMessage := signedNewViewMessage.Message
	signedViewChangeMessages := newViewMessage.SignedViewChangeMessages
	signedPrePrepareMessages := newViewMessage.SignedPrePrepareMessages
	viewNumber := newViewMessage.ViewNumber

	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify view number: must be greater than latest sent view change message view number
	if viewNumber < n.state.GetViewChangeViewNumber() {
		log.Warnf("Rejected: %s; view number is less than latest sent view change message view number", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.FailedPrecondition, "view number is less than latest sent view change message view number")
	}

	// Verify signature
	primaryID := utils.ViewNumberToPrimaryID(viewNumber, n.config.N)
	ok := crypto.Verify(newViewMessage, n.GetPublicKey1(primaryID), signedNewViewMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify view change messages signatures
	for _, signedViewChangeMessage := range signedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		ok := crypto.Verify(viewChangeMessage, n.GetPublicKey1(viewChangeMessage.NodeID), signedViewChangeMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on view change message", utils.LoggingString(newViewMessage))
			return status.Errorf(codes.FailedPrecondition, "invalid signature on view change message")
		}
	}

	// Verify preprepare messages signatures
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(primaryID), signedPrePrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on preprepare message", utils.LoggingString(newViewMessage))
			return status.Errorf(codes.FailedPrecondition, "invalid signature on preprepare message")
		}
	}

	// Transfer control to new view handler
	err := n.viewchanger.BackupNewViewRequestHandler(signedNewViewMessage)
	if err != nil {
		log.Warnf("New view request %s could not be handled: %s", utils.LoggingString(newViewMessage), err)
		return status.Errorf(codes.Internal, "new view request could not be handled")
	}

	// TODO: get missing requests
	// route it to router routine and set the missing requests in the transaction map

	// Route preprepare message to handler and stream prepare messages to primary
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		signedPrepareMessage, err := n.handler.BackupPrePrepareRequestHandler(signedPrePrepareMessage)
		if err != nil {
			log.Warnf("Prepare request %s could not be sent to primary: %s", utils.LoggingString(signedPrePrepareMessage), err)
			continue
		}

		// Byzantine node behavior: dark attack
		primaryID := utils.ViewNumberToPrimaryID(signedPrepareMessage.Message.ViewNumber, n.config.N)
		if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, primaryID) {
			continue
		}

		if err := stream.Send(signedPrepareMessage); err != nil {
			log.Warnf("Prepare message %s could not be sent to primary in stream: %s", utils.LoggingString(signedPrepareMessage), err)
		}
	}
	log.Infof("Streamed prepares messages for view number %d", viewNumber)

	return nil
}

// CheckpointRequest validates incoming check point messages and routes it to the check point manager
func (n *LinearPBFTNode) CheckpointRequest(ctx context.Context, signedCheckpointMessage *pb.SignedCheckpointMessage) (*emptypb.Empty, error) {
	checkpointMessage := signedCheckpointMessage.Message

	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify signature
	ok := crypto.Verify(checkpointMessage, n.GetPublicKey1(checkpointMessage.NodeID), signedCheckpointMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(checkpointMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	go n.executor.checkpointer.CheckpointMessageHandler(signedCheckpointMessage)
	return &emptypb.Empty{}, nil
}

// GetRequest returns a signed transaction request for a given digest
func (n *LinearPBFTNode) GetRequest(ctx context.Context, getRequestMessage *pb.GetRequestMessage) (*pb.SignedTransactionRequest, error) {
	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Byzantine node behavior: dark attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, getRequestMessage.NodeID) {
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	digest := getRequestMessage.Digest
	signedRequest := n.state.TransactionMap.Get(digest)
	if signedRequest == nil || signedRequest.Request == nil {
		log.Warnf("Rejected: %s; request not found in transaction map", utils.LoggingString(getRequestMessage))
		return nil, status.Errorf(codes.NotFound, "request not found in transaction map")
	}

	log.Infof("Get request: %s: request %s", utils.LoggingString(getRequestMessage), utils.LoggingString(signedRequest.Request))
	return signedRequest, nil
}

// GetCheckpoint returns a checkpoint for a given sequence number
func (n *LinearPBFTNode) GetCheckpoint(ctx context.Context, getCheckpointMessage *pb.GetCheckpointMessage) (*pb.Checkpoint, error) {
	// Ignore if not alive
	if !n.byzantineConfig.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Byzantine node behavior: dark attack
	if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, getCheckpointMessage.NodeID) {
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	sequenceNum := getCheckpointMessage.SequenceNum
	checkpoint := n.executor.checkpointer.GetCheckpoint(sequenceNum)
	if checkpoint == nil {
		log.Warnf("Rejected: %s; checkpoint not found for sequence number %d", utils.LoggingString(getCheckpointMessage), sequenceNum)
		return nil, status.Errorf(codes.NotFound, "checkpoint not found for sequence number %d", sequenceNum)
	}
	return checkpoint, nil
}
