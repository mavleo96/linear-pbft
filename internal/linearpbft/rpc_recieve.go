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
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.State.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if prePrepareMessage.ViewNumber != n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(prePrepareMessage), n.State.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify Node's signature
	currentPrimaryID := utils.ViewNumberToPrimaryID(n.State.GetViewNumber(), n.Handler.N)
	ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(currentPrimaryID), signedMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prePrepareMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify Client's signature if request is not nil
	if signedRequest != nil && signedRequest.Request != nil &&
		!cmp.Equal(prePrepareMessage.Digest, DigestNoOp) &&
		!crypto.Verify(signedRequest.Request, n.Clients[signedRequest.Request.Sender].PublicKey, signedRequest.Signature) {
		log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(signedRequest.Request))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature on request")
	}

	return n.Handler.BackupPrePrepareRequestHandler(signedMessage)
}

// PrepareRequest validates incoming prepare messages and routes it to the protocol handler
func (n *LinearPBFTNode) PrepareRequest(ctx context.Context, signedPrepareMessage *pb.SignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	prepareMessage := signedPrepareMessage.Message
	viewNumber := prepareMessage.ViewNumber

	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.State.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedPrepareMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedPrepareMessage), n.State.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify Signature
	ok := crypto.Verify(prepareMessage, n.Handler.masterPublicKey1, signedPrepareMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(signedPrepareMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	return n.Handler.BackupPrepareRequestHandler(signedPrepareMessage)
}

// CommitRequest validates incoming commit messages and routes it to the protocol handler
func (n *LinearPBFTNode) CommitRequest(ctx context.Context, signedCommitMessage *pb.SignedCommitMessage) (*emptypb.Empty, error) {
	commitMessage := signedCommitMessage.Message
	viewNumber := commitMessage.ViewNumber

	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Ignore if already in view change
	if n.State.InViewChangePhase() {
		log.Infof("Ignored: %s; view change phase", utils.LoggingString(signedCommitMessage))
		return nil, status.Errorf(codes.Unavailable, "view change phase")
	}

	// Verify View Number
	if viewNumber != n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; invalid view number (expected: %d)", utils.LoggingString(signedCommitMessage), n.State.GetViewNumber())
		return nil, status.Errorf(codes.InvalidArgument, "invalid view number")
	}

	// Verify Signature
	ok := crypto.Verify(commitMessage, n.Handler.masterPublicKey1, signedCommitMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(signedCommitMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	return n.Handler.BackupCommitRequestHandler(signedCommitMessage)
}

// ViewChangeRequest validates incoming view change messages and routes it to the view change manager
func (n *LinearPBFTNode) ViewChangeRequest(ctx context.Context, signedViewChangeMessage *pb.SignedViewChangeMessage) (*emptypb.Empty, error) {
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber
	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify view number
	if viewNumber <= n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; lower view number (expected: %d)", utils.LoggingString(viewChangeMessage), n.State.GetViewNumber())
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
	for _, signedCheckPointMessage := range viewChangeMessage.CheckPointMessages {
		checkPointMessage := signedCheckPointMessage.Message
		ok := crypto.Verify(checkPointMessage, n.GetPublicKey1(checkPointMessage.NodeID), signedCheckPointMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on check point message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on check point message")
		}
	}

	// Verify prepare set
	for _, prepareProof := range viewChangeMessage.PreparedSet {
		signedPrePrepareMessage := prepareProof.SignedPrePrepareMessage
		prePrepareMessage := signedPrePrepareMessage.Message
		signedPrepareMessage := prepareProof.SignedPrepareMessage
		prepareMessage := signedPrepareMessage.Message

		// Verify preprepare message signature
		proposerID := utils.ViewNumberToPrimaryID(prePrepareMessage.ViewNumber, n.Handler.N)
		ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(proposerID), signedPrePrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on preprepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on preprepare message")
		}

		// Verify prepare message signature
		ok = crypto.Verify(prepareMessage, n.Handler.masterPublicKey1, signedPrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on prepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on prepare message")
		}

		// Verify prepare message digest, view number and sequence number against corresponding preprepare message
		if prepareMessage.ViewNumber != prePrepareMessage.ViewNumber ||
			prepareMessage.SequenceNum != prePrepareMessage.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, prePrepareMessage.Digest) {
			log.Warnf("Rejected: %s; invalid digest on prepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid digest on prepare message")
		}
	}

	go n.ViewChangeManager.ViewChangeRequestHandler(signedViewChangeMessage)

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
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify view number: must be greater than latest sent view change message view number
	if viewNumber < n.State.GetViewChangeViewNumber() {
		log.Warnf("Rejected: %s; view number is less than latest sent view change message view number", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.FailedPrecondition, "view number is less than latest sent view change message view number")
	}

	// Verify signature
	primaryID := utils.ViewNumberToPrimaryID(viewNumber, n.Handler.N)
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
	err := n.ViewChangeManager.BackupNewViewRequestHandler(signedNewViewMessage)
	if err != nil {
		log.Warnf("New view request %s could not be handled: %s", utils.LoggingString(newViewMessage), err)
		return status.Errorf(codes.Internal, "new view request could not be handled")
	}

	// Route preprepare message to handler and stream prepare messages to primary
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		signedPrepareMessage, err := n.Handler.BackupPrePrepareRequestHandler(signedPrePrepareMessage)
		if err != nil {
			log.Warnf("Prepare request %s could not be sent to primary: %s", utils.LoggingString(signedPrePrepareMessage), err)
			continue
		}
		if err := stream.Send(signedPrepareMessage); err != nil {
			log.Warnf("Prepare message %s could not be sent to primary in stream: %s", utils.LoggingString(signedPrepareMessage), err)
		}
	}
	log.Infof("Streamed prepares messages for view number %d", viewNumber)

	return nil
}

// GetRequest returns a signed transaction request for a given digest
func (n *LinearPBFTNode) GetRequest(ctx context.Context, getRequestMessage *pb.GetRequestMessage) (*pb.SignedTransactionRequest, error) {
	n.Mutex.RLock()
	defer n.Mutex.RUnlock()

	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Byzantine node behavior: dark attack
	if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, getRequestMessage.NodeID) {
		// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, getRequestMessage.NodeID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	digest := getRequestMessage.Digest
	signedRequest := n.State.TransactionMap.Get(digest)
	if signedRequest == nil {
		log.Warnf("Rejected: %s; request not found in transaction map", utils.LoggingString(getRequestMessage))
		return nil, status.Errorf(codes.NotFound, "request not found in transaction map")
	}

	log.Infof("Get request: %s: request %s", utils.LoggingString(getRequestMessage), utils.LoggingString(signedRequest.Request))
	return signedRequest, nil
}
