package linearpbft

import (
	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/pbft/internal/crypto"
	"github.com/mavleo96/pbft/internal/utils"
	"github.com/mavleo96/pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// BackupPrePrepareRequestHandler handles the preprepare request backup
func (h *ProtocolHandler) BackupPrePrepareRequestHandler(signedPrePrepareMessage *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error) {
	prePrepareMessage := signedPrePrepareMessage.Message
	signedRequest := signedPrePrepareMessage.Request
	sequenceNum := prePrepareMessage.SequenceNum
	digest := prePrepareMessage.Digest

	// Get request if missing
	if signedRequest == nil {
		signedRequest = h.state.TransactionMap.Get(prePrepareMessage.Digest)
	}
	// if not in transaction map then send a get request to all nodes; if still nil then return error
	if signedRequest == nil {
		response, err := h.SendGetRequest(prePrepareMessage.Digest)
		if err != nil || response == nil || response.Request == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "request could not be retrieved from any node")
		}
		signedRequest = response
	}
	log.Infof("Adding request to transaction map: %s", utils.LoggingString(signedRequest))
	h.state.TransactionMap.Set(crypto.Digest(signedRequest), signedRequest)

	// Verify Digest
	if !cmp.Equal(prePrepareMessage.Digest, crypto.Digest(signedRequest)) {
		log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(signedPrePrepareMessage))
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest")
	}

	// Get or create log record
	created := h.state.StateLog.CreateRecordIfNotExists(prePrepareMessage.ViewNumber, sequenceNum, digest)

	// Start timer if new request but not forwarded
	if created && !h.state.InForwardedRequestsLog(digest) && !h.state.StateLog.IsExecuted(sequenceNum) {
		h.timer.IncrementWaitCountOrStart()
	}

	// Verify if previously accepted preprepare message with different digest for same view and sequence number
	if h.state.StateLog.IsPrePrepared(sequenceNum) && !cmp.Equal(h.state.StateLog.GetDigest(sequenceNum), digest) {
		log.Warnf("Rejected: %s; previously accepted %s", utils.LoggingString(signedPrePrepareMessage), utils.LoggingString(h.state.TransactionMap.Get(h.state.StateLog.GetDigest(sequenceNum))))
		return nil, status.Errorf(codes.FailedPrecondition, "previously accepted preprepare message with different digest")
	}

	// Log the preprepare message in record
	log.Infof("Logging preprepare message: %s", utils.LoggingString(signedPrePrepareMessage))
	status := h.state.StateLog.AddPrePrepareMessage(sequenceNum, signedPrePrepareMessage)
	log.Infof("v: %d s: %d status: %s req: %s", prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, status, utils.LoggingString(signedRequest))

	// Trigger execution if new request is committed
	if h.state.StateLog.IsCommitted(sequenceNum) {
		h.executionTriggerCh <- sequenceNum
	}

	// Create prepare message and sign it
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  prePrepareMessage.ViewNumber,
		SequenceNum: prePrepareMessage.SequenceNum,
		Digest:      prePrepareMessage.Digest,
		NodeID:      h.id,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:    prepareMessage,
		Signature:  crypto.Sign(prepareMessage, h.privateKey1),
		Signature2: crypto.Sign(prepareMessage, h.privateKey2),
	}

	// Byzantine node behavior: sign attack
	if h.byzantineConfig.Byzantine && h.byzantineConfig.SignAttack {
		signedPrepareMessage.Signature = []byte("invalid signature")
	}

	return signedPrepareMessage, nil
}

// BackupPrepareRequestHandler handles the prepare request backup
func (h *ProtocolHandler) BackupPrepareRequestHandler(signedPrepareMessage *pb.SignedPrepareMessage, sbftVerified bool) (*pb.SignedCommitMessage, error) {
	prepareMessage := signedPrepareMessage.Message
	viewNumber := prepareMessage.ViewNumber
	sequenceNum := prepareMessage.SequenceNum
	digest := prepareMessage.Digest

	// Get or create log record
	created := h.state.StateLog.CreateRecordIfNotExists(viewNumber, sequenceNum, digest)

	// Start timer if new request but not forwarded
	if created && !h.state.InForwardedRequestsLog(digest) && !h.state.StateLog.IsExecuted(sequenceNum) {
		h.timer.IncrementWaitCountOrStart()
	}

	// Log the prepare messages in record
	log.Infof("Logging prepare message: %s sbftVerified: %t", utils.LoggingString(signedPrepareMessage), sbftVerified)
	status := h.state.StateLog.AddPrepareMessages(sequenceNum, signedPrepareMessage, sbftVerified)
	log.Infof("v: %d s: %d status: %s", viewNumber, sequenceNum, status)

	// Trigger execution if request is committed
	if h.state.StateLog.IsCommitted(sequenceNum) {
		h.executionTriggerCh <- sequenceNum
	}

	// If sbft verified, commit phase is skipped
	if sbftVerified {
		return nil, nil
	}

	// Create commit message and sign it
	commitMessage := &pb.CommitMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      h.state.StateLog.GetDigest(sequenceNum),
		NodeID:      h.id,
	}
	signedCommitMessage := &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: crypto.Sign(commitMessage, h.privateKey1),
	}

	// Byzantine node behavior: sign attack
	if h.byzantineConfig.Byzantine && h.byzantineConfig.SignAttack {
		signedCommitMessage.Signature = []byte("invalid signature")
	}

	return signedCommitMessage, nil
}

// BackupCommitRequestHandler handles the commit request backup
func (h *ProtocolHandler) BackupCommitRequestHandler(signedCommitMessage *pb.SignedCommitMessage) (*emptypb.Empty, error) {
	commitMessage := signedCommitMessage.Message
	viewNumber := commitMessage.ViewNumber
	sequenceNum := commitMessage.SequenceNum
	digest := commitMessage.Digest

	// Get or create log record
	created := h.state.StateLog.CreateRecordIfNotExists(viewNumber, sequenceNum, digest)

	// Start timer if new request but not forwarded
	if created && !h.state.InForwardedRequestsLog(digest) && !h.state.StateLog.IsExecuted(sequenceNum) {
		h.timer.IncrementWaitCountOrStart()
	}

	// Log the commit messages in record
	log.Infof("Logging commit message: %s", utils.LoggingString(signedCommitMessage))
	status := h.state.StateLog.AddCommitMessages(sequenceNum, signedCommitMessage)
	log.Infof("v: %d s: %d status: %s", viewNumber, sequenceNum, status)

	// Trigger execution if request is committed
	if h.state.StateLog.IsCommitted(sequenceNum) {
		h.executionTriggerCh <- sequenceNum
	}

	return &emptypb.Empty{}, nil
}
