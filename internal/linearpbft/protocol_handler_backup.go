package linearpbft

import (
	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
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
	h.state.TransactionMap.Set(prePrepareMessage.Digest, signedRequest)

	request := signedRequest.Request

	// Verify Digest
	if !cmp.Equal(prePrepareMessage.Digest, crypto.Digest(signedRequest)) {
		log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prePrepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest")
	}

	// Get or create log record
	h.state.StateLog.CreateRecordIfNotExists(prePrepareMessage.ViewNumber, sequenceNum, digest)
	// record, exists := h.state.StateLog.Get(sequenceNum)
	// if !exists {
	// 	record = CreateLogRecord(prePrepareMessage.ViewNumber, sequenceNum, digest)
	// 	h.state.StateLog.Set(sequenceNum, record)
	// } else if record.ViewNumber < prePrepareMessage.ViewNumber {
	// 	record.Reset(prePrepareMessage.ViewNumber, digest)
	// }

	// Verify if previously accepted preprepare message with different digest for same view and sequence number
	if h.state.StateLog.IsPrePrepared(sequenceNum) && !cmp.Equal(h.state.StateLog.GetDigest(sequenceNum), digest) {
		log.Warnf("Rejected: %s; previously accepted %s", utils.LoggingString(prePrepareMessage, request), utils.LoggingString(h.state.TransactionMap.Get(h.state.StateLog.GetDigest(sequenceNum)).Request))
		return nil, status.Errorf(codes.FailedPrecondition, "previously accepted preprepare message with different digest")
	}

	// Log the preprepare message in record
	log.Infof("Logging preprepare message: %s", utils.LoggingString(prePrepareMessage))
	status := h.state.StateLog.AddPrePrepareMessage(sequenceNum, signedPrePrepareMessage)
	log.Infof("v: %d s: %d status: %s req: %s", prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, status, utils.LoggingString(request))
	// if n.Byzantine && n.CrashAttack {
	// 	record.MaliciousUpdateLogState()
	// }
	// if n.Byzantine && n.CrashAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
	// 	return nil, status.Errorf(codes.Unavailable, "node not alive")
	// }
	h.executeCh <- prePrepareMessage.SequenceNum

	// Create prepare message and sign it
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  prePrepareMessage.ViewNumber,
		SequenceNum: prePrepareMessage.SequenceNum,
		Digest:      prePrepareMessage.Digest,
		NodeID:      h.id,
	}
	signedPrepareMessage := &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: crypto.Sign(prepareMessage, h.privateKey1),
	}
	// // Byzantine node behavior: sign attack
	// if n.Byzantine && n.SignAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
	// 	signedPrepareMessage.Signature = []byte("invalid signature")
	// }

	// // Byzantine node behavior: dark attack
	// if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, prepareMessage.NodeID) {
	// 	// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, prepareMessage.NodeID)
	// 	return nil, status.Errorf(codes.Unavailable, "node not alive")
	// }

	return signedPrepareMessage, nil
	// return nil, nil

}

// BackupPrepareRequestHandler handles the prepare request backup
func (h *ProtocolHandler) BackupPrepareRequestHandler(signedPrepareMessage *pb.SignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	prepareMessage := signedPrepareMessage.Message
	viewNumber := prepareMessage.ViewNumber
	sequenceNum := prepareMessage.SequenceNum
	digest := prepareMessage.Digest

	// Get or create log record
	h.state.StateLog.CreateRecordIfNotExists(viewNumber, sequenceNum, digest)
	// record, exists := h.state.StateLog.Get(sequenceNum)
	// if !exists {
	// 	record = CreateLogRecord(viewNumber, sequenceNum, digest)
	// 	h.state.StateLog.Set(sequenceNum, record)
	// } else if record.ViewNumber < viewNumber {
	// 	record.Reset(viewNumber, digest)
	// }

	// Log the prepare messages in record
	request := h.state.TransactionMap.Get(signedPrepareMessage.Message.Digest).Request
	log.Infof("Logging prepare message: %s", utils.LoggingString(prepareMessage, request))
	status := h.state.StateLog.AddPrepareMessages(sequenceNum, signedPrepareMessage)
	log.Infof("v: %d s: %d status: %s req: %s", viewNumber, sequenceNum, status, utils.LoggingString(request))
	// if n.Byzantine && n.CrashAttack {
	// 	record.MaliciousUpdateLogState()
	// }
	// if n.Byzantine && n.CrashAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
	// 	return nil, status.Errorf(codes.Unavailable, "node not alive")
	// }
	h.executeCh <- sequenceNum

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
	// // Byzantine node behavior: sign attack
	// if n.Byzantine && n.SignAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
	// 	signedCommitMessage.Signature = []byte("invalid signature")
	// }
	// Byzantine node behavior: dark attack
	// if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, commitMessage.NodeID) {
	// 	// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, commitMessage.NodeID)
	// 	return nil, status.Errorf(codes.Unavailable, "node not alive")
	// }

	return signedCommitMessage, nil

}

// BackupCommitRequestHandler handles the commit request backup
func (h *ProtocolHandler) BackupCommitRequestHandler(signedCommitMessage *pb.SignedCommitMessage) (*emptypb.Empty, error) {
	commitMessage := signedCommitMessage.Message
	viewNumber := commitMessage.ViewNumber
	sequenceNum := commitMessage.SequenceNum
	digest := commitMessage.Digest

	// Get or create log record
	h.state.StateLog.CreateRecordIfNotExists(viewNumber, sequenceNum, digest)
	// record, exists := h.state.StateLog.Get(sequenceNum)
	// if !exists {
	// 	record = CreateLogRecord(viewNumber, sequenceNum, digest)
	// 	h.state.StateLog.Set(sequenceNum, record)
	// } else if record.ViewNumber < viewNumber {
	// 	record.Reset(viewNumber, digest)
	// }

	// Log the commit messages in record
	request := h.state.TransactionMap.Get(signedCommitMessage.Message.Digest).Request
	log.Infof("Logging commit message: %s", utils.LoggingString(commitMessage, request))
	status := h.state.StateLog.AddCommitMessages(sequenceNum, signedCommitMessage)
	log.Infof("v: %d s: %d status: %s req: %s", viewNumber, sequenceNum, status, utils.LoggingString(request))
	// if n.Byzantine && n.CrashAttack {
	// 	record.MaliciousUpdateLogState()
	// }
	// if n.Byzantine && n.CrashAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
	// 	return nil, status.Errorf(codes.Unavailable, "node not alive")
	// }
	h.executeCh <- sequenceNum
	return &emptypb.Empty{}, nil
}
