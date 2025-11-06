package linearpbft

import (
	"github.com/google/go-cmp/cmp"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ProtocolHandler is a struct that contains the state of the protocol
type ProtocolHandler struct {
	id          string
	state       *ServerState
	privateKey1 *bls.SecretKey
	// privateKey2    *bls.SecretKey
	peers map[string]*models.Node
	F     int64
	N     int64

	// Channels
	executeCh chan int64
	requestCh chan *pb.SignedTransactionRequest
	prepareCh chan []*pb.SignedPrepareMessage
	commitCh  chan []*pb.SignedCommitMessage

	// Functions
	SendPrePrepare func(signedPreprepareMessage *pb.SignedPrePrepareMessage, sequenceNum int64) error
	SendPrepare    func(collectedSignedPrepareMessages *pb.CollectedSignedPrepareMessage) error
	SendCommit     func(collectedSignedCommitMessages *pb.CollectedSignedCommitMessage) error
}

func (h *ProtocolHandler) GetRequestChannel() chan<- *pb.SignedTransactionRequest {
	return h.requestCh
}

func (h *ProtocolHandler) GetPrepareChannel() chan<- []*pb.SignedPrepareMessage {
	return h.prepareCh
}

func (h *ProtocolHandler) GetCommitChannel() chan<- []*pb.SignedCommitMessage {
	return h.commitCh
}

// HandlePrePrepareRequestBackup handles the preprepare request backup
func (h *ProtocolHandler) HandlePrePrepareRequestBackup(signedPrePrepareMessage *pb.SignedPrePrepareMessage) (*pb.SignedPrepareMessage, error) {
	prePrepareMessage := signedPrePrepareMessage.Message
	signedRequest := signedPrePrepareMessage.Request
	sequenceNum := prePrepareMessage.SequenceNum
	digest := prePrepareMessage.Digest

	// Get request if missing
	if signedRequest == nil {
		signedRequest = h.state.TransactionMap.Get(prePrepareMessage.Digest)
	}
	// // if not in transaction map then send a get request to all nodes; if still nil then return error
	// if signedRequest == nil {
	// 	response, err := n.SendGetRequest(prePrepareMessage.Digest)
	// 	if err != nil || response == nil {
	// 		return nil, status.Errorf(codes.FailedPrecondition, "request could not be retrieved from any node")
	// 	}
	// 	signedRequest = response
	// }
	h.state.TransactionMap.Set(prePrepareMessage.Digest, signedRequest)

	request := signedRequest.Request

	// Verify Digest
	if !cmp.Equal(prePrepareMessage.Digest, crypto.Digest(signedRequest)) {
		log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prePrepareMessage, request))
		return nil, status.Errorf(codes.InvalidArgument, "invalid digest")
	}

	// Get or create log record
	record, exists := h.state.StateLog.Get(sequenceNum)
	if !exists {
		record = CreateLogRecord(prePrepareMessage.ViewNumber, sequenceNum, digest)
		h.state.StateLog.Set(sequenceNum, record)
	} else if record.ViewNumber < prePrepareMessage.ViewNumber {
		record.Reset(prePrepareMessage.ViewNumber, digest)
	}

	// Verify if previously accepted preprepare message with different digest for same view and sequence number
	if record.IsPrePrepared() && !cmp.Equal(record.Digest, digest) {
		log.Warnf("Rejected: %s; previously accepted %s", utils.LoggingString(prePrepareMessage, request), utils.LoggingString(h.state.TransactionMap.Get(record.Digest).Request))
		return nil, status.Errorf(codes.FailedPrecondition, "previously accepted preprepare message with different digest")
	}

	// Log the preprepare message in record
	record.AddPrePrepareMessage(signedPrePrepareMessage)
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

func (h *ProtocolHandler) HandlePrepareRequestBackup(collectedSignedPrepareMessages *pb.CollectedSignedPrepareMessage) (*pb.SignedCommitMessage, error) {
	viewNumber := collectedSignedPrepareMessages.ViewNumber
	sequenceNum := collectedSignedPrepareMessages.SequenceNum
	digest := collectedSignedPrepareMessages.Digest

	// Get or create log record
	record, exists := h.state.StateLog.Get(sequenceNum)
	if !exists {
		record = CreateLogRecord(viewNumber, sequenceNum, digest)
		h.state.StateLog.Set(sequenceNum, record)
	} else if record.ViewNumber < viewNumber {
		record.Reset(viewNumber, digest)
	}

	// Log the prepare messages in record
	record.AddPrepareMessages(collectedSignedPrepareMessages.Messages)
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
		Digest:      record.Digest,
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

func (h *ProtocolHandler) HandleCommitRequestBackup(collectedSignedCommitMessages *pb.CollectedSignedCommitMessage) (*emptypb.Empty, error) {
	viewNumber := collectedSignedCommitMessages.ViewNumber
	sequenceNum := collectedSignedCommitMessages.SequenceNum
	digest := collectedSignedCommitMessages.Digest

	// Get or create log record
	record, exists := h.state.StateLog.Get(sequenceNum)
	if !exists {
		record = CreateLogRecord(viewNumber, sequenceNum, digest)
		h.state.StateLog.Set(sequenceNum, record)
	} else if record.ViewNumber < viewNumber {
		record.Reset(viewNumber, digest)
	}

	// Log the commit messages in record
	record.AddCommitMessages(collectedSignedCommitMessages.Messages)
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
