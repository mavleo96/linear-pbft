package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

type LogRecord struct {
	ViewNumber        int64
	SequenceNum       int64
	Digest            []byte
	prePrepared       bool
	prepared          bool
	committed         bool
	executed          bool
	prePrepareMessage *pb.SignedPrePrepareMessage
	prepareMessages   []*pb.SignedPrepareMessage
	commitMessages    []*pb.SignedCommitMessage
	Request           *pb.TransactionRequest
}

func (l *LogRecord) IsPrePrepared() bool {
	return l.prePrepared
}

func (l *LogRecord) IsPrepared() bool {
	return l.prepared
}

func (l *LogRecord) IsCommitted() bool {
	return l.committed
}

func (l *LogRecord) IsExecuted() bool {
	return l.executed
}

func (l *LogRecord) SetExecuted() {
	l.executed = true
}

func (l *LogRecord) updateLogState() {
	if l.prePrepareMessage == nil {
		return
	}
	l.prePrepared = true
	log.Infof("Preprepared (v: %d, s: %d): %s", l.ViewNumber, l.SequenceNum, utils.LoggingString(l.Request))
	if len(l.prepareMessages) == 0 {
		return
	}
	l.prepared = true
	log.Infof("Prepared (v: %d, s: %d): %s", l.ViewNumber, l.SequenceNum, utils.LoggingString(l.Request))
	if len(l.commitMessages) == 0 {
		return
	}
	l.committed = true
	log.Infof("Committed (v: %d, s: %d): %s", l.ViewNumber, l.SequenceNum, utils.LoggingString(l.Request))
}

func (l *LogRecord) AddPrePrepareMessage(signedPrePrepareMessage *pb.SignedPrePrepareMessage) {
	l.prePrepareMessage = signedPrePrepareMessage
	l.Request = signedPrePrepareMessage.Request
	l.updateLogState()

	// TODO: should you verify the digest of the preprepare message?
}

func (l *LogRecord) AddPrepareMessages(signedPrepareMessages []*pb.SignedPrepareMessage) {
	l.prepareMessages = signedPrepareMessages
	l.updateLogState()
}

func (l *LogRecord) AddCommitMessages(signedCommitMessages []*pb.SignedCommitMessage) {
	l.commitMessages = signedCommitMessages
	l.updateLogState()
}

func (l *LogRecord) GetPrepareProof() *pb.PrepareProof {
	return &pb.PrepareProof{
		SignedPrePrepareMessage: l.prePrepareMessage,
		SignedPrepareMessages:   l.prepareMessages,
	}
}

func CreateLogRecord(viewNumber int64, sequenceNumber int64, digest []byte) *LogRecord {
	return &LogRecord{
		ViewNumber:        viewNumber,
		SequenceNum:       sequenceNumber,
		Digest:            digest,
		prePrepared:       false,
		prepared:          false,
		committed:         false,
		executed:          false,
		prePrepareMessage: nil,
		prepareMessages:   nil,
		commitMessages:    nil,
	}
}
