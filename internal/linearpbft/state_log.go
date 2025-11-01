package linearpbft

import (
	"fmt"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// NoOpTransactionRequest is a no-op transaction request
var NoOpTransactionRequest = &pb.TransactionRequest{
	Transaction: &pb.Transaction{
		Type:     "null",
		Sender:   "null",
		Receiver: "null",
		Amount:   0,
	},
	Timestamp: 0,
	Sender:    "null",
}

// LogRecord represents a log record for a transaction
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
}

// IsPrePrepared returns true if the log record is preprepared
func (l *LogRecord) IsPrePrepared() bool {
	return l.prePrepared
}

// IsPrepared returns true if the log record is prepared
func (l *LogRecord) IsPrepared() bool {
	return l.prepared
}

// IsCommitted returns true if the log record is committed
func (l *LogRecord) IsCommitted() bool {
	return l.committed
}

// IsExecuted returns true if the log record is executed
func (l *LogRecord) IsExecuted() bool {
	return l.executed
}

// SetExecuted sets the log record to executed
func (l *LogRecord) SetExecuted() {
	l.executed = true
}

// AddPrePrepareMessage adds a preprepare message to the log record
func (l *LogRecord) AddPrePrepareMessage(signedPrePrepareMessage *pb.SignedPrePrepareMessage) {
	l.prePrepareMessage = signedPrePrepareMessage
	// l.Request = signedPrePrepareMessage.Request
	l.updateLogState()
}

// AddPrepareMessages adds prepare messages to the log record
func (l *LogRecord) AddPrepareMessages(signedPrepareMessages []*pb.SignedPrepareMessage) {
	l.prepareMessages = signedPrepareMessages
	l.updateLogState()
}

// AddCommitMessages adds commit messages to the log record
func (l *LogRecord) AddCommitMessages(signedCommitMessages []*pb.SignedCommitMessage) {
	l.commitMessages = signedCommitMessages
	l.updateLogState()
}

// GetPrepareProof returns the prepare proof for the log record
func (l *LogRecord) GetPrepareProof() *pb.PrepareProof {
	return &pb.PrepareProof{
		SignedPrePrepareMessage: l.prePrepareMessage,
		SignedPrepareMessages:   l.prepareMessages,
	}
}

func (l *LogRecord) Reset(viewNumber int64, digest []byte) {
	l.ViewNumber = viewNumber
	l.prePrepared = false
	l.prepared = false
	l.committed = false
	l.prePrepareMessage = nil
	l.prepareMessages = nil
	l.commitMessages = nil

	if l.executed && !cmp.Equal(l.Digest, digest) {
		log.Fatal("Resetting log record with different digest that is already executed")
	}
	l.Digest = digest
}

func (l *LogRecord) LogString() string {
	return fmt.Sprintf("v: %d, s: %d, (executed: %t)", l.ViewNumber, l.SequenceNum, l.executed)
}

// CreateLogRecord creates a new log record
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

// updateLogState updates the log state
// TODO: should maybe ensure everthing is in same view number
func (l *LogRecord) updateLogState() {
	if l.prePrepareMessage == nil {
		return
	}
	l.prePrepared = true
	log.Infof("Preprepared (v: %d, s: %d)", l.ViewNumber, l.SequenceNum)
	if len(l.prepareMessages) == 0 {
		return
	}
	l.prepared = true
	log.Infof("Prepared (v: %d, s: %d)", l.ViewNumber, l.SequenceNum)
	if len(l.commitMessages) == 0 {
		return
	}
	l.committed = true
	log.Infof("Committed (v: %d, s: %d)", l.ViewNumber, l.SequenceNum)
}

// LastReply represents a map of sender to last sent reply with a mutex
type LastReply struct {
	Mutex    sync.RWMutex
	ReplyMap map[string]*pb.TransactionResponse
}

// Get returns the last reply sent to a sender
func (l *LastReply) Get(sender string) *pb.TransactionResponse {
	l.Mutex.RLock()
	defer l.Mutex.RUnlock()
	return l.ReplyMap[sender]
}

// Update updates the last reply sent to a sender
func (l *LastReply) Update(sender string, reply *pb.TransactionResponse) {
	l.Mutex.Lock()
	defer l.Mutex.Unlock()
	l.ReplyMap[sender] = reply
}
