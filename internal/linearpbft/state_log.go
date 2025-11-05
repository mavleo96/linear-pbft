package linearpbft

import (
	"errors"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// ServerState represents the state of the server
type ServerState struct {
	mutex                   sync.RWMutex
	viewNumber              int64
	viewChangePhase         bool
	viewChangeViewNumber    int64
	lastExecutedSequenceNum int64

	// Self managed components
	StateLog       *StateLog
	TransactionMap *TransactionMap
}

// GetViewNumber returns the current view number
func (s *ServerState) GetViewNumber() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.viewNumber
}

// SetViewNumber sets the current view number
func (s *ServerState) SetViewNumber(viewNumber int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.viewNumber = viewNumber
}

// IsViewChangePhase returns true if the server is in view change phase
func (s *ServerState) IsViewChangePhase() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.viewChangePhase
}

// SetViewChangePhase sets the view change phase
func (s *ServerState) SetViewChangePhase(viewChangePhase bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.viewChangePhase = viewChangePhase
}

// GetViewChangeViewNumber returns the current view change view number
func (s *ServerState) GetViewChangeViewNumber() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.viewChangeViewNumber
}

// SetViewChangeViewNumber sets the current view change view number
func (s *ServerState) SetViewChangeViewNumber(viewChangeViewNumber int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.viewChangeViewNumber = viewChangeViewNumber
}

// GetLastExecutedSequenceNum returns the last executed sequence number
func (s *ServerState) GetLastExecutedSequenceNum() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.lastExecutedSequenceNum
}

// SetLastExecutedSequenceNum sets the last executed sequence number
func (s *ServerState) SetLastExecutedSequenceNum(lastExecutedSequenceNum int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.lastExecutedSequenceNum = lastExecutedSequenceNum
}

// ---------------------------------------------------------- //

// StateLog represents the state log of the server
type StateLog struct {
	mutex sync.RWMutex
	log   map[int64]*LogRecord
}

// Get returns the log record for a given sequence number
func (s *StateLog) Get(sequenceNum int64) (*LogRecord, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, ok := s.log[sequenceNum]
	return record, ok
}

// Set sets the log record for a given sequence number
func (s *StateLog) Set(sequenceNum int64, logRecord *LogRecord) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.log[sequenceNum] = logRecord
}

// Delete deletes the log record for a given sequence number
func (s *StateLog) Delete(sequenceNum int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.log, sequenceNum)
}

// Keys returns the keys of the log
func (s *StateLog) MaxSequenceNum() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return utils.Max(utils.Keys(s.log))
}

// GetOrAssignSequenceNumber gets the sequence number of a transaction request from the log record
// or assigns a new sequence number to the request
func (s *StateLog) GetOrAssignSequenceNumber(signedRequest *pb.SignedTransactionRequest) (int64, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Compute digest of request
	digest := crypto.Digest(signedRequest)

	// Check if request is already in log record
	for sequenceNum := range s.log {
		record, exists := s.log[sequenceNum]
		if !exists {
			continue
		}
		// TODO: remove this later
		if record == nil {
			log.Fatal("Log record is nil")
		}
		if record != nil && cmp.Equal(record.Digest, digest) {
			return record.SequenceNum, true
		}
	}

	// If request is not in log record, assign new sequence number
	sequenceNum := utils.Max(utils.Keys(s.log)) + 1
	return sequenceNum, false
}

// ---------------------------------------------------------- //

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

// Reset resets the log record
func (l *LogRecord) Reset(viewNumber int64, digest []byte) error {
	l.ViewNumber = viewNumber
	l.prePrepared = false
	l.prepared = false
	l.committed = false
	l.prePrepareMessage = nil
	l.prepareMessages = nil
	l.commitMessages = nil

	if l.executed && !cmp.Equal(l.Digest, digest) {
		return errors.New("resetting log record with different digest that is already executed")
	}
	l.Digest = digest
	return nil
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
	if !l.prePrepared {
		log.Infof("Preprepared (v: %d, s: %d)", l.ViewNumber, l.SequenceNum)
	}
	l.prePrepared = true
	if len(l.prepareMessages) == 0 {
		return
	}
	if !l.prepared {
		log.Infof("Prepared (v: %d, s: %d)", l.ViewNumber, l.SequenceNum)
	}
	l.prepared = true
	if len(l.commitMessages) == 0 {
		return
	}
	if !l.committed {
		log.Infof("Committed (v: %d, s: %d)", l.ViewNumber, l.SequenceNum)
	}
	l.committed = true
}

// ---------------------------------------------------------- //

// TransactionMap represents a map of digest to signed transaction request with a mutex
type TransactionMap struct {
	Mutex sync.RWMutex
	Map   map[[32]byte]*pb.SignedTransactionRequest
}

// Get returns the signed transaction request for a given digest
func (t *TransactionMap) Get(digest []byte) *pb.SignedTransactionRequest {
	t.Mutex.RLock()
	defer t.Mutex.RUnlock()
	return t.Map[utils.To32Bytes(digest)]
}

// Set sets the signed transaction request for a given digest
func (t *TransactionMap) Set(digest []byte, signedRequest *pb.SignedTransactionRequest) {
	t.Mutex.Lock()
	defer t.Mutex.Unlock()
	t.Map[utils.To32Bytes(digest)] = signedRequest
}

// CreateTransactionMap creates a new transaction map
func CreateTransactionMap() *TransactionMap {
	transactionMap := &TransactionMap{
		Mutex: sync.RWMutex{},
		Map:   make(map[[32]byte]*pb.SignedTransactionRequest),
	}
	transactionMap.Set(DigestNoOp, NoOpTransactionRequest)
	return transactionMap
}

// ---------------------------------------------------------- //

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
