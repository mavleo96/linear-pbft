package linearpbft

import (
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// StateLog represents the state log of the server
type StateLog struct {
	mutex sync.RWMutex
	log   map[int64]*LogRecord
}

// LogRecord represents a log record for a transaction
type LogRecord struct {
	viewNumber        int64
	sequenceNum       int64
	digest            []byte
	prePrepared       bool
	prepared          bool
	committed         bool
	executed          bool
	prePrepareMessage *pb.SignedPrePrepareMessage
	prepareMessage    *pb.SignedPrepareMessage
	commitMessage     *pb.SignedCommitMessage
}

func (s *StateLog) AssignSequenceNumberAndCreateRecord(digest []byte) (int64, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if request is already in log record
	for sequenceNum := range s.log {
		record, exists := s.log[sequenceNum]
		if !exists {
			continue
		}
		if record != nil && cmp.Equal(record.digest, digest) {
			return record.sequenceNum, false
		}
	}

	// If request is not in log record, assign new sequence number
	sequenceNum := utils.Max(utils.Keys(s.log)) + 1
	// TODO: -1 is a placeholder for view number, need to change this later
	s.log[sequenceNum] = CreateLogRecord(-1, sequenceNum, digest)
	return sequenceNum, true
}

func (s *StateLog) CreateRecordIfNotExists(viewNumber int64, sequenceNum int64, digest []byte) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, exists := s.log[sequenceNum]; !exists {
		s.log[sequenceNum] = CreateLogRecord(viewNumber, sequenceNum, digest)
		return true
	}
	if s.log[sequenceNum].viewNumber < viewNumber {
		// TODO: need to assert that digest is not different if status is > PP
		s.log[sequenceNum].viewNumber = viewNumber
		s.log[sequenceNum].digest = digest
		return true
	}
	return false
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

// GetDigest returns the digest of a log record for a given sequence number
func (s *StateLog) GetDigest(sequenceNum int64) []byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return nil
	}
	return record.digest
}

// IsPrePrepared returns true if the log record is preprepared
func (s *StateLog) IsPrePrepared(sequenceNum int64) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return false
	}
	return record.prePrepared
}

// IsPrepared returns true if the log record is prepared
func (s *StateLog) IsPrepared(sequenceNum int64) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return false
	}
	return record.prepared
}

// IsCommitted returns true if the log record is committed
func (s *StateLog) IsCommitted(sequenceNum int64) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return false
	}
	return record.committed
}

// IsExecuted returns true if the log record is executed
func (s *StateLog) IsExecuted(sequenceNum int64) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return false
	}
	return record.executed
}

// SetExecuted sets the log record to executed
func (s *StateLog) SetExecuted(sequenceNum int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return
	}
	record.executed = true
}

// AddPrePrepareMessage adds a preprepare message to the log record
func (s *StateLog) AddPrePrepareMessage(sequenceNum int64, signedPrePrepareMessage *pb.SignedPrePrepareMessage) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return ""
	}
	record.prePrepareMessage = signedPrePrepareMessage
	return record.updateLogState()
}

// AddPrepareMessages adds prepare messages to the log record
func (s *StateLog) AddPrepareMessages(sequenceNum int64, prepareMessage *pb.SignedPrepareMessage) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return ""
	}
	record.prepareMessage = prepareMessage
	return record.updateLogState()
}

// AddCommitMessages adds commit messages to the log record
func (s *StateLog) AddCommitMessages(sequenceNum int64, commitMessage *pb.SignedCommitMessage) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return ""
	}
	record.commitMessage = commitMessage
	return record.updateLogState()
}

// GetPrepareProof returns the prepare proofs for all prepared log records
func (s *StateLog) GetPrepareProof() []*pb.PrepareProof {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	prepareProofs := make([]*pb.PrepareProof, 0)
	for sequenceNum := range s.log {
		record, exists := s.log[sequenceNum]
		if !exists {
			continue
		}
		if record.prepared {
			prepareProofs = append(prepareProofs, &pb.PrepareProof{
				SignedPrePrepareMessage: record.prePrepareMessage,
				SignedPrepareMessage:    record.prepareMessage,
			})
		}
	}
	return prepareProofs
}

func (s *StateLog) GetLogRecord(sequenceNum int64) *LogRecord {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return nil
	}
	return record
}

// // Reset resets the log record
// func (l *LogRecord) Reset(viewNumber int64, digest []byte) error {
// 	l.viewNumber = viewNumber
// 	l.prePrepared = false
// 	l.prepared = false
// 	l.committed = false
// 	l.prePrepareMessage = nil
// 	l.prepareMessage = nil
// 	l.commitMessage = nil

// 	if l.executed && !cmp.Equal(l.digest, digest) {
// 		return errors.New("resetting log record with different digest that is already executed")
// 	}
// 	l.digest = digest
// 	return nil
// }

// CreateLogRecord creates a new log record
func CreateLogRecord(viewNumber int64, sequenceNumber int64, digest []byte) *LogRecord {
	return &LogRecord{
		viewNumber:        viewNumber,
		sequenceNum:       sequenceNumber,
		digest:            digest,
		prePrepared:       false,
		prepared:          false,
		committed:         false,
		executed:          false,
		prePrepareMessage: nil,
		prepareMessage:    nil,
		commitMessage:     nil,
	}
}

// updateLogState updates the log state
func (l *LogRecord) updateLogState() string {
	if l.prePrepareMessage == nil {
		return "X"
	}
	l.prePrepared = true
	if l.prepareMessage == nil {
		return "PP"
	}
	l.prepared = true
	if l.commitMessage == nil {
		return "P"
	}
	l.committed = true
	return "C"
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
