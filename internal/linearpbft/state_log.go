package linearpbft

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// StateLog represents the state log of the server
type StateLog struct {
	mutex  sync.RWMutex
	log    map[int64]*LogRecord
	config *ServerConfig
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

// GetSequenceNumberByDigest returns the sequence number of a log record for a given digest and returns 0 if not found
func (s *StateLog) GetSequenceNumberByDigest(digest []byte) int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for sequenceNum := range s.log {
		record, exists := s.log[sequenceNum]
		if !exists {
			continue
		}
		if cmp.Equal(record.digest, digest) {
			return record.sequenceNum
		}
	}
	return 0
}

// AssignSequenceNumberAndCreateRecord assigns a sequence number to a log record for a given digest and creates a new log record if not found
func (s *StateLog) AssignSequenceNumberAndCreateRecord(viewNumber int64, digest []byte) (int64, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if request is already in log record
	for sequenceNum := range s.log {
		record, exists := s.log[sequenceNum]
		if !exists {
			continue
		}
		if record != nil && cmp.Equal(record.digest, digest) {
			if record.viewNumber < viewNumber {
				record.viewNumber = viewNumber
				return record.sequenceNum, true
			}
			return record.sequenceNum, false
		}
	}

	// If request is not in log record, assign new sequence number
	sequenceNum := s.config.GetLowWaterMark() + 1
	if utils.Max(utils.Keys(s.log)) != 0 {
		sequenceNum = utils.Max(utils.Keys(s.log)) + 1
	}
	// TODO: -1 is a placeholder for view number, need to change this later
	s.log[sequenceNum] = createLogRecord(viewNumber, sequenceNum, digest)
	return sequenceNum, true
}

// CreateRecordIfNotExists creates a new log record if not found
func (s *StateLog) CreateRecordIfNotExists(viewNumber int64, sequenceNum int64, digest []byte) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, exists := s.log[sequenceNum]; !exists {
		s.log[sequenceNum] = createLogRecord(viewNumber, sequenceNum, digest)
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
	if utils.Max(utils.Keys(s.log)) == 0 {
		return s.config.GetLowWaterMark()
	}
	return utils.Max(utils.Keys(s.log))
}

// GetViewNumber returns the view number of a log record for a given sequence number
func (s *StateLog) GetViewNumber(sequenceNum int64) int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return 0
	}
	return record.viewNumber
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
	return updateLogState(record)
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
	return updateLogState(record)
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
	return updateLogState(record)
}

// GetPrepareProof returns the prepare proofs for all prepared log records
func (s *StateLog) GetPrepareProof() []*pb.PrepareProof {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	prepareProofs := make([]*pb.PrepareProof, 0)
	for sequenceNum := utils.Min(utils.Keys(s.log)); sequenceNum <= utils.Max(utils.Keys(s.log)); sequenceNum++ {
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

// GetLogRecord returns the log record for a given sequence number
func (s *StateLog) GetLogRecord(sequenceNum int64) *LogRecord {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return nil
	}
	return record
}

// Reset resets the state log
func (s *StateLog) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.log = make(map[int64]*LogRecord)
}

// CreateStateLog creates a new state log
func CreateStateLog(config *ServerConfig) *StateLog {
	return &StateLog{
		mutex:  sync.RWMutex{},
		log:    make(map[int64]*LogRecord),
		config: config,
	}
}

// CreateLogRecord creates a new log record
func createLogRecord(viewNumber int64, sequenceNumber int64, digest []byte) *LogRecord {
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
func updateLogState(record *LogRecord) string {
	if record.prePrepareMessage == nil {
		return "X"
	}
	record.prePrepared = true
	if record.prepareMessage == nil {
		return "PP"
	}
	record.prepared = true
	if record.commitMessage == nil {
		return "P"
	}
	record.committed = true
	if !record.executed {
		return "C"
	}
	return "E"
}

// ---------------------------------------------------------- //

// TransactionMap represents a map of digest to signed transaction request with a mutex
type TransactionMap struct {
	mutex      sync.RWMutex
	requestMap map[[32]byte]*pb.SignedTransactionRequest
}

// Get returns the signed transaction request for a given digest
func (t *TransactionMap) Get(digest []byte) *pb.SignedTransactionRequest {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.requestMap[utils.To32Bytes(digest)]
}

// Set sets the signed transaction request for a given digest
func (t *TransactionMap) Set(digest []byte, signedRequest *pb.SignedTransactionRequest) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.requestMap[utils.To32Bytes(digest)] = signedRequest
}

// Reset resets the transaction map
func (t *TransactionMap) Reset() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.requestMap = make(map[[32]byte]*pb.SignedTransactionRequest)
	t.requestMap[utils.To32Bytes(DigestNoOp)] = NoOpTransactionRequest
}

// CreateTransactionMap creates a new transaction map
func CreateTransactionMap() *TransactionMap {
	transactionMap := &TransactionMap{
		mutex:      sync.RWMutex{},
		requestMap: make(map[[32]byte]*pb.SignedTransactionRequest),
	}
	transactionMap.Set(DigestNoOp, NoOpTransactionRequest)
	return transactionMap
}

func (t *TransactionMap) LogString() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	transactionMapString := make([]string, 0)
	for digest, signedRequest := range t.requestMap {
		transactionMapString = append(transactionMapString, fmt.Sprintf("%s: %s", hex.EncodeToString(digest[:]), utils.LoggingString(signedRequest.Request)))
	}
	return strings.Join(transactionMapString, "\n")
}

// ---------------------------------------------------------- //

// LastReply represents a map of sender to last sent reply with a mutex
type LastReply struct {
	mutex    sync.RWMutex
	replyMap map[string]*pb.TransactionResponse
}

// Get returns the last reply sent to a sender
func (l *LastReply) Get(sender string) *pb.TransactionResponse {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.replyMap[sender]
}

// Update updates the last reply sent to a sender
func (l *LastReply) Update(sender string, reply *pb.TransactionResponse) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.replyMap[sender] = reply
}

// Reset resets the last reply
func (l *LastReply) Reset() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.replyMap = make(map[string]*pb.TransactionResponse)
}

// CreateLastReply creates a new last reply
func CreateLastReply() *LastReply {
	return &LastReply{
		mutex:    sync.RWMutex{},
		replyMap: make(map[string]*pb.TransactionResponse),
	}
}
