package linearpbft

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
)

// StateLog represents the state log of the server
type StateLog struct {
	mutex           sync.RWMutex
	log             map[int64]*LogRecord
	config          *ServerConfig
	byzantineConfig *ByzantineConfig
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
	result            int64
	sbftVerified      map[int64]bool
	prePrepareMessage map[int64]*pb.SignedPrePrepareMessage
	prepareMessage    map[int64]*pb.SignedPrepareMessage
	commitMessage     map[int64]*pb.SignedCommitMessage
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
	s.log[sequenceNum] = createLogRecord(viewNumber, sequenceNum, digest)

	// Byzantine node behavior: equivocation attack
	if s.byzantineConfig.Byzantine && s.byzantineConfig.EquivocationAttack {
		s.log[sequenceNum+1] = createLogRecord(viewNumber, sequenceNum+1, digest)
	}

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
		s.log[sequenceNum].viewNumber = viewNumber
		s.log[sequenceNum].digest = digest
		return true
	}
	return false
}

// Exists returns true if the log record exists for a given sequence number
func (s *StateLog) Exists(sequenceNum int64) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	_, exists := s.log[sequenceNum]
	return exists
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

// GetResult returns the result of a log record; returns -1 if not found
func (s *StateLog) GetResult(sequenceNum int64) int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return -1
	}
	return record.result
}

// SetResult sets the result of a log record
func (s *StateLog) SetResult(sequenceNum int64, result int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return
	}
	record.result = result
}

// AddPrePrepareMessage adds a preprepare message to the log record
func (s *StateLog) AddPrePrepareMessage(sequenceNum int64, signedPrePrepareMessage *pb.SignedPrePrepareMessage) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return "X"
	}
	viewNumber := signedPrePrepareMessage.Message.ViewNumber
	record.prePrepareMessage[viewNumber] = signedPrePrepareMessage
	updateLogState(record, viewNumber)

	// Byzantine node behavior: crash attack
	if s.byzantineConfig.Byzantine && s.byzantineConfig.CrashAttack {
		record.prepared = false
		record.committed = false
	}
	return statusString(record)
}

// AddPrepareMessages adds prepare messages to the log record
func (s *StateLog) AddPrepareMessages(sequenceNum int64, prepareMessage *pb.SignedPrepareMessage, sbftVerified bool) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return "X"
	}
	viewNumber := prepareMessage.Message.ViewNumber
	record.prepareMessage[viewNumber] = prepareMessage
	record.sbftVerified[viewNumber] = sbftVerified
	updateLogState(record, viewNumber)

	// Byzantine node behavior: crash attack
	if s.byzantineConfig.Byzantine && s.byzantineConfig.CrashAttack {
		record.prepared = false
		record.committed = false
	}
	return statusString(record)
}

// AddCommitMessages adds commit messages to the log record
func (s *StateLog) AddCommitMessages(sequenceNum int64, commitMessage *pb.SignedCommitMessage) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return "X"
	}
	viewNumber := commitMessage.Message.ViewNumber
	record.commitMessage[viewNumber] = commitMessage
	updateLogState(record, viewNumber)

	// Byzantine node behavior: crash attack
	if s.byzantineConfig.Byzantine && s.byzantineConfig.CrashAttack {
		record.prepared = false
		record.committed = false
	}
	return statusString(record)
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
			// max view number where preprepare and prepare messages are both available
			viewNumber1 := utils.Keys(record.prepareMessage)
			viewNumber2 := utils.Keys(record.prePrepareMessage)
			viewNumberIntersection := utils.Intersection(viewNumber1, viewNumber2)
			maxViewNumber := utils.Max(viewNumberIntersection)

			prePrepareMessage := record.prePrepareMessage[maxViewNumber]
			prePrepareMessageWithoutPiggyback := &pb.SignedPrePrepareMessage{
				Message:   prePrepareMessage.Message,
				Signature: prePrepareMessage.Signature,
			}
			prepareMessage := record.prepareMessage[maxViewNumber]
			prepareProofs = append(prepareProofs, &pb.PrepareProof{
				SignedPrePrepareMessage: prePrepareMessageWithoutPiggyback,
				SignedPrepareMessage:    prepareMessage,
			})
		}
	}
	return prepareProofs
}

// GetLogString returns the log string for a given sequence number
func (s *StateLog) GetLogString(sequenceNum int64) string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	record, exists := s.log[sequenceNum]
	if !exists {
		return fmt.Sprintf("s: %d, status: X", sequenceNum)
	}
	status := statusString(record)
	return fmt.Sprintf("s: %d, status: %s view: %d, result: %d", sequenceNum, status, record.viewNumber, record.result)
}

// Reset resets the state log
func (s *StateLog) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.log = make(map[int64]*LogRecord)
}

// statusString returns the status string for a given log record
func statusString(record *LogRecord) string {
	if record == nil {
		return "X"
	}
	if record.executed {
		return "E"
	}
	if record.committed {
		return "C"
	}
	if record.prepared {
		return "P"
	}
	if record.prePrepared {
		return "PP"
	}
	return "X"
}

// CreateStateLog creates a new state log
func CreateStateLog(config *ServerConfig, byzantineConfig *ByzantineConfig) *StateLog {
	return &StateLog{
		mutex:           sync.RWMutex{},
		log:             make(map[int64]*LogRecord),
		config:          config,
		byzantineConfig: byzantineConfig,
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
		result:            -1,
		sbftVerified:      make(map[int64]bool),
		prePrepareMessage: make(map[int64]*pb.SignedPrePrepareMessage),
		prepareMessage:    make(map[int64]*pb.SignedPrepareMessage),
		commitMessage:     make(map[int64]*pb.SignedCommitMessage),
	}
}

// updateLogState updates the log state with messages logged in the given view number from a given view number
func updateLogState(record *LogRecord, viewNumber int64) {
	if record.prePrepareMessage[viewNumber] == nil {
		return
	}
	record.prePrepared = true
	if record.prepareMessage[viewNumber] == nil {
		return
	}
	record.prepared = true
	if record.commitMessage[viewNumber] == nil && !record.sbftVerified[viewNumber] {
		return
	}
	record.committed = true
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
		transactionMapString = append(transactionMapString, fmt.Sprintf("%s: %s", hex.EncodeToString(digest[:]), utils.LoggingString(signedRequest)))
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
