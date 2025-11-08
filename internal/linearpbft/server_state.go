package linearpbft

import (
	"sync"

	"github.com/google/go-cmp/cmp"
)

// ServerState represents the state of the server
type ServerState struct {
	mutex                   sync.RWMutex
	config                  *ServerConfig
	viewNumber              int64
	viewChangePhase         bool
	viewChangeViewNumber    int64
	lastExecutedSequenceNum int64
	forwardedRequestsLog    [][]byte

	// Self managed components
	StateLog       *StateLog
	TransactionMap *TransactionMap
	LastReply      *LastReply
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

// InViewChangePhase returns true if the server is in view change phase
func (s *ServerState) InViewChangePhase() bool {
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

// AddForwardedRequest adds a forwarded request to the forwarded requests log
func (s *ServerState) AddForwardedRequest(digest []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.forwardedRequestsLog = append(s.forwardedRequestsLog, digest)
}

// InForwardedRequestsLog checks if a request is in the forwarded requests log
func (s *ServerState) InForwardedRequestsLog(digest []byte) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, forwardDigest := range s.forwardedRequestsLog {
		if cmp.Equal(forwardDigest, digest) {
			return true
		}
	}
	return false
}

// ResetForwardedRequestsLog resets the forwarded requests log
func (s *ServerState) ResetForwardedRequestsLog() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.forwardedRequestsLog = make([][]byte, 0)
}

// Reset resets the server state
func (s *ServerState) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.viewNumber = 0
	s.viewChangePhase = false
	s.viewChangeViewNumber = 0
	s.lastExecutedSequenceNum = 0
	s.forwardedRequestsLog = make([][]byte, 0)
	s.StateLog.Reset()
	s.TransactionMap.Reset()
	s.LastReply.Reset()
}

// CreateServerState creates a new server state
func CreateServerState(config *ServerConfig, byzantineConfig *ByzantineConfig) *ServerState {
	return &ServerState{
		mutex:                   sync.RWMutex{},
		config:                  config,
		viewNumber:              0,
		viewChangePhase:         false,
		viewChangeViewNumber:    0,
		lastExecutedSequenceNum: 0,
		forwardedRequestsLog:    make([][]byte, 0),
		StateLog:                CreateStateLog(config, byzantineConfig),
		TransactionMap:          CreateTransactionMap(),
		LastReply:               CreateLastReply(),
	}
}
