package linearpbft

import "sync"

// ServerState represents the state of the server
type ServerState struct {
	mutex                   sync.RWMutex
	viewNumber              int64
	viewChangePhase         bool
	viewChangeViewNumber    int64 // TODO: rename this to latestViewChangeViewNumber
	lastExecutedSequenceNum int64

	// Self managed components
	StateLog       *StateLog
	TransactionMap *TransactionMap
	config         *ServerConfig
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
