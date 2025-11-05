package clientapp

import "sync"

// State represents the state of the client application
type State struct {
	currentTimestamp  int64
	currentViewNumber int64
	responseMap       map[string]int64
	mutex             sync.RWMutex
}

// GetViewNumber returns the current view number
func (s *State) GetViewNumber() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.currentViewNumber
}

// GetTimestamp returns the current timestamp
func (s *State) GetTimestamp() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.currentTimestamp
}

// GetResponseMap returns the response map
func (s *State) GetResponseMap() map[string]int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.responseMap
}

// UpdateTimestamp sets the current timestamp
func (s *State) UpdateTimestamp(timestamp int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.currentTimestamp = timestamp
}

// UpdateViewNumber sets the current view number
func (s *State) UpdateViewNumber(viewNumber int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.currentViewNumber = viewNumber
}

// ResetResponseMap resets the response map
func (s *State) ResetResponseMap() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.responseMap = make(map[string]int64)
}

// AddResponse adds a response to the response map
func (s *State) AddResponse(nodeID string, result int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.responseMap[nodeID] = result
}

// Reset resets the state
func (s *State) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.currentTimestamp = 0
	s.currentViewNumber = 0
	s.responseMap = make(map[string]int64)
}
