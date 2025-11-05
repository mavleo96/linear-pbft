package clientapp

import "sync"

// State represents the state of the client application
type ClientState struct {
	currentTimestamp  int64
	currentViewNumber int64
	responseMap       map[string]Result
	mutex             sync.RWMutex
}

type Result struct {
	ViewNumber int64
	Result     int64
}

// GetViewNumber returns the current view number
func (s *ClientState) GetViewNumber() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.currentViewNumber
}

// GetTimestamp returns the current timestamp
func (s *ClientState) GetTimestamp() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.currentTimestamp
}

// GetResponseMap returns the response map
func (s *ClientState) GetResponseMap() map[string]Result {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.responseMap
}

// UpdateTimestamp sets the current timestamp
func (s *ClientState) UpdateTimestamp(timestamp int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.currentTimestamp = timestamp
}

// UpdateViewNumber sets the current view number
func (s *ClientState) UpdateViewNumber(viewNumber int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.currentViewNumber = viewNumber
}

// ResetResponseMap resets the response map
func (s *ClientState) ResetResponseMap() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.responseMap = make(map[string]Result)
}

// AddResponse adds a response to the response map
func (s *ClientState) AddResponse(nodeID string, response Result) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.responseMap[nodeID] = response
}

// Reset resets the state
func (s *ClientState) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.currentTimestamp = 0
	s.currentViewNumber = 0
	s.responseMap = make(map[string]Result)
}
