package linearpbft

import "sync"

// ServerConfig is the configuration for the server
type ServerConfig struct {
	mutex         sync.RWMutex
	lowWaterMark  int64
	highWaterMark int64
	K             int64
	N             int64
	F             int64
}

// GetLowWaterMark returns the low water mark
func (sc *ServerConfig) GetLowWaterMark() int64 {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	return sc.lowWaterMark
}

// GetHighWaterMark returns the high water mark
func (sc *ServerConfig) GetHighWaterMark() int64 {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	return sc.highWaterMark
}

// IncreaseWaterMark increases the water mark by a given delta
func (sc *ServerConfig) IncreaseWaterMark(delta int64) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	sc.lowWaterMark += delta
	sc.highWaterMark += delta
}

// SequenceNumberInRange checks if a sequence number is in range
func (sc *ServerConfig) SequenceNumberInRange(sequenceNum int64) bool {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	return sequenceNum > sc.lowWaterMark && sequenceNum <= sc.highWaterMark
}

// CreateServerConfig creates a new server configuration
func CreateServerConfig(n int64, k int64, l int64) *ServerConfig {
	return &ServerConfig{
		mutex:         sync.RWMutex{},
		lowWaterMark:  0,
		highWaterMark: l,
		K:             k,
		N:             n,
		F:             (n - 1) / 3,
	}
}
