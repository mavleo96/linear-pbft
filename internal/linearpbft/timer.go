package linearpbft

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// SafeTimer is a somewhat safe timer wrapper for linearpbft algorithm
type SafeTimer struct {
	mu        sync.Mutex
	timer     *time.Timer
	timeout   time.Duration
	running   bool
	waitCount int64

	ctx       context.Context
	cancel    context.CancelFunc
	TimeoutCh chan bool
}

// CreateSafeTimer creates and initializes a SafeTimer instance.
func CreateSafeTimer(timeout time.Duration) *SafeTimer {
	t := &SafeTimer{
		timer:     time.NewTimer(timeout),
		timeout:   timeout,
		TimeoutCh: make(chan bool),
	}
	t.timer.Stop()
	t.ctx, t.cancel = context.WithCancel(context.Background())
	go t.run()
	return t
}

// IncrementWaitCountOrStart increments the wait count or starts the timer.
func (t *SafeTimer) IncrementWaitCountOrStart() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		t.timer.Reset(t.timeout)
		t.running = true
	}
	t.waitCount++
	log.Infof("SafeTimer: Incremented wait count: %d, running: %t", t.waitCount, t.running)
}

// DecrementWaitCountAndResetOrStopIfZero decrements the wait count and resets/stops the timer.
func (t *SafeTimer) DecrementWaitCountAndResetOrStopIfZero() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.waitCount > 0 {
		t.waitCount--
	}

	t.timer.Stop()

	if t.waitCount == 0 {
		t.running = false
	} else {
		t.timer.Reset(t.timeout)
	}
	log.Infof("SafeTimer: Decremented wait count: %d, running: %t", t.waitCount, t.running)
}

// Cleanup resets the timer and clears all counters.
func (t *SafeTimer) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.timer.Stop()
	t.running = false
	t.waitCount = 0
	t.cancel()
	t.ctx, t.cancel = context.WithCancel(context.Background())
	log.Infof("SafeTimer: Cleanup wait count: %d, running: %t", t.waitCount, t.running)
}

// run is the internal goroutine that handles timeout events.
func (t *SafeTimer) run() {
	for range t.timer.C {
		t.cancel()
		t.Cleanup()
		log.Infof("SafeTimer: Timer expired")
		t.TimeoutCh <- true
		log.Infof("SafeTimer: Timeout channel signaled")
	}
}

// GetContext returns the timer’s context for cancellation signaling.
func (t *SafeTimer) GetContext() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ctx
}
