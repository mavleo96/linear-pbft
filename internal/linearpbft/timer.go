package linearpbft

import (
	"context"
	"math"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// SafeTimer is a somewhat safe timer wrapper for linearpbft algorithm
type SafeTimer struct {
	mu                 sync.Mutex
	timer              *time.Timer
	executionTimeout   time.Duration
	viewChangeTimeout  time.Duration
	running            bool
	waitCount          int64
	viewChangeTryCount int64
	ctx                context.Context
	cancel             context.CancelFunc
	TimeoutCh          chan bool
}

// CreateSafeTimer creates and initializes a SafeTimer instance.
func CreateSafeTimer(executionTimeout time.Duration, viewChangeTimeout time.Duration) *SafeTimer {
	t := &SafeTimer{
		mu:                 sync.Mutex{},
		timer:              time.NewTimer(executionTimeout),
		executionTimeout:   executionTimeout,
		viewChangeTimeout:  viewChangeTimeout,
		running:            false,
		viewChangeTryCount: 0,
		waitCount:          0,
		TimeoutCh:          make(chan bool),
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
		t.timer.Reset(t.executionTimeout)
		t.running = true
	}
	t.waitCount++
	log.Infof("SafeTimer: Incremented wait count: %d, running: %t", t.waitCount, t.running)
}

// DecrementWaitCountAndResetOrStopIfZero decrements the wait count and resets/stops the timer.
func (t *SafeTimer) DecrementWaitCountAndResetOrStopIfZero() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.viewChangeTryCount = 0
	if t.waitCount > 0 {
		t.waitCount--
	}

	t.timer.Stop()

	if t.waitCount == 0 {
		t.running = false
	} else {
		t.timer.Reset(t.executionTimeout)
	}
	log.Infof("SafeTimer: Decremented wait count: %d, running: %t", t.waitCount, t.running)
}

// StartViewTimerIfNotRunning starts the view change timer if not running
func (t *SafeTimer) StartViewTimerIfNotRunning() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		t.viewChangeTryCount++
		t.timer.Reset(t.getViewChangeTimeout())
		t.running = true
		log.Infof("SafeTimer: Started view timer: %d (%s), running: %t at %d", t.viewChangeTryCount, t.getViewChangeTimeout().String(), t.running, time.Now().UnixMilli())
		return
	}
	log.Infof("SafeTimer: View timer already running: %d, running: %t", t.viewChangeTryCount, t.running)
}

// getViewChangeTimeout returns the view change timeout for the current view change try count
func (t *SafeTimer) getViewChangeTimeout() time.Duration {
	return t.viewChangeTimeout * time.Duration(math.Pow(2, float64(t.viewChangeTryCount)-1))
}

// Cleanup resets the timer and clears all counters.
func (t *SafeTimer) Cleanup() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	stopped := t.timer.Stop()
	t.running = false
	t.waitCount = 0
	t.cancel()
	t.ctx, t.cancel = context.WithCancel(context.Background())
	log.Infof("SafeTimer: Cleanup wait count: %d, running: %t at %d", t.waitCount, t.running, time.Now().UnixMilli())
	return !stopped
}

// run is the internal goroutine that handles timeout events.
func (t *SafeTimer) run() {
	for range t.timer.C {
		log.Infof("SafeTimer: Timer expired at %d", time.Now().UnixMilli())
		t.cancel()
		t.Cleanup()
		t.TimeoutCh <- true
		log.Infof("SafeTimer: Timeout channel signaled at %d", time.Now().UnixMilli())
	}
}

// GetContext returns the timer’s context for cancellation signaling.
func (t *SafeTimer) GetContext() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ctx
}
