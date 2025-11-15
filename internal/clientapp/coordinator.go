package clientapp

import (
	"context"
	"sync"

	"github.com/mavleo96/pbft/pb"
	log "github.com/sirupsen/logrus"
)

// Coordinator coordinates the client application
type Coordinator struct {
	clientID  string
	state     *ClientState
	processor *Processor
	collector *ResponseCollector
	nodes     *NodeMap

	// Channels
	testSetCh chan *TestSet
	resetCh   chan bool

	// Context management
	parentCtx context.Context    // Parent context (for shutdown)
	ctx       context.Context    // Current Server Context
	cancel    context.CancelFunc // Function to cancel the current server context
	wg        sync.WaitGroup     // Wait group for the coordinator
	wgReset   sync.WaitGroup     // Wait group for the reset handler
	mutex     sync.Mutex
}

// GetReceiveTestSetChannel returns the channel for receiving test sets from main thread
func (c *Coordinator) GetReceiveTestSetChannel() chan<- *TestSet {
	return c.testSetCh
}

// GetReceiveResetChannel returns the channel for receiving reset signals from main thread
func (c *Coordinator) GetReceiveResetChannel() chan bool {
	return c.resetCh
}

// Start starts the coordinator
func (c *Coordinator) Start() {
	c.Run()

	// Start reset handler
	c.wgReset.Add(1)
	go func() {
		defer c.wgReset.Done()
		c.resetHandler()
	}()
}

// Run runs the coordinator
func (c *Coordinator) Run() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	ctx := c.ctx

	// Start collector
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.collector.CollectResponses(ctx)
	}()

	// Start transaction loop
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.runTransactionLoop(ctx)
	}()
}

// runTransactionLoop runs the transaction loop
func (c *Coordinator) runTransactionLoop(ctx context.Context) {
	log.Infof("%s: transaction loop started", c.clientID)
	for {
		select {
		case <-ctx.Done():
			log.Infof("%s: received exit signal on transaction loop", c.clientID)
			return
		case testSet := <-c.testSetCh:
			if testSet == nil {
				continue
			}
			transactions := testSet.Transactions[c.clientID]
			if transactions == nil {
				continue
			}
			log.Infof("%s: processing test set %d", c.clientID, testSet.SetNumber)
			c.processTestSet(ctx, transactions)
			log.Infof("%s: test set %d completed", c.clientID, testSet.SetNumber)
		}
	}
}

// processTestSet processes a test set
func (c *Coordinator) processTestSet(ctx context.Context, transactions []*pb.Transaction) {
	for _, transaction := range transactions {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, _ = c.processor.ProcessTransaction(ctx, transaction)
	}
}

func (c *Coordinator) resetHandler() {
	for {
		select {
		case <-c.parentCtx.Done():
			log.Infof("%s: reset handler shutting down", c.clientID)
			return
		case <-c.resetCh:

			c.mutex.Lock()
			c.cancel()
			c.wg.Wait()
			c.state.Reset()
			c.ctx, c.cancel = context.WithCancel(c.parentCtx)

			// drain result channel
		drainLoop:
			for {
				select {
				case <-c.processor.resultCh:
				default:
					break drainLoop
				}
			}
			c.mutex.Unlock()

			// Start new coordinator run after releasing mutex
			c.Run()

			c.resetCh <- true
		}
	}
}

// Stop stops the coordinator and all its components
func (c *Coordinator) Stop() {
	c.mutex.Lock()
	cancel := c.cancel
	c.mutex.Unlock()

	if cancel != nil {
		cancel()
	}

	// Wait for all coordinator goroutines to finish
	c.wg.Wait()

	// Wait for reset handler to finish
	c.wgReset.Wait()

	log.Infof("%s: coordinator stopped", c.clientID)
}
