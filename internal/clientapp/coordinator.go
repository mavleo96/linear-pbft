package clientapp

import (
	"context"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// Coordinator coordinates the client application
type Coordinator struct {
	clientID  string
	state     *State
	processor *Processor
	collector *ResponseCollector
	nodes     *NodeMap

	// Channels
	testSetCh chan *TestSet
	resetCh   chan bool

	// Context management
	ctx     context.Context    // Current Server Context
	cancel  context.CancelFunc // Function to cancel the current server context
	wg      sync.WaitGroup     // Wait group for the coordinator
	wgReset sync.WaitGroup     // Wait group for the reset handler
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
	go c.Run()

	c.wgReset.Add(1)
	go func() {
		defer c.wgReset.Done()
		c.resetHandler()
	}()
}

// Run runs the coordinator
func (c *Coordinator) Run() {
	// Start collector
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.collector.CollectResponses(c.ctx)
	}()

	// Start transaction loop
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.runTransactionLoop()
	}()
}

// runTransactionLoop runs the transaction loop
func (c *Coordinator) runTransactionLoop() {
	// log.Infof("%s: transaction loop started", c.clientID)
	for {
		select {
		case <-c.ctx.Done():
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
			c.processTestSet(transactions)
			log.Infof("%s: test set %d completed", c.clientID, testSet.SetNumber)
		}
	}
}

// processTestSet processes a test set
func (c *Coordinator) processTestSet(transactions []*pb.Transaction) {
	for _, transaction := range transactions {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		result, err := c.processor.ProcessTransaction(c.ctx, transaction)
		if err != nil {
			log.Warnf("%s -> %s: error processing transaction: %s", c.clientID, utils.LoggingString(transaction), err.Error())
		} else {
			log.Infof("%s -> %s: transaction completed; result: %d", c.clientID, utils.LoggingString(transaction), result)
		}
	}
}

func (c *Coordinator) resetHandler() {
	for {
		<-c.resetCh
		// Cancel current server context and reset state
		c.cancel()
		c.state.Reset()
		c.wg.Wait()

		// Start new server context
		c.ctx, c.cancel = context.WithCancel(context.Background())
		go c.Run()
		log.Infof("%s: reset complete by handler", c.clientID)
		c.resetCh <- true
		log.Infof("%s: reset complete by handler and waiting for next reset", c.clientID)

	}
}

// // Stop stops the coordinator
// func (c *Coordinator) Stop() {
// 	c.cancel()
// 	c.wg.Wait()
// 	c.wgReset.Wait()
// }
