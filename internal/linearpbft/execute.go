package linearpbft

import (
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// Executor is responsible for executing transactions and managing check points
type Executor struct {
	mutex               sync.Mutex
	state               *ServerState
	config              *ServerConfig
	db                  *database.Database
	checkpointer        *CheckpointManager
	timer               *SafeTimer
	executionTriggerCh  chan int64
	checkpointInstallCh chan int64
	sendReply           func(signedRequest *pb.SignedTransactionRequest, result int64)
}

// GetExecutionTriggerChannel returns the channel to send execution trigger messages to the executor
func (e *Executor) GetExecutionTriggerChannel() chan<- int64 {
	return e.executionTriggerCh
}

// GetCheckpointInstallChannel returns the channel to send check point install messages to the executor
func (e *Executor) GetCheckpointInstallChannel() chan<- int64 {
	return e.checkpointInstallCh
}

// CreateExecutor creates a new executor
func CreateExecutor(state *ServerState, config *ServerConfig, db *database.Database, checkpointer *CheckpointManager, timer *SafeTimer, executionTriggerCh chan int64) *Executor {
	return &Executor{
		mutex:               sync.Mutex{},
		state:               state,
		config:              config,
		db:                  db,
		checkpointer:        checkpointer,
		timer:               timer,
		executionTriggerCh:  executionTriggerCh,
		checkpointInstallCh: make(chan int64),
	}
}
