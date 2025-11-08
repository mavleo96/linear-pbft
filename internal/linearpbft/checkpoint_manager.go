package linearpbft

import (
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// CheckpointManager is responsible for managing check point messages
type CheckpointManager struct {
	mutex       sync.RWMutex
	id          string
	log         map[int64]map[string]*pb.SignedCheckpointMessage // s -> (id -> msg)
	checkpoints map[int64]*pb.Checkpoint

	state  *ServerState
	config *ServerConfig

	// Channels
	checkpointCreateCh chan int64
	checkpointPurgeCh  chan int64
}

// GetCheckpointCreateChannel returns the channel to create check point messages
func (c *CheckpointManager) GetCheckpointCreateChannel() chan int64 {
	return c.checkpointCreateCh
}

// GetCheckpointPurgeChannel returns the channel to purge checkpoints and messages
func (c *CheckpointManager) GetCheckpointPurgeChannel() chan<- int64 {
	return c.checkpointPurgeCh
}

// AddMessage adds a signed check point message to the log
func (c *CheckpointManager) AddMessage(sequenceNum int64, nodeID string, signedCheckpointMessage *pb.SignedCheckpointMessage) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, ok := c.log[sequenceNum]; !ok {
		c.log[sequenceNum] = make(map[string]*pb.SignedCheckpointMessage)
	}
	c.log[sequenceNum][nodeID] = signedCheckpointMessage
}

// GetMessages gets the signed check point messages for a given sequence number
func (c *CheckpointManager) GetMessages(sequenceNum int64) []*pb.SignedCheckpointMessage {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return utils.Values(c.log[sequenceNum])
}

// DeleteMessages deletes the signed check point messages for a given sequence number
func (c *CheckpointManager) DeleteMessages(sequenceNum int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.log, sequenceNum)
}

// AddCheckpoint adds a checkpoint for a given sequence number
func (c *CheckpointManager) AddCheckpoint(sequenceNum int64, snapshot map[string]int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	digest := crypto.DigestAny(snapshot)
	c.checkpoints[sequenceNum] = &pb.Checkpoint{
		Digest:   digest,
		Snapshot: snapshot,
	}
}

// GetCheckpoint gets the checkpoint for a given sequence number
func (c *CheckpointManager) GetCheckpoint(sequenceNum int64) *pb.Checkpoint {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.checkpoints[sequenceNum]
}

// DeleteCheckpoint deletes the checkpoint for a given sequence number
func (c *CheckpointManager) DeleteCheckpoint(sequenceNum int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.checkpoints, sequenceNum)
}

// Reset resets the checkpoint manager
func (c *CheckpointManager) Reset() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.log = make(map[int64]map[string]*pb.SignedCheckpointMessage)
	c.checkpoints = make(map[int64]*pb.Checkpoint)
}

// CreateCheckpointManager creates a new check point manager
func CreateCheckpointManager(id string, state *ServerState, config *ServerConfig) *CheckpointManager {
	return &CheckpointManager{
		mutex:              sync.RWMutex{},
		id:                 id,
		log:                make(map[int64]map[string]*pb.SignedCheckpointMessage),
		checkpoints:        make(map[int64]*pb.Checkpoint),
		state:              state,
		config:             config,
		checkpointCreateCh: make(chan int64, 5),
		checkpointPurgeCh:  make(chan int64, 5),
	}
}
