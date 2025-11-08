package linearpbft

import (
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// ViewChangeManager is responsible for managing view changes and new views
type ViewChangeManager struct {
	id            string
	mutex         sync.RWMutex
	viewChangeLog map[int64]map[string]*pb.SignedViewChangeMessage
	newViewLog    map[int64]*pb.SignedNewViewMessage
	SafeTimer     *SafeTimer
	state         *ServerState
	config        *ServerConfig
	checkpointer  *CheckpointManager

	// Channels
	viewChangeTriggerCh        chan int64
	newViewTriggerCh           chan int64
	viewChangeToRouteCh        chan int64
	newViewToRouteCh           chan int64
	checkpointInstallRequestCh chan int64

	// Functions
	SendGetCheckpoint func(sequenceNum int64) (*pb.Checkpoint, error)
}

// GetViewChangeToRouteChannel returns the channel to send view change messages to route
func (v *ViewChangeManager) GetViewChangeToRouteChannel() <-chan int64 {
	return v.viewChangeToRouteCh
}

// GetNewViewToRouteChannel returns the channel to send new view messages to route
func (v *ViewChangeManager) GetNewViewToRouteChannel() <-chan int64 {
	return v.newViewToRouteCh
}

// GetCheckpointInstallRequestChannel returns the channel to send check point install request messages to executor
func (v *ViewChangeManager) GetCheckpointInstallRequestChannel() <-chan int64 {
	return v.checkpointInstallRequestCh
}

// AddViewChangeMessage adds a signed view change message to the view change log
func (v *ViewChangeManager) AddViewChangeMessage(signedViewChangeMessage *pb.SignedViewChangeMessage) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber
	if _, ok := v.viewChangeLog[viewNumber]; !ok {
		v.viewChangeLog[viewNumber] = make(map[string]*pb.SignedViewChangeMessage)
	}
	v.viewChangeLog[viewNumber][viewChangeMessage.NodeID] = signedViewChangeMessage
}

// GetViewChangeMessages returns the signed view change messages for a given view number
func (v *ViewChangeManager) GetViewChangeMessages(viewNumber int64) []*pb.SignedViewChangeMessage {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return utils.Values(v.viewChangeLog[viewNumber])
}

// AddNewViewMessage adds a signed new view message to the new view log
func (v *ViewChangeManager) AddNewViewMessage(signedNewViewMessage *pb.SignedNewViewMessage) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	newViewMessage := signedNewViewMessage.Message
	viewNumber := newViewMessage.ViewNumber
	v.newViewLog[viewNumber] = signedNewViewMessage
}

// GetViewChangeLogKeys returns the keys of the view change log
func (v *ViewChangeManager) GetViewChangeLogKeys() []int64 {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return utils.Keys(v.viewChangeLog)
}

// Reset resets the view change manager
func (v *ViewChangeManager) Reset() {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	v.viewChangeLog = make(map[int64]map[string]*pb.SignedViewChangeMessage)
	v.newViewLog = make(map[int64]*pb.SignedNewViewMessage)
}

// CreateViewChangeManager creates a new view change manager
func CreateViewChangeManager(id string, safeTimer *SafeTimer, state *ServerState, config *ServerConfig, checkpointer *CheckpointManager) *ViewChangeManager {
	return &ViewChangeManager{
		id:            id,
		mutex:         sync.RWMutex{},
		viewChangeLog: make(map[int64]map[string]*pb.SignedViewChangeMessage),
		newViewLog:    make(map[int64]*pb.SignedNewViewMessage),
		SafeTimer:     safeTimer,
		state:         state,
		config:        config,
		checkpointer:  checkpointer,

		// Should trigger channels be non-buffered instead of buffered?
		viewChangeTriggerCh:        make(chan int64, 5),
		newViewTriggerCh:           make(chan int64, 5),
		viewChangeToRouteCh:        make(chan int64, 5),
		newViewToRouteCh:           make(chan int64, 5),
		checkpointInstallRequestCh: make(chan int64, 5),
	}
}
