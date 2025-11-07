package linearpbft

import (
	"context"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
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

	// Channels
	viewChangeRequestCh chan bool
	newViewRequestCh    chan bool
	viewChangeRouterCh  chan int64
	newViewRouterCh     chan int64
}

// GetViewChangeChannel returns the channel to receive view change messages in router routine
func (v *ViewChangeManager) GetViewChangeChannel() <-chan int64 {
	return v.viewChangeRouterCh
}

// GetNewViewChannel returns the channel to receive new view messages in router routine
func (v *ViewChangeManager) GetNewViewChannel() <-chan int64 {
	return v.newViewRouterCh
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

// ViewChangeRoutine is the routine that handles view changes and new views
func (v *ViewChangeManager) ViewChangeRoutine(ctx context.Context) {
	log.Infof("Starting view change routine for %s", v.id)
	for {
		select {
		case <-ctx.Done():
			return

		case <-v.viewChangeRequestCh:
			// TODO: What if timer expires at this point? -> double view change
			log.Infof("View change request channel signaled")
			// TODO: handle view change request
			// TODO: send view change message to all nodes if f + 1 view change messages are collected

			// Get smallest view number of the logged view change messages which is higher than latest sent view change message view number
			viewNumber := v.state.GetViewChangeViewNumber() + 1
			maxViewNumber := utils.Max(utils.Keys(v.viewChangeLog))
			for i := viewNumber; i <= maxViewNumber; i++ {
				if _, ok := v.viewChangeLog[i]; ok {
					viewNumber = i
					break
				}
			}
			log.Infof("VCN: %d, NEW VCN: %d, Key of VC log: %d", v.state.GetViewChangeViewNumber(), viewNumber, utils.Keys(v.viewChangeLog))
			log.Infof("Node %s is entering view change phase and updated vc to %d", v.id, viewNumber)
			v.state.SetViewChangeViewNumber(viewNumber)
			v.state.SetViewChangePhase(true)
			v.viewChangeRouterCh <- viewNumber

		case <-v.SafeTimer.TimeoutCh:
			log.Infof("View change routine: Timer expired at v %d vc %d", v.state.GetViewNumber(), v.state.GetViewChangeViewNumber())

			// Get smallest view number of the logged view change messages which is higher than latest sent view change message view number
			viewNumber := v.state.GetViewChangeViewNumber() + 1
			maxViewNumber := utils.Max(utils.Keys(v.viewChangeLog))
			for i := viewNumber; i <= maxViewNumber; i++ {
				if _, ok := v.viewChangeLog[i]; ok {
					viewNumber = i
					break
				}
			}
			log.Infof("VCN: %d, NEW VCN: %d, Key of VC log: %d", v.state.GetViewChangeViewNumber(), viewNumber, utils.Keys(v.viewChangeLog))
			log.Infof("Node %s is entering view change phase and updated vc to %d", v.id, viewNumber)
			v.state.SetViewChangeViewNumber(viewNumber)
			v.state.SetViewChangePhase(true)
			v.viewChangeRouterCh <- viewNumber

		case <-v.newViewRequestCh:
			log.Infof("New view request channel signaled")
			v.newViewRouterCh <- v.state.GetViewChangeViewNumber()
		}
	}
}
