package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/utils"
	log "github.com/sirupsen/logrus"
)

// ViewChangeRoutine is the routine that handles view changes and new views
func (v *ViewChangeManager) ViewChangeRoutine(ctx context.Context) {
	log.Infof("Starting view change routine for %s", v.id)
	for {
		select {
		case <-ctx.Done():
			return

		case viewNumber := <-v.viewChangeTriggerCh:
			// TODO: What if timer expires at this point? -> double view change
			log.Infof("View change request channel signaled")
			// TODO: handle view change request
			// TODO: send view change message to all nodes if f + 1 view change messages are collected
			if viewNumber <= v.state.GetViewChangeViewNumber() {
				log.Infof("View change request channel signaled for view number %d but already in view change phase for view number %d", viewNumber, v.state.GetViewChangeViewNumber())
				continue
			}

			log.Infof("VCN: %d, NEW VCN: %d, Key of VC log: %d", v.state.GetViewChangeViewNumber(), viewNumber, utils.Keys(v.viewChangeLog))
			log.Infof("Node %s is entering view change phase and updated vc to %d", v.id, viewNumber)
			v.state.SetViewChangeViewNumber(viewNumber)
			v.state.SetViewChangePhase(true)
			v.viewChangeToRouteCh <- viewNumber

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
			v.viewChangeToRouteCh <- viewNumber

		case viewNumber := <-v.newViewTriggerCh:
			log.Infof("New view request channel signaled")
			if viewNumber < v.state.GetViewChangeViewNumber() {
				log.Infof("New view request channel signaled for view number %d but already in view change phase for view number %d", viewNumber, v.state.GetViewChangeViewNumber())
				continue
			}
			if utils.ViewNumberToPrimaryID(viewNumber, v.config.N) == v.id {
				log.Infof("Triggering new view to route channel since primary for view number %d", viewNumber)
				v.newViewToRouteCh <- viewNumber
			} else {
				log.Infof("Starting view change timer since new view request channel signaled but not primary for view number %d", viewNumber)
				v.SafeTimer.StartViewTimerIfNotRunning()
			}
		}
	}
}
