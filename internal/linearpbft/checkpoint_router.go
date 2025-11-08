package linearpbft

import (
	"context"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

// CheckpointRoutine is the routine that handles check point messages
func (c *CheckpointManager) CheckpointRoutine(ctx context.Context) {
checkpointingLoop:
	for {
		select {
		case <-ctx.Done():
			log.Infof("Checkpoint routine received exit signal")
			return

		case sequenceNum := <-c.checkpointRequestCh:
			log.Infof("Received signal to start check point routine for sequence number %d", sequenceNum)

			// Create checkpoint digest and verify the digest on check point messages
			checkpoint := c.GetCheckpoint(sequenceNum)
			checkpointDigest := checkpoint.Digest
			verifiedCount := 0
			for _, checkpointMessage := range c.GetMessages(sequenceNum) {
				if cmp.Equal(checkpointMessage.Message.Digest, checkpointDigest) {
					verifiedCount++
				}
			}
			if verifiedCount < int(2*c.config.F+1) {
				log.Warnf("Check point digest not verified for sequence number %d", sequenceNum)
				continue checkpointingLoop
			}

			// Update low and high water mark and purge log records
			log.Infof("Purging logs for sequence number %d", sequenceNum)
			delta := sequenceNum - c.config.GetLowWaterMark()
			c.config.IncreaseWaterMark(delta)
			for i := c.config.GetLowWaterMark() - delta + 1; i <= c.config.GetLowWaterMark(); i++ {
				c.state.StateLog.Delete(i)
			}
			log.Infof("Updated low and high water mark to %d and %d", c.config.GetLowWaterMark(), c.config.GetHighWaterMark())

			// Delete check point messages and checkpoints older than low water mark
			for i := range c.log {
				if i < c.config.GetLowWaterMark() {
					c.DeleteMessages(i)
				}
			}
			for i := range c.checkpoints {
				if i < c.config.GetLowWaterMark() {
					c.DeleteCheckpoint(i)
				}
			}
		}
	}
}
