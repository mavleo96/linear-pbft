package linearpbft

import (
	"context"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// RouterRoutine routes messages from components to all nodes
func (n *LinearPBFTNode) RouterRoutine(ctx context.Context) {
	log.Infof("Router routine started")
	for {
		select {
		case <-ctx.Done():
			return

		// Route preprepare message from protocol handler to all backup nodes
		case signedPreprepareMessage := <-n.handler.GetPreprepareToRouteChannel():
			// Multicast preprepare message to all nodes
			responseCh := make(chan *pb.SignedPrepareMessage, len(n.handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()
					log.Infof("Preprepare was sent to node %s: %s", peer.ID, utils.LoggingString(signedPreprepareMessage.Message))
					signedPrepareMsg, err := n.SendPrePrepareToNode(signedPreprepareMessage, peer.ID)
					if err != nil {
						return
					}
					log.Infof("Prepare was sent to collector channel: %s", utils.LoggingString(signedPrepareMsg.Message))
					responseCh <- signedPrepareMsg
				}(peer)
			}

			// Wait for all responses and close the channel
			go func() {
				wg.Wait()
				close(responseCh)
			}()

			// // Collect 2f prepare messages
			go n.CollectPrepareMessages(responseCh)

		// Route prepare message from protocol handler to all backup nodes
		case signedPrepareMessage := <-n.handler.GetPrepareToRouteChannel():
			// Multicast prepare message to all nodes
			responseCh := make(chan *pb.SignedCommitMessage, len(n.handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()
					signedCommitMsg, err := n.SendPrepareToNode(signedPrepareMessage, peer.ID)
					if err != nil {
						return
					}
					responseCh <- signedCommitMsg
				}(peer)
			}
			go func() {
				wg.Wait()
				close(responseCh)
			}()
			// // Collect 2f + 1 matching commit messages including self
			go n.CollectCommitMessages(responseCh)

		// Route commit message from protocol handler to all backup nodes
		case signedCommitMessage := <-n.handler.GetCommitToRouteChannel():
			// Multicast commit message to all nodes
			for _, peer := range n.handler.peers {
				go n.SendCommitToNode(signedCommitMessage, peer.ID)
			}

			// Signal the executor to execute the next sequence number
			n.executor.GetExecutionTriggerChannel() <- 0

		// Route view change message from view change manager to all nodes
		case viewNumber := <-n.viewchanger.GetViewChangeToRouteChannel():
			// NOTE: this should be part of the view change manager
			// but view change manager does not have access to the check point log
			signedViewChangeMessage := n.CreateViewChangeMessage(viewNumber)
			log.Infof("Router routine has logged view change message: %s", utils.LoggingString(signedViewChangeMessage.Message))
			n.viewchanger.AddViewChangeMessage(signedViewChangeMessage)

			// Multicast view change message to all nodes
			log.Infof("Router routine is multicasting view change message to all nodes: %s", utils.LoggingString(signedViewChangeMessage.Message))
			for _, peer := range n.handler.peers {
				go n.SendViewChangeMessageToNode(signedViewChangeMessage, peer.ID)
			}

		// Create New View: Route new view message from view change manager to all nodes
		case viewNumber := <-n.viewchanger.GetNewViewToRouteChannel():
			// Create new view message and route it to the leader handler
			signedNewViewMessage := n.CreateNewViewMessage(viewNumber)
			n.viewchanger.LeaderNewViewRequestHandler(signedNewViewMessage)

			// Multicast new view message to all nodes and collect prepare messages from all nodes
			responseCh := make(chan *pb.SignedPrepareMessage, 100)
			wg := sync.WaitGroup{}
			for _, peer := range n.handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()
					n.SendNewViewMessageToNode(signedNewViewMessage, peer.ID, responseCh)
				}(peer)
			}
			go func() {
				wg.Wait()
				close(responseCh)
			}()

			// Collect prepare messages from all nodes and send to handler
			go n.CollectPrepareMessages(responseCh)

		// Create Check Point: Route check point message from check point manager to all nodes
		case sequenceNum := <-n.executor.checkpointer.GetCheckpointCreateChannel():
			signedCheckpointMessage := n.CreateCheckpointMessage(sequenceNum)
			log.Infof("Router is trying to log check point message: %s", utils.LoggingString(signedCheckpointMessage.Message))
			n.executor.checkpointer.CheckpointMessageHandler(signedCheckpointMessage)

			// Multicast check point message to all nodes
			for _, peer := range n.handler.peers {
				go n.SendCheckpointMessageToNode(signedCheckpointMessage, peer.ID)
			}

		// Install Check Point: Route install check point message from view change manager to executor
		case sequenceNum := <-n.viewchanger.GetCheckpointInstallRequestChannel():
			// If checkpoint is missing then get it from all nodes
			checkpoint, err := n.SendGetCheckpoint(sequenceNum)
			if err != nil {
				log.Fatalf("Failed to get check point for sequence number %d", sequenceNum)
			}
			if checkpoint == nil || checkpoint.Snapshot == nil {
				log.Fatalf("Check point not found or snapshot is nil for sequence number %d", sequenceNum)
			}
			n.executor.checkpointer.AddCheckpoint(sequenceNum, checkpoint.Snapshot)

			// Signal the executor to install the checkpoint
			n.executor.GetCheckpointInstallChannel() <- sequenceNum

		}

	}
}
