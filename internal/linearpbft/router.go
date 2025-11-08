package linearpbft

import (
	"context"
	"slices"
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
			// Logger: add sent preprepare message
			n.logger.AddSentPrePrepareMessage(signedPreprepareMessage)

			// Multicast preprepare message to all nodes
			responseCh := make(chan *pb.SignedPrepareMessage, len(n.handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()

					// Byzantine node behavior: equivocation attack
					if n.byzantineConfig.Byzantine && n.byzantineConfig.EquivocationAttack && !slices.Contains(n.byzantineConfig.EquivocationAttackNodes, peer.ID) {
						return
					}

					log.Infof("Preprepare was sent to node %s: %s", peer.ID, utils.LoggingString(signedPreprepareMessage))
					signedPrepareMsg, err := n.SendPrePrepareToNode(signedPreprepareMessage, peer.ID)
					if err != nil {
						return
					}
					log.Infof("Prepare was sent to collector channel: %s", utils.LoggingString(signedPrepareMsg))
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

		// Route equivocation preprepare message from handler to attacked backup nodes
		case signedPreprepareMessage := <-n.byzantineConfig.GetEquivocationPrePrepareToRouteChannel():
			// Logger: add sent preprepare message
			n.logger.AddSentPrePrepareMessage(signedPreprepareMessage)

			// Multicast equivocation preprepare message to other nodes
			responseCh := make(chan *pb.SignedPrepareMessage, len(n.handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()

					// Byzantine node behavior: equivocation attack
					if n.byzantineConfig.Byzantine && n.byzantineConfig.EquivocationAttack && slices.Contains(n.byzantineConfig.EquivocationAttackNodes, peer.ID) {
						return
					}

					log.Infof("Equivocation preprepare was sent to node %s: %s", peer.ID, utils.LoggingString(signedPreprepareMessage))
					signedPrepareMsg, err := n.SendPrePrepareToNode(signedPreprepareMessage, peer.ID)
					if err != nil {
						return
					}
					log.Infof("Prepare was sent to collector channel: %s", utils.LoggingString(signedPrepareMsg))
					responseCh <- signedPrepareMsg
				}(peer)
			}

			// Wait for all responses and close the channel
			go func() {
				wg.Wait()
				close(responseCh)
			}()

			// Collect 2f prepare messages
			go n.CollectPrepareMessages(responseCh)

		// Route prepare message from protocol handler to all backup nodes
		case signedPrepareMessage := <-n.handler.GetPrepareToRouteChannel():
			// Logger: add sent aggregated prepare message
			n.logger.AddSentAggregatedPrepareMessage(signedPrepareMessage)

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

		// SBFT Prepare Route: Prepares are sent to all nodes without collecting commit messages
		case signedPrepareMessage := <-n.handler.GetSBFTPrepareToRouteChannel():
			// Logger: add sent aggregated prepare message
			n.logger.AddSentAggregatedPrepareMessage(signedPrepareMessage)

			// Multicast sbft prepare message to all nodes
			for _, peer := range n.handler.peers {
				go n.SendPrepareToNode(signedPrepareMessage, peer.ID)
			}

			n.executor.GetExecutionTriggerChannel() <- signedPrepareMessage.Message.SequenceNum

		// Route commit message from protocol handler to all backup nodes
		case signedCommitMessage := <-n.handler.GetCommitToRouteChannel():
			// Logger: add sent aggregated commit message
			n.logger.AddSentAggregatedCommitMessage(signedCommitMessage)

			// Multicast commit message to all nodes
			for _, peer := range n.handler.peers {
				go n.SendCommitToNode(signedCommitMessage, peer.ID)
			}

			// Signal the executor to execute the next sequence number
			n.executor.GetExecutionTriggerChannel() <- signedCommitMessage.Message.SequenceNum

		// Route view change message from view change manager to all nodes
		case viewNumber := <-n.viewchanger.GetViewChangeToRouteChannel():
			signedViewChangeMessage := n.CreateViewChangeMessage(viewNumber)
			n.viewchanger.ViewChangeMessageHandler(signedViewChangeMessage)

			// Logger: add sent view change message
			n.logger.AddSentViewChangeMessage(signedViewChangeMessage)

			// Multicast view change message to all nodes
			log.Infof("Router routine is multicasting view change message to all nodes: %s", utils.LoggingString(signedViewChangeMessage))
			for _, peer := range n.handler.peers {
				go n.SendViewChangeMessageToNode(signedViewChangeMessage, peer.ID)
			}

		// Create New View: Route new view message from view change manager to all nodes
		case viewNumber := <-n.viewchanger.GetNewViewToRouteChannel():
			// Create new view message and route it to the leader handler
			signedNewViewMessage := n.CreateNewViewMessage(viewNumber)
			n.viewchanger.LeaderNewViewRequestHandler(signedNewViewMessage)

			// Logger: add sent new view message
			n.logger.AddSentNewViewMessage(signedNewViewMessage)

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
			log.Infof("Router is trying to log check point message: %s", utils.LoggingString(signedCheckpointMessage))
			n.executor.checkpointer.CheckpointMessageHandler(signedCheckpointMessage)

			// Logger: add sent checkpoint message
			n.logger.AddSentCheckpointMessage(signedCheckpointMessage)

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

			// // Send reply to client
			// case sequenceNum := <-n.executor.GetSendReplyChannel():
			// 	result := n.state.StateLog.GetResult(sequenceNum)
			// 	if result == -1 {
			// 		log.Warnf("Result not found for sequence number %d", sequenceNum)
			// 		continue
			// 	}
			// 	digest := n.state.StateLog.GetDigest(sequenceNum)
			// 	signedRequest := n.state.TransactionMap.Get(digest)
			// 	go n.SendReply(signedRequest, result)
		}

	}
}
