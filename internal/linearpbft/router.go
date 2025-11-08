package linearpbft

import (
	"context"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) RouteAndCollectRoutine(ctx context.Context) {
	log.Infof("Router routine started")
	for {
		// TODO: need to stop this service routine if not primary and drain the channels
		select {
		case <-ctx.Done():
			return

		// Route preprepare message from protocol handler to all backup nodes
		case signedPreprepareMessage := <-n.Handler.GetPreprepareChannel():
			// Multicast preprepare message to all nodes
			responseCh := make(chan *pb.SignedPrepareMessage, len(n.Handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.Handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()
					signedPrepareMsg, err := n.SendPrePrepareToNode(signedPreprepareMessage, peer.ID)
					if err != nil {
						return
					}
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
		case signedPrepareMessage := <-n.Handler.GetPrepareChannel():
			// Multicast prepare message to all nodes
			responseCh := make(chan *pb.SignedCommitMessage, len(n.Handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.Handler.peers {
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
		case signedCommitMessage := <-n.Handler.GetCommitChannel():
			// Multicast commit message to all nodes
			for _, peer := range n.Handler.peers {
				go n.SendCommitToNode(signedCommitMessage, peer.ID)
			}

			// Signal the executor to execute the next sequence number
			n.Executor.GetExecuteChannel() <- 0

		// Route view change message from view change manager to all nodes
		case viewNumber := <-n.ViewChangeManager.GetViewChangeChannel():
			// NOTE: this should be part of the view change manager
			// but view change manager does not have access to the check point log
			signedViewChangeMessage := n.CreateViewChangeMessage(viewNumber)
			log.Infof("Router routine has logged view change message: %s", utils.LoggingString(signedViewChangeMessage.Message))
			n.ViewChangeManager.AddViewChangeMessage(signedViewChangeMessage)

			// Multicast view change message to all nodes
			log.Infof("Router routine is multicasting view change message to all nodes: %s", utils.LoggingString(signedViewChangeMessage.Message))
			for _, peer := range n.Handler.peers {
				go n.SendViewChangeMessageToNode(signedViewChangeMessage, peer.ID)
			}

		// Route new view message from view change manager to all nodes
		case viewNumber := <-n.ViewChangeManager.GetNewViewChannel():
			// Create new view message and route it to the leader handler
			signedNewViewMessage := n.CreateNewViewMessage(viewNumber)
			n.ViewChangeManager.LeaderNewViewRequestHandler(signedNewViewMessage)

			// Multicast new view message to all nodes and collect prepare messages from all nodes
			responseCh := make(chan *pb.SignedPrepareMessage, 100)
			wg := sync.WaitGroup{}
			for _, peer := range n.Handler.peers {
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

		// Route check point message from check point manager to all nodes
		case sequenceNum := <-n.CheckPointManager.GetCheckPointCreateChannel():
			signedCheckPointMessage := n.CreateCheckPointMessage(sequenceNum)
			log.Infof("Router is trying to log check point message: %s", utils.LoggingString(signedCheckPointMessage.Message))
			n.Executor.CheckPointManager.CheckPointMessageHandler(signedCheckPointMessage)

			// Multicast check point message to all nodes
			for _, peer := range n.Handler.peers {
				go n.SendCheckPointMessageToNode(signedCheckPointMessage, peer.ID)
			}

		// Route install check point message from view change manager to executor
		case sequenceNum := <-n.ViewChangeManager.GetInstallCheckPointChannel():
			// If checkpoint is missing then get it from all nodes
			checkPoint, err := n.SendGetCheckPoint(sequenceNum)
			if err != nil {
				log.Fatalf("Failed to get check point for sequence number %d", sequenceNum)
			}
			if checkPoint == nil || checkPoint.Snapshot == nil {
				log.Fatalf("Check point not found or snapshot is nil for sequence number %d", sequenceNum)
			}
			n.Executor.CheckPointManager.AddCheckpoint(sequenceNum, checkPoint.Snapshot)

			// Signal the executor to install the checkpoint
			n.Executor.GetInstallCheckPointChannel() <- sequenceNum

		}

	}
}
