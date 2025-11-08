package linearpbft

import (
	"context"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

// TODO: router should not be responsible for collecting messages; it should only route them
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
					signedPrepareMsg, _ := n.SendPrePrepareToNode(signedPreprepareMessage, peer.ID)
					// if err != nil {
					// 	return
					// }
					responseCh <- signedPrepareMsg
				}(peer)
			}

			// Wait for all responses and close the channel
			go func() {
				wg.Wait()
				close(responseCh)
			}()

			// Collect 2f + 1 matching prepare messages including self
			signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
			// Add primary's own prepare message
			prepareMessage := &pb.PrepareMessage{
				ViewNumber:  signedPreprepareMessage.Message.ViewNumber,
				SequenceNum: signedPreprepareMessage.Message.SequenceNum,
				Digest:      signedPreprepareMessage.Message.Digest,
				NodeID:      n.ID,
			}
			signedPrepareMessage := &pb.SignedPrepareMessage{
				Message:   prepareMessage,
				Signature: crypto.Sign(prepareMessage, n.Handler.privateKey1),
			}
			signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMessage)

			for range len(n.Handler.peers) {
				signedPrepareMsg := <-responseCh
				if signedPrepareMsg == nil || signedPrepareMsg.Message == nil {
					continue
				}
				signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMsg)
				if len(signedPrepareMsgs) == int(n.config.N-n.config.F) {
					n.Handler.LeaderPrepareMessageHandler(signedPrepareMsgs)
				}
				// Rest are just ignored after collection
			}

		// Route prepare message from protocol handler to all backup nodes
		case signedPrepareMessage := <-n.Handler.GetPrepareChannel():
			// Multicast prepare message to all nodes
			responseCh := make(chan *pb.SignedCommitMessage, len(n.Handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.Handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()
					signedCommitMsg, _ := n.SendPrepareToNode(signedPrepareMessage, peer.ID)
					responseCh <- signedCommitMsg
				}(peer)
			}
			go func() {
				wg.Wait()
				close(responseCh)
			}()
			// Collect 2f + 1 matching commit messages including self
			signedCommitMsgs := make([]*pb.SignedCommitMessage, 0)
			// Add primary's own commit message
			commitMessage := &pb.CommitMessage{
				ViewNumber:  signedPrepareMessage.Message.ViewNumber,
				SequenceNum: signedPrepareMessage.Message.SequenceNum,
				Digest:      signedPrepareMessage.Message.Digest,
				NodeID:      n.ID,
			}
			signedCommitMessage := &pb.SignedCommitMessage{
				Message:   commitMessage,
				Signature: crypto.Sign(commitMessage, n.Handler.privateKey1),
			}
			signedCommitMsgs = append(signedCommitMsgs, signedCommitMessage)
			for range len(n.Handler.peers) {
				signedCommitMsg := <-responseCh
				if signedCommitMsg == nil || signedCommitMsg.Message == nil {
					continue
				}
				signedCommitMsgs = append(signedCommitMsgs, signedCommitMsg)
				if len(signedCommitMsgs) == int(n.config.N-n.config.F) {
					n.Handler.LeaderCommitMessageHandler(signedCommitMsgs)
				}
				// Rest are just ignored after collection
			}

		// Route commit message from protocol handler to all backup nodes
		case signedCommitMessage := <-n.Handler.GetCommitChannel():
			// Multicast commit message to all nodes
			for _, peer := range n.Handler.peers {
				go n.SendCommitToNode(signedCommitMessage, peer.ID)
			}

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

		// Route get check point message from router to all nodes

		// NOTE: The executor is signalled everytime may be redundant; but it is safe to do so
		// TODO: need to check if calling only in commit message handler or in router routine is sufficient
		n.Executor.GetExecuteChannel() <- 0

	}
}

func (n *LinearPBFTNode) CollectPrepareMessages(responseCh chan *pb.SignedPrepareMessage) {
	signedPrepareMessageMap := make(map[int64]map[string]*pb.SignedPrepareMessage) // sequence number -> node ID -> signed prepare message

	// Keep looping and send to handler once we have 2f + 1 prepare messages for a sequence number
	for {
		// Keep collecting until the channel is closed
		signedPrepareMessage, ok := <-responseCh
		if !ok {
			break
		}
		prepareMessage := signedPrepareMessage.Message
		sequenceNum := prepareMessage.SequenceNum
		if _, ok := signedPrepareMessageMap[sequenceNum]; !ok {
			signedPrepareMessageMap[sequenceNum] = make(map[string]*pb.SignedPrepareMessage)
		}

		// Log the prepare message in collection map
		signedPrepareMessageMap[sequenceNum][prepareMessage.NodeID] = signedPrepareMessage

		// If we have 2f prepare messages for a sequence number, send to handler
		if len(signedPrepareMessageMap[sequenceNum]) == int(2*n.config.F) {
			log.Infof("New view prepare collector: Collected 2f prepare messages for sequence number %d", sequenceNum)
			// Convert map to slice of signed prepare messages and add self's prepare message
			signedPrepareMessages := utils.Values(signedPrepareMessageMap[sequenceNum])
			prepareMessage := &pb.PrepareMessage{
				ViewNumber:  signedPrepareMessage.Message.ViewNumber,
				SequenceNum: sequenceNum,
				Digest:      signedPrepareMessage.Message.Digest,
				NodeID:      n.ID,
			}
			signedPrepareMessage := &pb.SignedPrepareMessage{
				Message:   prepareMessage,
				Signature: crypto.Sign(prepareMessage, n.Handler.privateKey1),
			}
			signedPrepareMessages = append(signedPrepareMessages, signedPrepareMessage)
			go n.Handler.LeaderPrepareMessageHandler(signedPrepareMessages)
		}
	}
}
