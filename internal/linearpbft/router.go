package linearpbft

import (
	"context"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (n *LinearPBFTNode) RouterRoutine(ctx context.Context) {
	log.Infof("Router routine started")
	for {
		// TODO: need to stop this service routine if not primary and drain the channels
		select {
		case <-ctx.Done():
			return
			// Handle preprepare message
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
				if len(signedPrepareMsgs) == int(n.Handler.N-n.Handler.F) {
					n.Handler.LeaderPrepareMessageHandler(signedPrepareMsgs)
				}
				// Rest are just ignored after collection
			}
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
				if len(signedCommitMsgs) == int(n.Handler.N-n.Handler.F) {
					n.Handler.LeaderCommitMessageHandler(signedCommitMsgs)
				}
				// Rest are just ignored after collection
			}

		case signedCommitMessage := <-n.Handler.GetCommitChannel():
			// Multicast commit message to all nodes
			responseCh := make(chan *emptypb.Empty, len(n.Handler.peers))
			wg := sync.WaitGroup{}
			for _, peer := range n.Handler.peers {
				wg.Add(1)
				go func(peer *models.Node) {
					defer wg.Done()
					_ = n.SendCommitToNode(signedCommitMessage, peer.ID)
					responseCh <- &emptypb.Empty{}
				}(peer)
			}
			go func() {
				wg.Wait()
				close(responseCh)
			}()
		}
		n.Executor.GetExecuteChannel() <- 0

	}
}
