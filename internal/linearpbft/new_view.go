package linearpbft

import (
	"context"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewViewRoutine is a routine that handles sending new view messages to all nodes
func (n *LinearPBFTNode) NewViewRoutine(ctx context.Context, viewNumber int64) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Update view number
	n.State.SetViewNumber(viewNumber)
	n.State.SetViewChangePhase(false)

	// Get view change messages from view change message log
	signedViewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	signedViewChangeMessages := make([]*pb.SignedViewChangeMessage, 0)
	for _, signedViewChangeMessage := range signedViewChangeMessageLog {
		signedViewChangeMessages = append(signedViewChangeMessages, signedViewChangeMessage)
	}

	// TODO: later get this from stable checkpoint in the new view message
	lowerSequenceNum := int64(0)

	// Aggregate preprepare messages from view change messages and create preprepare message with current view number
	signedPrePrepareMessages := make(map[int64]*pb.SignedPrePrepareMessage)
	for _, signedViewChangeMessage := range signedViewChangeMessageLog {
		viewChangeMessage := signedViewChangeMessage.Message

		// Loop through prepare proofs and add to signed preprepare messages if not already added
		for _, prepareProof := range viewChangeMessage.PreparedSet {
			prePrepareMessage := prepareProof.SignedPrePrepareMessage.Message
			sequenceNum := prePrepareMessage.SequenceNum

			// If preprepare message is already in the map, then continue
			if _, ok := signedPrePrepareMessages[sequenceNum]; ok {
				continue
			}

			// Create new preprepare message and add to signed preprepare messages
			newPrePrepareMessage := &pb.PrePrepareMessage{
				ViewNumber:  viewNumber,
				SequenceNum: sequenceNum,
				Digest:      prePrepareMessage.Digest,
			}
			signedPrePrepareMessages[sequenceNum] = &pb.SignedPrePrepareMessage{
				Message:   newPrePrepareMessage,
				Signature: crypto.Sign(newPrePrepareMessage, n.Handler.privateKey1),
			}
			// Byzantine node behavior: sign attack
			if n.Byzantine && n.SignAttack {
				// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
				signedPrePrepareMessages[sequenceNum].Signature = []byte("invalid signature")
			}
		}
	}

	// Order signed preprepare messages by sequence number
	sortedSignedPrePrepareMessages := make([]*pb.SignedPrePrepareMessage, 0)
	maxSequenceNum := utils.Max(utils.Keys(signedPrePrepareMessages))
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		// If preprepare message is not in the map, then create a new no op preprepare message and add to the map
		var newSignedPrePrepareMessage *pb.SignedPrePrepareMessage
		if _, ok := signedPrePrepareMessages[sequenceNum]; !ok {
			newPrePrepareMessage := &pb.PrePrepareMessage{
				ViewNumber:  viewNumber,
				SequenceNum: sequenceNum,
				Digest:      crypto.Digest(NoOpTransactionRequest),
			}
			newSignedPrePrepareMessage = &pb.SignedPrePrepareMessage{
				Message:   newPrePrepareMessage,
				Signature: crypto.Sign(newPrePrepareMessage, n.Handler.privateKey1),
			}
			// Byzantine node behavior: sign attack
			if n.Byzantine && n.SignAttack {
				// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
				newSignedPrePrepareMessage.Signature = []byte("invalid signature")
			}
		} else {
			newSignedPrePrepareMessage = signedPrePrepareMessages[sequenceNum]
		}
		sortedSignedPrePrepareMessages = append(sortedSignedPrePrepareMessages, newSignedPrePrepareMessage)
	}

	// Primary needs to first preprepare the request in its own log record
	for _, signedPrePrepareMessage := range sortedSignedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		sequenceNum := prePrepareMessage.SequenceNum

		// If request is not in the transaction map then send a get request to all nodes
		signedRequest := n.State.TransactionMap.Get(prePrepareMessage.Digest)
		if signedRequest == nil {
			response, err := n.SendGetRequest(prePrepareMessage.Digest)
			if err != nil || response == nil {
				log.Warnf("Rejected: %s; request could not be retrieved from any node", utils.LoggingString(prePrepareMessage))
			} else {
				signedRequest = response
				log.Infof("Adding request to transaction map: %s", utils.LoggingString(signedRequest.Request))
				n.State.TransactionMap.Set(prePrepareMessage.Digest, signedRequest)
			}
		}

		// Get record from log record or create new one
		n.State.StateLog.CreateRecordIfNotExists(viewNumber, sequenceNum, prePrepareMessage.Digest)
		log.Infof("Logging preprepare message: %s", utils.LoggingString(prePrepareMessage))
		status := n.State.StateLog.AddPrePrepareMessage(sequenceNum, signedPrePrepareMessage)
		log.Infof("v: %d s: %d status: %s req: %s", prePrepareMessage.ViewNumber, prePrepareMessage.SequenceNum, status, utils.LoggingString(signedRequest.Request))
	}
	// Purge log records with older view number / greater than maxSequenceNum
	for i := maxSequenceNum + 1; i <= n.State.StateLog.MaxSequenceNum(); i++ {
		n.State.StateLog.Delete(i)
	}
	// Purge forwarded requests
	n.ForwardedRequestsLog = make([]*pb.SignedTransactionRequest, 0)

	// Create new view message and sign it
	newViewMessage := &pb.NewViewMessage{
		ViewNumber:               viewNumber,
		SignedViewChangeMessages: signedViewChangeMessages,
		SignedPrePrepareMessages: sortedSignedPrePrepareMessages,
	}
	signedNewViewMessage := &pb.SignedNewViewMessage{
		Message:   newViewMessage,
		Signature: crypto.Sign(newViewMessage, n.Handler.privateKey1),
	}
	// Byzantine node behavior: sign attack
	if n.Byzantine && n.SignAttack {
		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
		signedNewViewMessage.Signature = []byte("invalid signature")
	}

	collectedSignedPrepareMessages := n.SendNewView(signedNewViewMessage)

	// Send prepare messages to prepare channel
	for sequenceNum := range collectedSignedPrepareMessages {
		// n.Handler.GetPrepareChannel() <- collectedSignedPrepareMessages[sequenceNum]
		n.Handler.LeaderPrepareMessageHandler(collectedSignedPrepareMessages[sequenceNum])
	}
}

func (n *LinearPBFTNode) NewViewRequest(signedNewViewMessage *pb.SignedNewViewMessage, stream pb.LinearPBFTNode_NewViewRequestServer) error {
	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return status.Errorf(codes.Unavailable, "node not alive")
	}

	newViewMessage := signedNewViewMessage.Message
	signedViewChangeMessages := newViewMessage.SignedViewChangeMessages
	signedPrePrepareMessages := newViewMessage.SignedPrePrepareMessages
	viewNumber := newViewMessage.ViewNumber

	// Check if view number matches latest sent view change message view number
	if viewNumber < n.State.GetViewChangeViewNumber() {
		log.Warnf("Rejected: %s; view number is less than latest sent view change message view number", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.FailedPrecondition, "view number is less than latest sent view change message view number")
	}

	// Verify signature
	primaryID := utils.ViewNumberToPrimaryID(viewNumber, n.Handler.N)
	ok := crypto.Verify(newViewMessage, n.GetPublicKey1(primaryID), signedNewViewMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify view change messages signatures
	for _, signedViewChangeMessage := range signedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		ok := crypto.Verify(viewChangeMessage, n.GetPublicKey1(viewChangeMessage.NodeID), signedViewChangeMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on view change message", utils.LoggingString(newViewMessage))
			return status.Errorf(codes.Unauthenticated, "invalid signature on view change message")
		}
	}

	// Verify preprepare messages signatures
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(primaryID), signedPrePrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on preprepare message", utils.LoggingString(newViewMessage))
			return status.Errorf(codes.Unauthenticated, "invalid signature on preprepare message")
		}
	}

	// TODO: transfer control to new view handler

	// Cleanup timer and update view number
	// n.SafeTimer.Cleanup() // TODO: check if this is alright...but it correct as per the paper
	n.State.SetViewNumber(viewNumber)
	n.State.SetViewChangeViewNumber(viewNumber)
	n.State.SetViewChangePhase(false)
	log.Infof("Accepted %s", utils.LoggingString(newViewMessage))

	// Byzantine node behavior: dark attack
	if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, primaryID) {
		// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, primaryID)
		return status.Errorf(codes.Unavailable, "node not alive")
	}

	// TODO: Install latest stable checkpoint

	// Stream prepare messages to primary
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		signedPrepareMessage, err := n.Handler.BackupPrePrepareRequestHandler(signedPrePrepareMessage)
		if err != nil {
			log.Warnf("Prepare request %s could not be sent to primary: %s", utils.LoggingString(signedPrePrepareMessage), err)
			continue
		}
		if err := stream.Send(signedPrepareMessage); err != nil {
			log.Warnf("Prepare message %s could not be sent to primary in stream: %s", utils.LoggingString(signedPrepareMessage), err)
		}
	}
	log.Infof("Streamed prepares messages for view number %d", viewNumber)
	return nil
}

// SendNewView sends a new view message to all nodes
func (n *LinearPBFTNode) SendNewView(signedNewViewMessage *pb.SignedNewViewMessage) map[int64][]*pb.SignedPrepareMessage {
	viewMessage := signedNewViewMessage.Message
	signedPrePrepareMessages := viewMessage.SignedPrePrepareMessages

	// Multicast new view message to all nodes and collect signed prepare messages
	log.Infof("Sending new view message: %s", utils.LoggingString(viewMessage))
	wg := sync.WaitGroup{}
	responseCh := make(chan *pb.SignedPrepareMessage, len(n.Handler.peers))
	for _, peer := range n.Handler.peers {
		wg.Add(1)
		go func(peer *models.Node) {
			defer wg.Done()
			// Byzantine node behavior: dark attack
			if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
				// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
				return
			}
			// Byzantine node behavior: time attack
			if n.Byzantine && n.TimeAttack {
				// log.Infof("Node %s is Byzantine and is performing time attack", n.ID)
				time.Sleep(TimeAttackDelay)
			}

			// Send new view message to peer
			stream, err := (*peer.Client).NewViewRequest(context.Background(), signedNewViewMessage)
			if err != nil {
				return
			}

			// Stream prepare messages from peer and send to response channel
			for {
				signedPrepareMessage, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Warn(err)
					return
				}

				responseCh <- signedPrepareMessage
			}
		}(peer)
	}

	// Close response channel when all peers have sent their prepare messages
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Convert signed preprepare messages to map of sequence numbers to signed preprepare messages
	signedPrePrepareMessagesMap := make(map[int64]*pb.SignedPrePrepareMessage)
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		signedPrePrepareMessagesMap[signedPrePrepareMessage.Message.SequenceNum] = signedPrePrepareMessage
	}

	// Collect and verify signed prepare messages
	collectedSignedPrepareMessages := make(map[int64][]*pb.SignedPrepareMessage)
	for {
		signedPrepareMessage, more := <-responseCh
		if !more {
			break
		}
		prepareMessage := signedPrepareMessage.Message
		sequenceNum := prepareMessage.SequenceNum

		// Verify signature
		ok := crypto.Verify(prepareMessage, n.GetPublicKey1(prepareMessage.NodeID), signedPrepareMessage.Signature)
		if !ok {
			// log.Warnf("Rejected: %s; invalid signature on prepare message", utils.LoggingString(prepareMessage))
			continue
		}

		// Check if preprepare message is in the map
		signedPrePrepareMessage, ok := signedPrePrepareMessagesMap[sequenceNum]
		if !ok {
			// log.Warnf("Rejected: %s; preprepare message not found", utils.LoggingString(prepareMessage))
			continue
		}
		prePrepareMessage := signedPrePrepareMessage.Message

		// Check if preprepare message digest, view number and sequence number match
		if prepareMessage.ViewNumber != prePrepareMessage.ViewNumber ||
			prepareMessage.SequenceNum != prePrepareMessage.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, prePrepareMessage.Digest) {
			// log.Warnf("Rejected: %s; preprepare message does not match", utils.LoggingString(prepareMessage))
			continue
		}

		// Add to collected signed prepare messages
		if _, ok := collectedSignedPrepareMessages[sequenceNum]; !ok {
			collectedSignedPrepareMessages[sequenceNum] = make([]*pb.SignedPrepareMessage, 0)
		}
		collectedSignedPrepareMessages[sequenceNum] = append(collectedSignedPrepareMessages[sequenceNum], signedPrepareMessage)
	}

	// Purge sequence numbers with less than 2f + 1 prepare messages
	for sequenceNum, signedPrepareMessages := range collectedSignedPrepareMessages {
		if len(signedPrepareMessages) < int(n.Handler.N-n.Handler.F) {
			log.Warnf("Purged: %d; not enough prepare messages (collected: %d)", sequenceNum, len(signedPrepareMessages))
			delete(collectedSignedPrepareMessages, sequenceNum)
		}
	}

	return collectedSignedPrepareMessages
}
