package linearpbft

import (
	"context"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) SendPrePrepare(signedPreprepare *pb.SignedPrePrepareMessage, sequenceNum int64) ([]*pb.SignedPrepareMessage, error) {
	preprepare := signedPreprepare.Message

	// Add preprepare message to log record
	record := n.LogRecords[sequenceNum]
	if record == nil {
		log.Fatal("Leader tried to preprepare a sequence number that is not in the log record")
	}
	request := record.Request

	// Multicast preprepare message to all nodes
	responseCh := make(chan *pb.SignedPrepareMessage, len(n.Peers))
	log.Infof("Sending preprepare (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(request))
	wg := sync.WaitGroup{}
	for _, peer := range n.Peers {
		wg.Go(func() {
			signedPrepareMsg, err := (*peer.Client).PrePrepare(context.Background(), signedPreprepare)
			if err != nil {
				log.Fatal(err)
			}
			responseCh <- signedPrepareMsg
		})
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Add leader's own prepare message
	signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
	prepareMessage := &pb.PrepareMessage{
		ViewNumber:  preprepare.ViewNumber,
		SequenceNum: preprepare.SequenceNum,
		Digest:      preprepare.Digest,
		NodeID:      n.ID,
	}
	signedPrepareMsgs = append(signedPrepareMsgs, &pb.SignedPrepareMessage{
		Message:   prepareMessage,
		Signature: security.Sign(prepareMessage, n.PrivateKey),
	})

	// Collect 2f + 1 matching prepare messages including self
	// Note: leader is attaching his own prepare message to comply with TSS
	for range len(n.Peers) {
		signedPrepareMsg := <-responseCh
		if signedPrepareMsg == nil || signedPrepareMsg.Message == nil {
			continue
		}

		// Verify signature
		ok := security.Verify(signedPrepareMsg.Message, n.Peers[signedPrepareMsg.Message.NodeID].PublicKey, signedPrepareMsg.Signature)
		if !ok {
			continue
		}

		// Check if the prepare message matches preprepare message
		if signedPrepareMsg.Message.ViewNumber != preprepare.ViewNumber ||
			signedPrepareMsg.Message.SequenceNum != preprepare.SequenceNum ||
			!cmp.Equal(signedPrepareMsg.Message.Digest, preprepare.Digest) {
			continue
		}

		// Add to signed prepare messages
		signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMsg)

		// If 2f + 1 (n - f) matching prepare messages are collected, then return the signed prepare messages
		if len(signedPrepareMsgs) == int(n.N-n.F) {
			log.Infof("Verified prepare messages for sequence number %d", sequenceNum)
			log.Infof("Prepare messages collected for sequence number %d", sequenceNum)
			record.AddPrepareMessages(signedPrepareMsgs)
			return signedPrepareMsgs, nil
		}
	}
	log.Infof("Prepare messages not collected for sequence number %d", sequenceNum)
	return nil, nil
}

func (n *LinearPBFTNode) SendPrepare(signedPrepareMessages []*pb.SignedPrepareMessage, sequenceNum int64) ([]*pb.SignedCommitMessage, error) {
	// Get preprepare record from preprepare log
	n.Mutex.Lock()
	record := n.LogRecords[sequenceNum]
	n.Mutex.Unlock()
	if record == nil || !record.IsPrePrepared() {
		log.Fatal("Preprepare record is nil")
	}

	// Create collected signed prepare message
	collectedSignedPrepareMessage := &pb.CollectedSignedPrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		Messages:    signedPrepareMessages,
	}

	// Multicast prepare message to all nodes
	responseCh := make(chan *pb.SignedCommitMessage, len(n.Peers))
	log.Infof("Sending prepare message for sequence number %d", sequenceNum)
	wg := sync.WaitGroup{}
	for _, peer := range n.Peers {
		wg.Go(func() {
			signedCommitMsg, err := (*peer.Client).Prepare(context.Background(), collectedSignedPrepareMessage)
			if err != nil {
				log.Fatal(err)
			}
			responseCh <- signedCommitMsg
		})
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	signedCommitMsgs := make([]*pb.SignedCommitMessage, 0)

	n.Mutex.Lock()
	record.AddPrepareMessages(signedPrepareMessages)
	n.Mutex.Unlock()

	// Create commit message and sign it
	commitMessage := &pb.CommitMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		NodeID:      n.ID,
	}
	signedCommitMsgs = append(signedCommitMsgs, &pb.SignedCommitMessage{
		Message:   commitMessage,
		Signature: security.Sign(commitMessage, n.PrivateKey),
	})

	// Collect 2f + 1 matching commit messages including self
	for range len(n.Peers) {
		signedCommitMsg := <-responseCh
		if signedCommitMsg == nil || signedCommitMsg.Message == nil {
			continue
		}

		// Verify signature
		// log.Infof("Signed commit message: %s", signedCommitMsg.Message.String())
		ok := security.Verify(signedCommitMsg.Message, n.Peers[signedCommitMsg.Message.NodeID].PublicKey, signedCommitMsg.Signature)
		if !ok {
			continue
		}

		// Check if the commit message matches prepare message
		if signedCommitMsg.Message.ViewNumber != record.ViewNumber ||
			signedCommitMsg.Message.SequenceNum != record.SequenceNum ||
			!cmp.Equal(signedCommitMsg.Message.Digest, record.Digest) {
			continue
		}

		// Add to signed commit messages
		signedCommitMsgs = append(signedCommitMsgs, signedCommitMsg)

		// If 2f + 1 (n - f) matching commit messages are collected, then return the signed commit messages
		if len(signedCommitMsgs) == int(n.N-n.F) {
			log.Infof("Verified commit messages for sequence number %d", sequenceNum)
			log.Infof("Collected commit message for sequence number %d", sequenceNum)
			return signedCommitMsgs, nil
		}
	}
	return nil, nil
}

func (n *LinearPBFTNode) SendCommit(signedCommitMessages []*pb.SignedCommitMessage, sequenceNum int64) (bool, error) {
	// Get prepared record from prepared log
	n.Mutex.Lock()
	record := n.LogRecords[sequenceNum]
	n.Mutex.Unlock()
	if record == nil || !record.IsPrepared() {
		log.Fatal("Prepared record is nil")
	}

	// Create collected signed commit message
	collectedSignedCommitMessage := &pb.CollectedSignedCommitMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      record.Digest,
		Messages:    signedCommitMessages,
	}

	// Multicast commit message to all nodes
	log.Infof("Sending commit message for sequence number %d", sequenceNum)
	for _, peer := range n.Peers {
		go func() {
			_, err := (*peer.Client).Commit(context.Background(), collectedSignedCommitMessage)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	// Add to committed log
	n.Mutex.Lock()
	record.AddCommitMessages(signedCommitMessages)
	n.Mutex.Unlock()
	return true, nil
}

func (n *LinearPBFTNode) SendNewView(viewNumber int64) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Update view number
	n.ViewNumber = viewNumber
	n.SentViewChange = false

	// Get view change messages from view change message log
	viewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	signedViewChangeMessages := make([]*pb.SignedViewChangeMessage, 0)
	for _, viewChangeMessage := range viewChangeMessageLog {
		signedViewChangeMessages = append(signedViewChangeMessages, viewChangeMessage)
	}

	// TODO: later get this from stable checkpoint
	lowerSequenceNum := int64(0)

	// Aggregate preprepare messages from view change messages
	signedPrePrepareMessages := make(map[int64]*pb.SignedPrePrepareMessage)
	for _, signedViewChangeMessage := range viewChangeMessageLog {
		viewChangeMessage := signedViewChangeMessage.Message

		// Loop through prepare proofs and add to signed preprepare messages if not already added
		for _, prepareProof := range viewChangeMessage.PreparedSet {
			prePrepareMessage := prepareProof.SignedPrePrepareMessage.Message
			sequenceNum := prePrepareMessage.SequenceNum

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
				Signature: security.Sign(newPrePrepareMessage, n.PrivateKey),
			}
		}
	}
	// Order signed preprepare messages by sequence number and add no op preprepare message if sequence number is not in the log record
	sortedSignedPrePrepareMessages := make([]*pb.SignedPrePrepareMessage, 0)
	maxSequenceNum := int64(0)
	if utils.Max(utils.Keys(signedPrePrepareMessages)) != nil {
		maxSequenceNum = *utils.Max(utils.Keys(signedPrePrepareMessages))
	}
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		var newSignedPrePrepareMessage *pb.SignedPrePrepareMessage
		if _, ok := signedPrePrepareMessages[sequenceNum]; !ok {
			newPrePrepareMessage := &pb.PrePrepareMessage{
				ViewNumber:  viewNumber,
				SequenceNum: sequenceNum,
				Digest:      security.Digest(NoOpTransactionRequest),
			}
			newSignedPrePrepareMessage = &pb.SignedPrePrepareMessage{
				Message:   newPrePrepareMessage,
				Signature: security.Sign(newPrePrepareMessage, n.PrivateKey),
			}
		} else {
			newSignedPrePrepareMessage = signedPrePrepareMessages[sequenceNum]
		}
		sortedSignedPrePrepareMessages = append(sortedSignedPrePrepareMessages, newSignedPrePrepareMessage)
		continue
	}

	// Create new view message and sign it
	newViewMessage := &pb.NewViewMessage{
		ViewNumber:               viewNumber,
		SignedViewChangeMessages: signedViewChangeMessages,
		SignedPrePrepareMessages: sortedSignedPrePrepareMessages,
	}
	signedNewViewMessage := &pb.SignedNewViewMessage{
		Message:   newViewMessage,
		Signature: security.Sign(newViewMessage, n.PrivateKey),
	}

	// Multicast new view message to all nodes
	log.Infof("Sending new view message for view number %d: %s", viewNumber, utils.LoggingString(newViewMessage))
	for _, peer := range n.Peers {
		go func() {
			_, err := (*peer.Client).NewView(context.Background(), signedNewViewMessage)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}
}
