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

func (n *LinearPBFTNode) SendPrePrepare(request *pb.TransactionRequest) ([]*pb.SignedPrepareMessage, error) {
	// Assign sequence number to request
	sequenceNum := n.AssignSequenceNumber(request)

	// Create preprepare message and sign it
	preprepare := &pb.PrePrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      security.Digest(request),
	}
	signedPreprepare := &pb.SignedPrePrepareMessage{
		Message:   preprepare,
		Signature: security.Sign(preprepare, n.PrivateKey),
		Request:   request,
	}

	// Add preprepare message to preprepare log
	n.Mutex.Lock()
	n.PrePrepareLog[sequenceNum] = preprepare
	log.Infof("Logged: %s", utils.LoggingString(preprepare, request))
	n.Mutex.Unlock()

	// Multicast preprepare message to all nodes
	responseCh := make(chan *pb.SignedPrepareMessage, len(n.Peers))
	log.Infof("Sending preprepare message for sequence number %d", sequenceNum)
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

	signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
	for range len(n.Peers) {
		signedPrepareMsg := <-responseCh
		if signedPrepareMsg == nil {
			continue
		}
		signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMsg)
		if len(signedPrepareMsgs) == len(n.Peers)-n.F+1 {
			log.Infof("Prepare messages collected for sequence number %d", sequenceNum)
			return signedPrepareMsgs, nil
		}
	}
	log.Infof("Prepare messages not collected for sequence number %d", sequenceNum)
	return nil, nil
}

func (n *LinearPBFTNode) SendPrepare(signedPrepareMessages []*pb.SignedPrepareMessage, sequenceNum int64) ([]*pb.SignedCommitMessage, error) {
	// Create collected signed prepare message
	collectedSignedPrepareMessage := &pb.CollectedSignedPrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Messages:    signedPrepareMessages,
	}
	n.Mutex.Lock()
	digest := n.PrePrepareLog[sequenceNum].Digest
	n.Mutex.Unlock()

	// Multicast prepare message to all nodes
	responseCh := make(chan *pb.SignedCommitMessage, len(n.Peers))
	// defer close(responseCh)
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

	// Verify the prepare messages
	verifiedCount := 0
	for _, signedPrepareMessage := range signedPrepareMessages {
		if signedPrepareMessage == nil {
			log.Fatal("Signed prepare message is nil")
		}
		prepareMessage := signedPrepareMessage.Message

		// Verify Signature
		ok := security.Verify(prepareMessage, n.Peers[prepareMessage.NodeID].PublicKey, signedPrepareMessage.Signature)
		if !ok {
			// log.Warnf("Invalid signature on collected prepare message: %s", utils.LoggingString(signedPrepareMessage, signedPrepareMessage.Request))
			// log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prepareMessage, n.TransactionMap[utils.To32Bytes(prepareMessage.Digest)]))
			continue
		}

		// Check if the prepare message matches preprepare message
		if !cmp.Equal(prepareMessage.Digest, digest) {
			// log.Warnf("Invalid digest on prepare message with sequence number %d in view number %d; request: %v", prepareMessage.SequenceNum, prepareMessage.ViewNumber, n.PrePrepareLog[sequenceNum].String())
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	signedCommitMsgs := make([]*pb.SignedCommitMessage, 0)

	if verifiedCount >= 2*n.F {
		log.Infof("Verified prepare messages for sequence number %d", sequenceNum)
		n.Mutex.Lock()
		n.PrepareLog[sequenceNum] = &pb.PrepareMessage{
			ViewNumber:  n.ViewNumber,
			SequenceNum: sequenceNum,
			Digest:      digest,
			NodeID:      n.ID,
		}
		log.Infof("Logged: %s", utils.LoggingString(n.PrepareLog[sequenceNum], n.TransactionMap[utils.To32Bytes(digest)]))
		n.Mutex.Unlock()
		commitMessage := &pb.CommitMessage{
			ViewNumber:  n.ViewNumber,
			SequenceNum: sequenceNum,
			Digest:      digest,
			NodeID:      n.ID,
		}
		signedCommitMsgs = append(signedCommitMsgs, &pb.SignedCommitMessage{
			Message:   commitMessage,
			Signature: security.Sign(commitMessage, n.PrivateKey),
		})
	} else {
		n.Mutex.Lock()
		log.Warnf("Not enough prepare messages to prepare message %d: %s", sequenceNum, n.PrePrepareLog[sequenceNum].String())
		n.Mutex.Unlock()
	}

	for range len(n.Peers) {
		signedCommitMsg := <-responseCh
		if signedCommitMsg == nil {
			continue
		}
		signedCommitMsgs = append(signedCommitMsgs, signedCommitMsg)
		if len(signedCommitMsgs) == len(n.Peers)-n.F+1 {
			log.Infof("Collected commit message for sequence number %d", sequenceNum)
			return signedCommitMsgs, nil
		}
	}
	return nil, nil
}
