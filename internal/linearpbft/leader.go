package linearpbft

import (
	"context"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) SendPrePrepare(request *pb.TransactionRequest) ([]*pb.SignedPrepareMessage, error) {
	// Compute digest of request
	digest := security.Digest(utils.MessageString(request))

	// Assign sequence number to request
	sequenceNum := n.AssignSequenceNumber(request)

	// Create preprepare message and sign it
	preprepare := &pb.PrePrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      digest,
	}
	signedPreprepare := &pb.SignedPrePrepareMessage{
		Message:   preprepare,
		Signature: security.Sign(utils.MessageString(preprepare), n.PrivateKey),
		Request:   request,
	}

	// Add preprepare message to preprepare log
	n.PrePrepareLog[sequenceNum] = preprepare
	log.Infof("Logged preprepare message for sequence number %d", sequenceNum)

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
			log.Infof("Collected prepare message for sequence number %d", sequenceNum)
			return signedPrepareMsgs, nil
		}
	}
	return nil, nil
}

	return signedPrepareMsgs, nil
}
