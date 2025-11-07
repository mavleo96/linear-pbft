package linearpbft

import (
	"context"
	"slices"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SendGetRequest sends a get request to all nodes for a given sequence number
func (n *LinearPBFTNode) SendGetRequest(digest []byte) (*pb.SignedTransactionRequest, error) {
	getRequestMessage := &pb.GetRequestMessage{
		Digest: digest,
		NodeID: n.ID,
	}

	// Multicast get request to all nodes
	responseCh := make(chan *pb.SignedTransactionRequest, len(n.Handler.peers))
	wg := sync.WaitGroup{}
	log.Infof("Sending get request: %s", utils.LoggingString(getRequestMessage))
	for _, peer := range n.Handler.peers {
		wg.Add(1)
		go func(peer *models.Node) {
			defer wg.Done()
			// Byzantine node behavior: dark attack
			if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
				// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
				return
			}
			signedRequest, err := (*peer.Client).GetRequest(context.Background(), getRequestMessage)
			if err != nil {
				return
			}
			responseCh <- signedRequest
		}(peer)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Return the first valid response
	for signedRequest := range responseCh {
		request := signedRequest.Request

		if request == nil {
			continue
		}

		// Verify client signature
		if !cmp.Equal(crypto.Digest(signedRequest), DigestNoOp) &&
			!crypto.Verify(request, n.Clients[request.Sender].PublicKey, signedRequest.Signature) {
			log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(request))
			continue
		}

		// Verify if digest is same as in log record
		if !cmp.Equal(crypto.Digest(signedRequest), digest) {
			log.Warnf("Rejected: %s; invalid digest on request", utils.LoggingString(request))
			continue
		}

		return signedRequest, nil
	}
	log.Warnf("Missing request: %s; could not be retrieved from any node", utils.LoggingString(getRequestMessage))
	return nil, status.Errorf(codes.NotFound, "request not found")
}
