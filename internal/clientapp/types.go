package clientapp

import (
	"fmt"
	"strings"
	"sync"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// TestSet represents a test set with a set number, transactions, live nodes, byzantine nodes, and attacks
type TestSet struct {
	SetNumber    int
	Transactions map[string][]*pb.Transaction
	Live         []*models.Node
	Byzantine    []*models.Node
	Attack       []*Attack
}

// Attack represents an attack with a type and a list of attack nodes
type Attack struct {
	Type        string
	AttackNodes []*models.Node
}

// String returns a string representation of the attack
func (a *Attack) String() string {
	if a.AttackNodes == nil {
		return a.Type
	}
	nodeStrings := make([]string, 0)
	for _, n := range a.AttackNodes {
		nodeStrings = append(nodeStrings, n.ID)
	}
	return fmt.Sprintf("%s(%s)", a.Type, strings.Join(nodeStrings, ", "))
}

type NodeMap struct {
	nodes map[string]*models.Node
	N     int64
	F     int64
	mutex sync.RWMutex
}

// GetPublicKey1 returns the public key 1 of a node
func (n *NodeMap) GetPublicKey1(nodeID string) *bls.PublicKey {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.nodes[nodeID].PublicKey1
}

// GetNodes returns all nodes
func (n *NodeMap) GetNodes() []*models.Node {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return utils.Values(n.nodes)
}

// GetNode returns a node by ID
func (n *NodeMap) GetNode(nodeID string) *models.Node {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.nodes[nodeID]
}
