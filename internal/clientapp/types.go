package clientapp

import (
	"fmt"
	"strings"

	"github.com/mavleo96/bft-mavleo96/internal/models"
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
