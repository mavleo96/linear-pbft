package client

import (
	"errors"
	"strconv"
	"strings"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// parseTransactionString parses a transaction string of the format "(Sender, Receiver, Amount)"
func parseTransactionString(s string) (pb.Transaction, error) {
	p := strings.Split(strings.Trim(s, "()\""), ", ")

	if len(p) != 1 && len(p) != 3 {
		return pb.Transaction{}, errors.New("invalid transaction string: " + s)
	}

	if len(p) == 1 {
		return pb.Transaction{
			Type:   "read",
			Sender: p[0],
		}, nil
	}

	amount, err := strconv.Atoi(p[2])
	if err != nil {
		return pb.Transaction{}, err
	}

	return pb.Transaction{
		Type:     "send",
		Sender:   p[0],
		Receiver: p[1],
		Amount:   int64(amount),
	}, nil
}

// parseNodeString parses a string representation of a list of nodes of the format "[n1, n2, n3]"
func parseNodeString(s string, nodeMap map[string]*models.Node) []*models.Node {
	nodes := make([]*models.Node, 0)
	for n := range strings.SplitSeq(strings.Trim(s, "[]\""), ", ") {
		nodes = append(nodes, nodeMap[n])
	}
	return nodes
}

// parseAttackString parses a string representation of a list of attacks of the format "[attack1, attack2, attack3]"
func parseAttackString(s string, nodeMap map[string]*models.Node) []*Attack {
	attacks := make([]*Attack, 0)
	for a := range strings.SplitSeq(strings.Trim(s, "[]\""), "; ") {
		if !strings.Contains(a, "dark") && !strings.Contains(a, "equivocation") {
			attacks = append(attacks, &Attack{Type: a})
			continue
		}

		nodeString := strings.Split(strings.Split(a, "(")[1], ")")[0]
		a := strings.Split(a, "(")[0]

		attackNodes := make([]*models.Node, 0)
		for n := range strings.SplitSeq(nodeString, ", ") {
			attackNodes = append(attackNodes, nodeMap[n])
		}
		attacks = append(attacks, &Attack{Type: a, AttackNodes: attackNodes})
	}
	return attacks
}
