package clientapp

import (
	"encoding/csv"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// ReadCSV reads records from a csv file at given path
func ReadCSV(path string) ([][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return [][]string{}, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return [][]string{}, err
	}
	return records, nil
}

// ParseRecords parses the records from a csv file
func ParseRecords(records [][]string, clientIDs []string, nodeMap map[string]*models.Node) ([]*TestSet, error) {
	testSets := make([]*TestSet, 0)

	for i, record := range records {
		if i == 0 {
			continue // Skip header row
		}

		// If set number is new, create a new test set
		if record[0] != "" {
			// Parse set number
			setNumber, err := strconv.Atoi(record[0])
			if err != nil {
				return []*TestSet{}, err
			}

			liveNodes := parseNodeString(record[2], nodeMap)
			byzantineNodes := parseNodeString(record[3], nodeMap)
			attacks := parseAttackString(record[4], nodeMap)
			testSets = append(testSets, &TestSet{
				SetNumber:    setNumber,
				Live:         liveNodes,
				Byzantine:    byzantineNodes,
				Attack:       attacks,
				Transactions: make(map[string][]*pb.Transaction),
			})
		}

		t, err := parseTransactionString(record[1])
		if err != nil {
			return []*TestSet{}, err
		}
		testSet := *utils.LastElement(testSets)
		testSet.Transactions[t.Sender] = append(testSet.Transactions[t.Sender], &t)
	}
	return testSets, nil
}

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
