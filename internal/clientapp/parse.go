package clientapp

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"

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
