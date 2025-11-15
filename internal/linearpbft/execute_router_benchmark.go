package linearpbft

import (
	"fmt"

	"github.com/mavleo96/pbft/pb"
	log "github.com/sirupsen/logrus"
)

// ExecuteBenchmarkTransaction is the routine for executing YCSB benchmark transactions
func (e *Executor) ExecuteBenchmarkTransaction(signedRequest *pb.SignedTransactionRequest) (any, error) {
	// Execute transaction
	request := signedRequest.Request
	var result any
	var err error
	switch request.Transaction.Type {
	case "ycsb_write", "ycsb_update":
		// Key-value write/update operations
		table := request.Transaction.Table
		key := request.Transaction.Key
		values := request.Transaction.Values

		if table == "" || key == "" {
			err = fmt.Errorf("table and key are required for write/update operations")
			break
		}

		// Get encoded data from values map
		encodedData, ok := values["data"]
		if !ok || len(encodedData) == 0 {
			err = fmt.Errorf("no data provided for write/update")
			break
		}

		if request.Transaction.Type == "ycsb_write" {
			err = e.db.PutKeyValue(table, key, encodedData)
		} else {
			err = e.db.UpdateKeyValue(table, key, encodedData)
		}

		if err != nil {
			log.Warnf("Write/Update operation failed: %v", err)
			result = false
		} else {
			result = true
		}

	case "ycsb_delete":
		table := request.Transaction.Table
		key := request.Transaction.Key

		if table == "" || key == "" {
			err = fmt.Errorf("table and key are required for delete operation")
			break
		}

		err = e.db.DeleteKeyValue(table, key)
		if err != nil {
			log.Warnf("Delete operation failed: %v", err)
			result = false
		} else {
			result = true
		}

	case "ycsb_scan":
		table := request.Transaction.Table
		startKey := request.Transaction.StartKey
		count := request.Transaction.ScanCount

		results, err := e.db.ScanKeyValue(table, startKey, int(count))
		if err != nil {
			log.Warnf("Scan operation failed: %v", err)
			// Send empty results on error
		} else {
			// Convert []struct{Key, Value} to []map[string][]byte for easier handling
			scanResults := make([]map[string][]byte, 0, len(results))
			for _, r := range results {
				scanResults = append(scanResults, map[string][]byte{"value": r.Value})
			}
			result = scanResults
		}

	case "ycsb_read":
		table := request.Transaction.Table
		key := request.Transaction.Key

		value, err := e.db.GetKeyValue(table, key)
		if err != nil {
			log.Warnf("Read operation failed: %v", err)
			result = false
		} else {
			// Convert []byte to map[string][]byte for consistency
			result = map[string][]byte{"value": value}
		}
	}

	return result, err
}
