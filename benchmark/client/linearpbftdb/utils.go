package linearpbftdb

import (
	"crypto/sha256"
	"sort"

	"github.com/mavleo96/bft-mavleo96/pb"
)

// mapKey creates a hashable key from a map[string][]byte for use in maps
func mapKey(m map[string][]byte) [32]byte {
	if m == nil {
		return [32]byte{}
	}
	// Sort keys for deterministic hashing
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Create a deterministic byte representation
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0}) // separator
		h.Write(m[k])
		h.Write([]byte{0}) // separator
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// scanResultsKey creates a hashable key from []*pb.ScanResult for use in maps
func scanResultsKey(results []*pb.ScanResult) [32]byte {
	if results == nil {
		return [32]byte{}
	}
	h := sha256.New()
	// Hash each result's map, then combine
	for _, result := range results {
		if result != nil && result.Fields != nil {
			mapKey := mapKey(result.Fields)
			h.Write(mapKey[:])
		}
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}
