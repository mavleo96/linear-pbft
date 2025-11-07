package utils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// Convert view number to primary ID
func ViewNumberToPrimaryID(v int64, n int64) string {
	primaryID := v%n + 1
	return fmt.Sprintf("n%d", primaryID)
}

// Convert node ID to BLS mask ID
func NodeIDToBLSMaskID(nodeID string) bls.ID {
	var id bls.ID
	id.SetDecString(strings.ReplaceAll(nodeID, "n", ""))
	return id
}

// Remove key from json marshalled string
func RegexRemoveKey(data string, key string) string {
	re := regexp.MustCompile(fmt.Sprintf("\"%s\":\"n\\d+\"", key))
	return re.ReplaceAllString(data, "")
}
