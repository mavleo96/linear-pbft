package utils

import "fmt"

func ViewNumberToPrimaryID(v int64, n int64) string {
	primaryID := v%n + 1
	return fmt.Sprintf("n%d", primaryID)
}
