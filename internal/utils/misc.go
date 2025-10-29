package utils

import "fmt"

func ViewNumberToLeaderID(v int64, n int64) string {
	leaderID := v%n + 1
	return fmt.Sprintf("n%d", leaderID)
}
