package utils

// LastElement returns the pointer to the last element of a slice
func LastElement[T any](slice []T) *T {
	if len(slice) == 0 {
		return nil
	}
	return &slice[len(slice)-1]
}
