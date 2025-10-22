package utils

import "cmp"

// LastElement returns the pointer to the last element of a slice
func LastElement[T any](slice []T) *T {
	if len(slice) == 0 {
		return nil
	}
	return &slice[len(slice)-1]
}

func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0)
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func Max[T cmp.Ordered](slice []T) *T {
	if len(slice) == 0 {
		return nil
	}
	max := slice[0]
	for _, v := range slice {
		if cmp.Compare(v, max) > 0 {
			max = v
		}
	}
	return &max
}
