package utils

import (
	"cmp"
	"slices"
)

// LastElement returns the pointer to the last element of a slice of any type
func LastElement[T any](slice []T) *T {
	if len(slice) == 0 {
		return nil
	}
	return &slice[len(slice)-1]
}

// Max returns the maximum value of a slice
func Max[T cmp.Ordered](slice []T) T {
	if len(slice) == 0 {
		return *new(T)
	}
	max := slice[0]
	for _, v := range slice {
		if cmp.Compare(v, max) > 0 {
			max = v
		}
	}
	return max
}

// Min returns the minimum value of a slice
func Min[T cmp.Ordered](slice []T) T {
	if len(slice) == 0 {
		return *new(T)
	}
	min := slice[0]
	for _, v := range slice {
		if cmp.Compare(v, min) < 0 {
			min = v
		}
	}
	return min
}

// Range returns a slice of integers from start to end
func Range(start, end int64) []int64 {
	slice := make([]int64, end-start)
	for i := range slice {
		slice[i] = start + int64(i)
	}
	return slice
}

// Intersection returns the intersection of two slices
func Intersection[T comparable](slice1, slice2 []T) []T {
	intersection := make([]T, 0)
	for _, v := range slice1 {
		if slices.Contains(slice2, v) {
			intersection = append(intersection, v)
		}
	}
	return intersection
}

// Keys returns the keys of a map
func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0)
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Values returns the values of a map
func Values[K comparable, V any](m map[K]V) []V {
	values := make([]V, 0)
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// MaxByValue returns the key and value of the maximum value in a map
func MaxByValue[K comparable, V cmp.Ordered](m map[K]V) (K, V) {
	maxKey := Keys(m)[0]
	maxValue := m[maxKey]
	for k, v := range m {
		if cmp.Compare(v, maxValue) > 0 {
			maxKey = k
			maxValue = v
		}
	}
	return maxKey, maxValue
}

// CountMap returns a map of the count of each element in a slice
func CountMap[T comparable](slice []T) map[T]int64 {
	count := make(map[T]int64)
	for _, v := range slice {
		count[v]++
	}
	return count
}
