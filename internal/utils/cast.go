package utils

// Convert byte slice to 32 byte array
func To32Bytes(b []byte) [32]byte {
	var v [32]byte
	copy(v[:], b)
	return v
}

// Convert bool to int64
func BoolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// Convert int64 to bool
func Int64ToBool(i int64) bool {
	return i != 0
}
