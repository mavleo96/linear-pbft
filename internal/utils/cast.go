package utils

func To32Bytes(b []byte) [32]byte {
	var v [32]byte
	copy(v[:], b)
	return v
}
