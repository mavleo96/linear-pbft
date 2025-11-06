package crypto

import (
	"os"
	"strings"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// Read private key from file
func ReadPrivateKey(path string) (*bls.SecretKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sk bls.SecretKey
	if err := sk.Deserialize(data); err != nil {
		return nil, err
	}
	return &sk, nil
}

// Read public key from file
func ReadPublicKey(path string) (*bls.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pk bls.PublicKey
	if err := pk.Deserialize(data); err != nil {
		return nil, err
	}
	return &pk, nil
}

// Convert node ID to BLS mask ID
func NodeIDToBLSMaskID(nodeID string) bls.ID {
	var id bls.ID
	id.SetDecString(strings.ReplaceAll(nodeID, "n", ""))
	return id
}
