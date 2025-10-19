package models

// Node represents a node in the distributed system
type Node struct {
	ID        string `yaml:"id"`
	Address   string `yaml:"address"`
	PublicKey []byte
}

// String returns a string representation of the node
func (n *Node) String() string {
	return n.ID
}
