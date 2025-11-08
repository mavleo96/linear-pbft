package linearpbft

// ByzantineConfig represents the configuration of a byzantine node
type ByzantineConfig struct {
	Alive                   bool
	Byzantine               bool
	SignAttack              bool
	CrashAttack             bool
	DarkAttack              bool
	DarkAttackNodes         []string
	TimeAttack              bool
	EquivocationAttack      bool
	EquivocationAttackNodes []string
}

// Reset resets the byzantine config
func (b *ByzantineConfig) Reset() {
	b.Alive = true
	b.Byzantine = false
	b.SignAttack = false
	b.CrashAttack = false
	b.DarkAttack = false
	b.DarkAttackNodes = make([]string, 0)
	b.TimeAttack = false
	b.EquivocationAttack = false
	b.EquivocationAttackNodes = make([]string, 0)
}

// CreateByzantineConfig creates a new byzantine config
func CreateByzantineConfig() *ByzantineConfig {
	return &ByzantineConfig{
		Alive:                   true,
		Byzantine:               false,
		SignAttack:              false,
		CrashAttack:             false,
		DarkAttack:              false,
		DarkAttackNodes:         make([]string, 0),
		TimeAttack:              false,
		EquivocationAttack:      false,
		EquivocationAttackNodes: make([]string, 0),
	}
}
