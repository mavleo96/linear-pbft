package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"gopkg.in/yaml.v3"
)

// Config holds the configuration for the distributed system
type Config struct {
	Nodes       map[string]*models.Node `yaml:"nodes"`
	Clients     []string                `yaml:"clients"`
	DBDir       string                  `yaml:"db_dir"`
	InitBalance int                     `yaml:"init_balance"`
}

// String returns a formatted, human-readable representation of the Config.
func (c *Config) String() string {
	var b strings.Builder

	// TODO: improve this
	b.WriteString("Nodes: ")
	for _, node := range c.Nodes {
		b.WriteString(node.ID + ", ")
	}
	b.WriteString("\nClients: ")
	b.WriteString(strings.Join(c.Clients, ", "))
	b.WriteString("\nDBDir: ")
	b.WriteString(c.DBDir)
	b.WriteString("\nInitBalance: ")
	b.WriteString(strconv.Itoa(c.InitBalance))
	b.WriteString("\n")
	return b.String()

}

// ParseConfig parses the config from a yaml file
func ParseConfig(cfgPath string) (*Config, error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return &Config{}, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return &Config{}, err
	}

	return &cfg, nil
}
