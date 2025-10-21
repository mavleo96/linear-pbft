package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration for the distributed system
type Config struct {
	Nodes       map[string]*NodeEntry   `yaml:"nodes"`
	Clients     map[string]*ClientEntry `yaml:"clients"`
	DBDir       string                  `yaml:"db_dir"`
	InitBalance int                     `yaml:"init_balance"`
}

// NodeEntry represents a node entry in the config
type NodeEntry struct {
	ID      string `yaml:"id"`
	Address string `yaml:"address"`
}

// ClientEntry represents a client entry in the config
type ClientEntry struct {
	ID      string `yaml:"id"`
	Address string `yaml:"address"`
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
