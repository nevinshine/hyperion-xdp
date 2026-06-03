package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type PortRule struct {
	Protocol uint8  `yaml:"protocol"`
	Port     uint16 `yaml:"port"`
}

type FastPathConfig struct {
	DropIPs       []string   `yaml:"drop_ips"`
	RedirectPorts []PortRule `yaml:"redirect_ports"`
}

type Rule struct {
	Match  string `yaml:"match"`
	Action string `yaml:"action"`
}

type SlowPathConfig struct {
	DNSRules          []Rule `yaml:"dns_rules"`
	PayloadSignatures []Rule `yaml:"payload_signatures"`
}

type PolicyConfig struct {
	FastPath FastPathConfig `yaml:"fast_path"`
	SlowPath SlowPathConfig `yaml:"slow_path"`
}

func LoadPolicyConfig(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config PolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	return &config, nil
}
