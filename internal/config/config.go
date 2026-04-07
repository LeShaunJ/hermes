// Package config loads hermes configuration from /etc/hermes.yaml.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the canonical location of the hermes configuration file.
const DefaultPath = "/etc/hermes.yaml"

// Config is the top-level hermes configuration.
type Config struct {
	Server   ServerConfig `yaml:"server"`
	DB       DBConfig     `yaml:"db"`
	Trivy    TrivyConfig  `yaml:"trivy"`
	CacheURL string       `yaml:"cache_url"`
}

// ServerConfig configures the HTTP API server.
type ServerConfig struct {
	Addr string `yaml:"addr"`
}

// DBConfig configures the PostgreSQL connection.
type DBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Name     string `yaml:"name"`
	SSLMode  string `yaml:"sslmode"`
}

// DSN returns a libpq-style connection string.
func (d DBConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode,
	)
}

// TrivyConfig configures the trivy container runner.
type TrivyConfig struct {
	// Image is the trivy Docker image to use (default: aquasec/trivy:latest).
	Image string `yaml:"image"`
	// Args are extra arguments appended to `trivy image`.
	Args []string `yaml:"args"`
	// ConvertArgs are extra arguments appended to `trivy convert`.
	ConvertArgs []string `yaml:"convert_args"`
}

// defaults returns a Config pre-populated with sensible defaults.
func defaults() Config {
	return Config{
		Server: ServerConfig{
			Addr: ":8080",
		},
		DB: DBConfig{
			Host:    "localhost",
			Port:    5432,
			User:    "hermes",
			Name:    "hermes",
			SSLMode: "disable",
		},
		Trivy: TrivyConfig{
			Image: "aquasec/trivy:latest",
		},
	}
}

// Load reads the YAML config at path.
// If path does not exist the default configuration is returned with no error.
func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	return &cfg, nil
}
