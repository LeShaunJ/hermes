// Package config loads hermes configuration from /etc/hermes.yaml.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// DefaultPath is the canonical location of the hermes configuration file.
const DefaultPath = "/etc/hermes.yaml"

// Config is the top-level hermes configuration.
type Config struct {
	Server   ServerConfig `mapstructure:"server"`
	DB       DBConfig     `mapstructure:"db"`
	Trivy    TrivyConfig  `mapstructure:"trivy"`
	Log      LogConfig    `mapstructure:"log"`
	CacheURL string       `mapstructure:"cache_url"`
}

// LogConfig configures the global logger.  Format is one of "json" (standard
// slog JSON, Loki-compatible) or "journald" (JSON with journald MESSAGE /
// PRIORITY fields).  Level is one of "debug", "info", "warn", or "error".
type LogConfig struct {
	Format string `mapstructure:"format"`
	Level  string `mapstructure:"level"`
}

// ServerConfig configures the HTTP API server.
type ServerConfig struct {
	Addr     string `mapstructure:"addr"`
	URL      string `mapstructure:"url"`      // public base URL (default: http://hostname:port)
	Redirect bool   `mapstructure:"redirect"` // use HTTP 307 for blob paths instead of proxying
}

// DBConfig configures the PostgreSQL connection.
type DBConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
	SSLMode  string `mapstructure:"sslmode"`
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
	Image string `mapstructure:"image"`
	// Args are extra arguments appended to `trivy image`.
	Args []string `mapstructure:"args"`
	// ConvertArgs are extra arguments appended to `trivy convert`.
	ConvertArgs []string `mapstructure:"convert_args"`
}

// Load reads the YAML config at path using viper.
// Environment variables prefixed with HERMES_ override file values
// (e.g. HERMES_DB_PASSWORD overrides db.password).
// If path does not exist the default configuration is returned with no error.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults mirror the zero-value behaviour of the previous implementation.
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("db.host", "localhost")
	v.SetDefault("db.port", 5432)
	v.SetDefault("db.user", "hermes")
	v.SetDefault("db.name", "hermes")
	v.SetDefault("db.sslmode", "disable")
	v.SetDefault("trivy.image", "aquasec/trivy:latest")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.level", "info")

	// HERMES_DB_HOST, HERMES_DB_PASSWORD, HERMES_SERVER_ADDR, …
	v.SetEnvPrefix("hermes")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	// Compute default server.url from hostname + port when not set.
	if cfg.Server.URL == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}
		_, port, err := net.SplitHostPort(cfg.Server.Addr)
		if err != nil {
			port = strings.TrimPrefix(cfg.Server.Addr, ":")
		}
		cfg.Server.URL = "http://" + hostname + ":" + port
	}

	return &cfg, nil
}
