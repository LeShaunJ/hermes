package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_defaults(t *testing.T) {
	cfg, err := Load("/nonexistent/path/hermes.yaml")
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Server.Addr != ":8080" {
		t.Errorf("Server.Addr = %q, want %q", cfg.Server.Addr, ":8080")
	}
	if cfg.DB.Host != "localhost" {
		t.Errorf("DB.Host = %q, want %q", cfg.DB.Host, "localhost")
	}
	if cfg.DB.Port != 5432 {
		t.Errorf("DB.Port = %d, want 5432", cfg.DB.Port)
	}
	if cfg.DB.SSLMode != "disable" {
		t.Errorf("DB.SSLMode = %q, want %q", cfg.DB.SSLMode, "disable")
	}
	if cfg.Trivy.Image != "aquasec/trivy:latest" {
		t.Errorf("Trivy.Image = %q, want %q", cfg.Trivy.Image, "aquasec/trivy:latest")
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want json", cfg.Log.Format)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want info", cfg.Log.Level)
	}
}

func TestLoad_logFromYAML(t *testing.T) {
	yaml := `
log:
  format: journald
  level: debug
`
	f, err := os.CreateTemp(t.TempDir(), "hermes*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Log.Format != "journald" {
		t.Errorf("Log.Format = %q, want journald", cfg.Log.Format)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
}

func TestLoad_serverURL_default(t *testing.T) {
	cfg, err := Load("/nonexistent/path/hermes.yaml")
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	// Default URL should be http://<hostname>:<port>.
	if !strings.HasPrefix(cfg.Server.URL, "http://") {
		t.Errorf("Server.URL = %q, want http:// prefix", cfg.Server.URL)
	}
	if !strings.HasSuffix(cfg.Server.URL, ":8080") {
		t.Errorf("Server.URL = %q, want :8080 suffix", cfg.Server.URL)
	}
}

func TestLoad_fromYAML(t *testing.T) {
	yaml := `
server:
  addr: ":9090"
  url: "http://myhost:9090"
  redirect: true

db:
  host: db.example.com
  port: 5433
  user: admin
  password: secret
  name: hermesdb
  sslmode: require

trivy:
  image: aquasec/trivy:0.50.0

cache_url: "cache.example.com"
`
	f, err := os.CreateTemp(t.TempDir(), "hermes*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Addr != ":9090" {
		t.Errorf("Server.Addr = %q, want :9090", cfg.Server.Addr)
	}
	if cfg.Server.URL != "http://myhost:9090" {
		t.Errorf("Server.URL = %q, want http://myhost:9090", cfg.Server.URL)
	}
	if !cfg.Server.Redirect {
		t.Error("Server.Redirect = false, want true")
	}
	if cfg.DB.Host != "db.example.com" {
		t.Errorf("DB.Host = %q, want db.example.com", cfg.DB.Host)
	}
	if cfg.DB.Port != 5433 {
		t.Errorf("DB.Port = %d, want 5433", cfg.DB.Port)
	}
	if cfg.DB.User != "admin" {
		t.Errorf("DB.User = %q, want admin", cfg.DB.User)
	}
	if cfg.DB.Password != "secret" {
		t.Errorf("DB.Password = %q, want secret", cfg.DB.Password)
	}
	if cfg.DB.Name != "hermesdb" {
		t.Errorf("DB.Name = %q, want hermesdb", cfg.DB.Name)
	}
	if cfg.DB.SSLMode != "require" {
		t.Errorf("DB.SSLMode = %q, want require", cfg.DB.SSLMode)
	}
	if cfg.Trivy.Image != "aquasec/trivy:0.50.0" {
		t.Errorf("Trivy.Image = %q, want aquasec/trivy:0.50.0", cfg.Trivy.Image)
	}
	if cfg.CacheURL != "cache.example.com" {
		t.Errorf("CacheURL = %q, want cache.example.com", cfg.CacheURL)
	}
}

func TestDBConfig_DSN(t *testing.T) {
	d := DBConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "hermes",
		Password: "secret",
		Name:     "hermesdb",
		SSLMode:  "disable",
	}
	dsn := d.DSN()
	want := "host=localhost port=5432 user=hermes password=secret dbname=hermesdb sslmode=disable"
	if dsn != want {
		t.Errorf("DSN() = %q, want %q", dsn, want)
	}
}

func TestLoad_invalidYAML(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "hermes*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{{{invalid yaml"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Error("Load() with invalid YAML expected error, got nil")
	}
}

func TestLoad_defaultURL_notOverwritten(t *testing.T) {
	// When server.url is set explicitly in YAML it must not be replaced.
	yaml := `
server:
  addr: ":8080"
  url: "https://gateway.example.com"
`
	f, err := os.CreateTemp(t.TempDir(), "hermes*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Server.URL != "https://gateway.example.com" {
		t.Errorf("Server.URL = %q, want https://gateway.example.com", cfg.Server.URL)
	}
}

// Ensure the test file is in the right directory.
var _ = filepath.Join
