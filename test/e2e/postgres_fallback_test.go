//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/leshaunj/hermes/internal/config"
)

// dockerReachable probes for a local OCI daemon without starting a
// container. HERMES_E2E_DSN=<anything> forces the local-Postgres path.
func dockerReachable() bool {
	if os.Getenv("HERMES_E2E_DSN") != "" {
		return false
	}
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return dialDockerHost(h)
	}
	for _, p := range dockerSocketPaths() {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return true
		}
	}
	return false
}

func dockerSocketPaths() []string {
	paths := []string{"/var/run/docker.sock"}
	if home := os.Getenv("HOME"); home != "" {
		paths = append(paths,
			home+"/.colima/default/docker.sock",
			home+"/.docker/run/docker.sock",
			home+"/.rd/docker.sock",
		)
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		paths = append(paths, xdg+"/docker.sock", xdg+"/podman/podman.sock")
	}
	return paths
}

func dialDockerHost(h string) bool {
	u, err := url.Parse(h)
	if err != nil {
		return false
	}
	network, addr := "", ""
	switch u.Scheme {
	case "unix":
		network, addr = "unix", u.Path
	case "tcp", "http", "https":
		network, addr = "tcp", u.Host
	default:
		return false
	}
	c, err := net.DialTimeout(network, addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// adminDBConfig reads HERMES_DB_* with localhost defaults, mirroring
// the CLI's viper wiring in internal/config.
func adminDBConfig() config.DBConfig {
	get := func(k, def string) string {
		if v := os.Getenv("HERMES_DB_" + k); v != "" {
			return v
		}
		return def
	}
	port, _ := strconv.Atoi(get("PORT", "5432"))
	if port == 0 {
		port = 5432
	}
	return config.DBConfig{
		Host:     get("HOST", "localhost"),
		Port:     port,
		User:     get("USER", "hermes"),
		Password: get("PASSWORD", "hermes"),
		Name:     get("NAME", "hermes"),
		SSLMode:  get("SSLMODE", "disable"),
	}
}

// startLocalPG creates a unique database on the configured local
// Postgres and returns its coordinates. Unreachable-Postgres is a
// t.Fatalf, never a skip — a broken DB must not pass as green.
func startLocalPG(t *testing.T) (host string, port int, user, pass, dbname, dsn string) {
	t.Helper()

	base := adminDBConfig()
	admin, err := sql.Open("postgres", base.DSN())
	if err != nil {
		t.Fatalf("local pg open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("local pg unreachable at %s:%d (set HERMES_DB_* or start docker): %v",
			base.Host, base.Port, err)
	}

	name := uniqueDBName()
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		_ = admin.Close()
		t.Fatalf("create database %q: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`)
		_ = admin.Close()
	})

	per := base
	per.Name = name
	return per.Host, per.Port, per.User, per.Password, per.Name, per.DSN()
}

func uniqueDBName() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("hermes_e2e_%d_%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}
