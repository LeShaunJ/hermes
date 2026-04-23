//go:build e2e

// Package e2e exercises the full stack: a real PostgreSQL process, an
// in-process OCI upstream registry, and hermes's gateway wired to both.
// Tests use github.com/google/go-containerregistry as the OCI client so
// they catch protocol bugs that unit tests against mockStorage / sqlmock
// cannot surface (e.g. a query that compiles but returns wrong rows, or a
// proxy response whose headers are silently tolerated by net/http but
// rejected by real pull clients).
//
// Run with: go test -tags e2e ./test/e2e/...
//
// Requirements: the host must have PostgreSQL 16 binaries (initdb,
// pg_ctl, postgres) on PATH or at /usr/lib/postgresql/16/bin.  No Docker
// daemon is required — the upstream registry runs in-process.
package e2e

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/leshaunj/hermes/internal/api"
	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
)

// stack bundles every live dependency a test needs.
type stack struct {
	pg       *pgProcess
	db       *db.DB
	upstream *httptest.Server // in-process OCI registry acting as upstream
	hermes   *httptest.Server // hermes gateway under test

	// upstreamName is the pseudo-host ("upstream.test") stored in the DB
	// and used in refs the client sends.  The rewriteTransport translates
	// it to upstreamReal ("127.0.0.1:<port>") on every outbound call so
	// both hermes and crane can reach the real httptest upstream without
	// colon-in-path ambiguity breaking ref parsing.
	upstreamName string
	upstreamReal string

	// transport is the rewriting RoundTripper clients need to dial the
	// pseudo-host.  Tests pass this to crane.WithTransport(...).
	transport http.RoundTripper
}

// newStack starts Postgres, the upstream registry, and hermes.  Every
// resource is registered with t.Cleanup so no goroutine leaks past the test.
func newStack(t *testing.T, opts ...stackOption) *stack {
	t.Helper()

	o := stackOptions{redirect: false}
	for _, f := range opts {
		f(&o)
	}

	pg := startPostgres(t)
	d, err := db.Open(pg.dsn)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(d.Close)

	// Bearer-auth middleware sits in front of the in-process registry so
	// the full /v2/ → 401 → /token → bearer handshake runs end-to-end.
	// A production-like auth dance catches bugs (header rewriting, token
	// pass-through) that an auth-less registry hides.
	registryHandler := registry.New()
	ua := newUpstreamAuth()
	upstream := httptest.NewServer(ua.wrap(registryHandler))
	t.Cleanup(upstream.Close)
	upstreamReal := hostPortOf(t, upstream.URL)
	ua.base = "http://" + upstreamReal

	const upstreamName = "upstream.test"
	transport := &rewriteTransport{
		base:   http.DefaultTransport,
		scheme: "http",
		from:   map[string]bool{upstreamName: true},
		to:     upstreamReal,
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Addr:     ":0",
			Redirect: o.redirect,
		},
	}
	srv := api.New(d, cfg)
	srv.SetTransport(transport)

	hermes := httptest.NewServer(srv.Handler())
	t.Cleanup(hermes.Close)

	// WWW-Authenticate realm rewriting relies on cfg.Server.URL — fill it
	// in now that httptest has assigned a port.
	cfg.Server.URL = hermes.URL

	return &stack{
		pg:           pg,
		db:           d,
		upstream:     upstream,
		hermes:       hermes,
		upstreamName: upstreamName,
		upstreamReal: upstreamReal,
		transport:    transport,
	}
}

type stackOption func(*stackOptions)
type stackOptions struct {
	redirect bool
}

func withRedirect() stackOption { return func(o *stackOptions) { o.redirect = true } }

// hermesHost returns "<host>:<port>" of the hermes gateway.
func (s *stack) hermesHost(t *testing.T) string {
	t.Helper()
	return hostPortOf(t, s.hermes.URL)
}

// ref builds the hermes-rooted client-facing image reference for
// "<upstream>/<repo>:<tag>".
func (s *stack) ref(t *testing.T, repo, tag string) string {
	return fmt.Sprintf("%s/%s/%s:%s", s.hermesHost(t), s.upstreamName, repo, tag)
}

// upstreamRef builds the upstream-rooted reference used for seeding fixtures.
// Clients must dial via s.transport (crane.WithTransport) so the pseudo-host
// resolves to the real httptest port.
func (s *stack) upstreamRef(repo, tag string) string {
	return fmt.Sprintf("%s/%s:%s", s.upstreamName, repo, tag)
}

// rewriteTransport redirects requests whose Host matches any entry in
// `from` to `to` under the given scheme.  Every other request passes
// through untouched, so crane calls hermes directly while hermes's
// outbound calls to the pseudo-host(s) are transparently routed to the
// real httptest upstream.  Multi-host support lets tests exercise
// registry-mask chains (docker.io / registry-1.docker.io).
type rewriteTransport struct {
	base   http.RoundTripper
	scheme string
	from   map[string]bool
	to     string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.from[req.URL.Host] || rt.from[req.Host] {
		req = req.Clone(req.Context())
		req.URL.Scheme = rt.scheme
		req.URL.Host = rt.to
		req.Host = rt.to
	}
	return rt.base.RoundTrip(req)
}

// registerPseudoHost adds another name that rewriteTransport should map
// onto the real upstream.  Safe to call before any test request runs.
func (rt *rewriteTransport) registerPseudoHost(name string) {
	rt.from[name] = true
}

// hostPortOf extracts "<host>:<port>" from a URL like "http://127.0.0.1:40123".
func hostPortOf(t *testing.T, rawURL string) string {
	t.Helper()
	// rawURL is always "<scheme>://<host>:<port>" from httptest.
	for _, prefix := range []string{"http://", "https://"} {
		if len(rawURL) > len(prefix) && rawURL[:len(prefix)] == prefix {
			return rawURL[len(prefix):]
		}
	}
	t.Fatalf("unexpected httptest URL: %q", rawURL)
	return ""
}

// ── Postgres harness ──────────────────────────────────────────────────────────

type pgProcess struct {
	dataDir string
	sockDir string
	port    int
	dsn     string
	cmd     *exec.Cmd
}

const pgBinDir = "/usr/lib/postgresql/16/bin"

// startPostgres provisions a fresh Postgres cluster in a tmpdir, starts the
// server on a random port + unix socket, creates the hermes database, and
// registers cleanup.  Skips the test if Postgres binaries aren't installed.
// When invoked as root, drops privileges to the local `postgres` account
// because initdb refuses to run as root.
func startPostgres(t *testing.T) *pgProcess {
	t.Helper()
	initdb := resolvePGBin(t, "initdb")
	postgres := resolvePGBin(t, "postgres")
	createdb := resolvePGBin(t, "createdb")

	cred := unprivilegedCredential(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	sockDir := filepath.Join(root, "sock")
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		t.Fatalf("mkdir sock: %v", err)
	}
	if cred != nil {
		// initdb-as-postgres needs traverse rights on every ancestor of
		// dataDir.  t.TempDir() creates pid dirs with mode 0700, so relax
		// the whole chain to 0755 for this ephemeral test fixture.
		for d := root; d != "/" && d != "."; d = filepath.Dir(d) {
			_ = os.Chmod(d, 0o755)
		}
		for _, d := range []string{root, sockDir} {
			if err := os.Chown(d, int(cred.Uid), int(cred.Gid)); err != nil {
				t.Fatalf("chown %s: %v", d, err)
			}
		}
	}

	runAs(t, cred, exec.Command(initdb,
		"-D", dataDir,
		"-U", "hermes",
		"--auth=trust",
		"--encoding=UTF8",
		"--no-sync",
	))

	port, err := freePort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}

	cmd := exec.Command(postgres,
		"-D", dataDir,
		"-p", fmt.Sprint(port),
		"-k", sockDir,
		"-c", "listen_addresses=127.0.0.1",
		"-c", "fsync=off",
		"-c", "full_page_writes=off",
		"-c", "synchronous_commit=off",
	)
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
	})

	dsn := fmt.Sprintf("host=127.0.0.1 port=%d user=hermes dbname=postgres sslmode=disable", port)
	if err := waitPGReady(dsn, 20*time.Second); err != nil {
		t.Fatalf("postgres never became ready: %v", err)
	}

	runAs(t, cred, exec.Command(createdb, "-h", "127.0.0.1", "-p", fmt.Sprint(port), "-U", "hermes", "hermes"))

	return &pgProcess{
		dataDir: dataDir,
		sockDir: sockDir,
		port:    port,
		dsn:     fmt.Sprintf("host=127.0.0.1 port=%d user=hermes dbname=hermes sslmode=disable", port),
		cmd:     cmd,
	}
}

// unprivilegedCredential returns a *syscall.Credential for the local
// `postgres` account when the test is running as root, or nil otherwise.
// initdb refuses to run as root, so CI or dev sandboxes that execute tests
// as uid 0 need to drop privileges for the Postgres subprocesses.
func unprivilegedCredential(t *testing.T) *syscall.Credential {
	t.Helper()
	if os.Geteuid() != 0 {
		return nil
	}
	u, err := user.Lookup("postgres")
	if err != nil {
		t.Skipf("running as root and no 'postgres' user available to drop privileges to: %v", err)
		return nil
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("parse postgres uid: %v", err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Fatalf("parse postgres gid: %v", err)
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
}

// runAs executes c, optionally under the given credential, and fails the
// test with command output on error.
func runAs(t *testing.T, cred *syscall.Credential, c *exec.Cmd) {
	t.Helper()
	if cred != nil {
		c.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", filepath.Base(c.Path), err, string(out))
	}
}

func resolvePGBin(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	candidate := filepath.Join(pgBinDir, name)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	t.Skipf("postgres tool %q not found (looked in PATH and %s)", name, pgBinDir)
	return ""
}

func waitPGReady(dsn string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := sql.Open("postgres", dsn)
		if err == nil {
			pingErr := conn.Ping()
			_ = conn.Close()
			if pingErr == nil {
				return nil
			}
			lastErr = pingErr
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out: %w", lastErr)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
