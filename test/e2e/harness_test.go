//go:build e2e

// Package e2e exercises the full stack: a real PostgreSQL instance, an
// in-process OCI upstream registry, and hermes's gateway wired to both.
// Tests use github.com/google/go-containerregistry as the OCI client so
// they catch protocol bugs that unit tests against mockStorage / sqlmock
// cannot surface (e.g. a query that compiles but returns wrong rows, or a
// proxy response whose headers are silently tolerated by net/http but
// rejected by real pull clients).
//
// Run with: go test -tags e2e ./test/e2e/...
//
// Requirements: a Docker-compatible daemon reachable via the standard
// DOCKER_HOST discovery (Docker Desktop, Colima, Rancher Desktop, podman
// with docker-compat socket, dockerd, etc.).  Tests skip cleanly when no
// daemon is available.  The postgres image (postgres:16-alpine) is pulled
// on first run and cached thereafter.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcwait "github.com/testcontainers/testcontainers-go/wait"

	"github.com/leshaunj/hermes/internal/api"
	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
)

// Disable testcontainers-go's Ryuk reaper sidecar.  Ryuk tries to attach
// to a Docker network literally named `bridge`, which doesn't exist on
// Colima, rootless Docker, and some podman setups — those environments
// error out with "network not found" before the real container even
// starts.  Our t.Cleanup callbacks already terminate containers on test
// exit, so we only lose the belt-and-suspenders guarantee that a
// SIGKILL-ed test process won't leak containers; `docker container
// prune` mops any up after an unclean shutdown.
func init() { _ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true") }

// stack bundles every live dependency a test needs.
type stack struct {
	pg       *postgres.PostgresContainer
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

	// Postgres connection details exposed for blackbox CLI tests that
	// need to materialise a hermes.yaml pointing at this instance.
	pgHost, pgUser, pgPassword, pgDatabase string
	pgPort                                 int
}

// newStack starts Postgres, the upstream registry, and hermes.  Every
// resource is registered with t.Cleanup so no goroutine leaks past the test.
func newStack(t *testing.T, opts ...stackOption) *stack {
	t.Helper()

	o := stackOptions{redirect: false}
	for _, f := range opts {
		f(&o)
	}

	ctx := context.Background()

	const (
		pgUser     = "hermes"
		pgPassword = "hermes"
		pgDatabase = "hermes"
	)

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase(pgDatabase),
		postgres.WithUsername(pgUser),
		postgres.WithPassword(pgPassword),
		testcontainers.WithWaitStrategy(
			tcwait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Skipf("postgres container: %v (is Docker/Podman running?)", err)
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(pgContainer) })

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	host, err := pgContainer.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	mapped, err := pgContainer.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}

	d, err := db.Open(dsn)
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
		pg:           pgContainer,
		db:           d,
		upstream:     upstream,
		hermes:       hermes,
		upstreamName: upstreamName,
		upstreamReal: upstreamReal,
		transport:    transport,
		pgHost:       host,
		pgPort:       mapped.Int(),
		pgUser:       pgUser,
		pgPassword:   pgPassword,
		pgDatabase:   pgDatabase,
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
