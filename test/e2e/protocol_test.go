//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
)

// TestProtocol_HeadMatchesGet ensures that HEAD and GET on an approved
// manifest return the same status, Content-Type, and Docker-Content-
// Digest.  Docker's pull client issues HEAD first and refuses to
// continue when the digest header is missing or different from the GET
// response, so a silent HEAD regression fails pulls in ways that only
// appear with real clients.
func TestProtocol_HeadMatchesGet(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	approve(t, s, "myorg/app", "v1")

	manifestURL := s.hermes.URL + "/v2/" + s.upstreamName + "/myorg/app/manifests/v1"

	get := doMethod(t, http.MethodGet, manifestURL)
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", get.StatusCode)
	}
	gotDigest := get.Header.Get("Docker-Content-Digest")
	gotCT := get.Header.Get("Content-Type")

	head := doMethod(t, http.MethodHead, manifestURL)
	_ = head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", head.StatusCode)
	}
	if h := head.Header.Get("Docker-Content-Digest"); h != gotDigest {
		t.Errorf("HEAD Docker-Content-Digest = %q, want %q (matching GET)", h, gotDigest)
	}
	if h := head.Header.Get("Content-Type"); h != gotCT {
		t.Errorf("HEAD Content-Type = %q, want %q (matching GET)", h, gotCT)
	}
}

// TestProtocol_AcceptHeaderFanout replays the multi-value Accept header
// that real OCI clients (docker, podman, containerd) send with every
// manifest request.  Hermes must pass it through to the upstream so the
// client gets the manifest variant it asked for.  A regression (e.g.
// stripping headers during proxying) would show up as docker pulling an
// unexpected media type and erroring out.
func TestProtocol_AcceptHeaderFanout(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	approve(t, s, "myorg/app", "v1")

	req, err := http.NewRequest(http.MethodGet,
		s.hermes.URL+"/v2/"+s.upstreamName+"/myorg/app/manifests/v1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Mirror docker client: several variants, prefer OCI manifest.
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"*/*",
	}, ", "))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with multi-Accept: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	// The returned media type must be one of the Accept-listed variants.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "manifest") && !strings.Contains(ct, "index") {
		t.Errorf("Content-Type = %q, expected an OCI/Docker manifest media type", ct)
	}
}

// TestProtocol_HealthzStaysSimple guards against accidentally routing
// /healthz through the auth or OCI handler.  It must always return 200
// with a plain body — the container's HEALTHCHECK relies on this and a
// regression (e.g. adding middleware that challenges /healthz) silently
// breaks health probes in production.
func TestProtocol_HealthzStaysSimple(t *testing.T) {
	s := newStack(t)

	resp := mustGet(t, s.hermes.URL+"/healthz")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := strings.TrimSpace(string(body)); got != "ok" {
		t.Errorf("/healthz body = %q, want %q", got, "ok")
	}
}

// TestProtocol_V2RootReturnsChallenge verifies the very first request an
// OCI client makes — GET /v2/ — returns 401 with a WWW-Authenticate
// header pointing at /ident.  This is the dance every pull starts with,
// and a regression (missing realm, wrong realm, wrong status) breaks
// authentication before any other code path runs.
func TestProtocol_V2RootReturnsChallenge(t *testing.T) {
	s := newStack(t)

	resp := mustGet(t, s.hermes.URL+"/v2/")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/v2/ status = %d, want 401", resp.StatusCode)
	}
	auth := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("WWW-Authenticate = %q, want Bearer challenge", auth)
	}
	if !strings.Contains(auth, "/ident") {
		t.Errorf("WWW-Authenticate realm does not point at /ident: %q", auth)
	}
}

// TestProtocol_PullByDigest covers the digest-addressed pull path —
// different code in serveOCI from tag pulls, with its own short-circuit
// around alternate-tag adoption.  Clients that resolved a tag to a
// digest earlier use this path for every subsequent pull.
func TestProtocol_PullByDigest(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	digest := mustDigest(t, img)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	approve(t, s, "myorg/app", "v1")

	digestRef := s.hermesHost(t) + "/" + s.upstreamName + "/myorg/app@" + digest
	pulled, err := crane.Pull(digestRef, crane.Insecure, crane.WithTransport(s.transport))
	if err != nil {
		t.Fatalf("crane.Pull by digest: %v", err)
	}
	if got := mustDigest(t, pulled); got != digest {
		t.Errorf("digest-pull returned %s, want %s", got, digest)
	}
}

// ── helpers (protocol) ────────────────────────────────────────────────────────

func doMethod(t *testing.T, method, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}
