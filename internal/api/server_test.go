package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
)

// ── mock storage ──────────────────────────────────────────────────────────────

type mockStorage struct {
	approved            *db.Image
	approvedErr         error
	approvedByDigest    *db.Image
	approvedDigestErr   error
	approvedByTagDigest *db.Image
	approvedTagDigErr   error
	rejected            *db.Image
	rejectedErr         error
	queueStubErr        error
	logEventErr         error

	adoptResult bool
	adoptErr    error
	adoptCalls  int

	blobAuthorized   bool
	blobAuthCache    string
	blobAuthErr      error
	blobAuthRegistry string
	blobAuthRepo     string
	blobAuthDigest   string
}

func (m *mockStorage) GetApproved(_, _, _ string) (*db.Image, error) {
	return m.approved, m.approvedErr
}
func (m *mockStorage) GetApprovedByDigest(_, _, _ string) (*db.Image, error) {
	return m.approvedByDigest, m.approvedDigestErr
}
func (m *mockStorage) GetApprovedByTagAndDigest(_, _, _, _ string) (*db.Image, error) {
	return m.approvedByTagDigest, m.approvedTagDigErr
}
func (m *mockStorage) GetRejected(_, _, _ string) (*db.Image, error) {
	return m.rejected, m.rejectedErr
}
func (m *mockStorage) QueueStub(_ db.ImageRef) error { return m.queueStubErr }
func (m *mockStorage) AdoptTagByDigest(_ db.ImageRef, _ string) (bool, error) {
	m.adoptCalls++
	return m.adoptResult, m.adoptErr
}
func (m *mockStorage) BlobAuthorized(registry, repository, digest string) (bool, string, error) {
	m.blobAuthRegistry = registry
	m.blobAuthRepo = repository
	m.blobAuthDigest = digest
	return m.blobAuthorized, m.blobAuthCache, m.blobAuthErr
}
func (m *mockStorage) LogEvent(_ *int64, _ db.EventSource, _ string, _ map[string]interface{}) error {
	return m.logEventErr
}

// newTestServer returns a Server wired with a nil DB and minimal config for
// unit tests that do not exercise database queries.
func newTestServer(url string, redirect bool) *Server {
	return &Server{
		cfg: &config.Config{
			Server: config.ServerConfig{
				Addr:     ":8080",
				URL:      url,
				Redirect: redirect,
			},
		},
		mux: http.NewServeMux(),
	}
}

func newMockServer(store storage, url string, redirect bool) *Server {
	s := &Server{
		db: store,
		cfg: &config.Config{
			Server: config.ServerConfig{
				Addr:     ":8080",
				URL:      url,
				Redirect: redirect,
			},
		},
		mux: http.NewServeMux(),
	}
	s.mux.HandleFunc("/v2/", s.serveOCI)
	s.mux.HandleFunc("/v2", s.serveOCI)
	s.mux.HandleFunc("/ident/", s.serveIdent)
	s.mux.HandleFunc("/ident", s.serveIdent)
	s.mux.HandleFunc("GET /healthz", s.serveHealthz)
	return s
}

func makeTestImage(state db.State) *db.Image {
	return &db.Image{
		ID:          1,
		RegistryURL: "registry.example.com",
		Repository:  "myrepo",
		TagName:     "latest",
		Digest:      "sha256:abc123",
		Arch:        "amd64",
		OS:          "linux",
		State:       state,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// ── parseV2Path ───────────────────────────────────────────────────────────────

func TestParseV2Path(t *testing.T) {
	tests := []struct {
		path    string
		want    parsedPath
		wantErr bool
	}{
		{
			path: "/v2/registry.example.com/myrepo/manifests/latest",
			want: parsedPath{
				Registry:   "registry.example.com",
				Repository: "myrepo",
				Tag:        "latest",
				Kind:       refKindTag,
			},
		},
		{
			path: "/v2/registry.example.com/org/myrepo/manifests/v1.2.3",
			want: parsedPath{
				Registry:   "registry.example.com",
				Repository: "org/myrepo",
				Tag:        "v1.2.3",
				Kind:       refKindTag,
			},
		},
		{
			path: "/v2/registry.example.com/myrepo/manifests/sha256:abc123def456",
			want: parsedPath{
				Registry:   "registry.example.com",
				Repository: "myrepo",
				Digest:     "sha256:abc123def456",
				Kind:       refKindDigest,
			},
		},
		{
			path: "/v2/registry.example.com/myrepo/manifests/latest@sha256:abc123",
			want: parsedPath{
				Registry:   "registry.example.com",
				Repository: "myrepo",
				Tag:        "latest",
				Digest:     "sha256:abc123",
				Kind:       refKindTagAndDigest,
			},
		},
		{
			path: "/v2/registry.example.com/myrepo/blobs/sha256:abc123",
			want: parsedPath{
				Registry:   "registry.example.com",
				Repository: "myrepo",
				Digest:     "sha256:abc123",
				Kind:       refKindBlob,
			},
		},
		{
			path: "/v2/registry.example.com/myrepo/blobs/uploads/abc",
			want: parsedPath{
				Registry: "registry.example.com",
				Kind:     refKindOther,
			},
		},
		{
			path: "/v2/registry.example.com/myrepo/tags/list",
			want: parsedPath{
				Registry: "registry.example.com",
				Kind:     refKindOther,
			},
		},
		{
			path:    "not/v2/path",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got, err := parseV2Path(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Kind != tc.want.Kind {
				t.Errorf("Kind = %d, want %d", got.Kind, tc.want.Kind)
			}
			if got.Registry != tc.want.Registry {
				t.Errorf("Registry = %q, want %q", got.Registry, tc.want.Registry)
			}
			if got.Repository != tc.want.Repository {
				t.Errorf("Repository = %q, want %q", got.Repository, tc.want.Repository)
			}
			if got.Tag != tc.want.Tag {
				t.Errorf("Tag = %q, want %q", got.Tag, tc.want.Tag)
			}
			if got.Digest != tc.want.Digest {
				t.Errorf("Digest = %q, want %q", got.Digest, tc.want.Digest)
			}
		})
	}
}

// ── writeOCIError ─────────────────────────────────────────────────────────────

func TestWriteOCIError(t *testing.T) {
	s := newTestServer("http://localhost:8080", false)

	tests := []struct {
		status  int
		code    string
		message string
	}{
		{http.StatusUnauthorized, "UNAUTHORIZED", "approval required"},
		{http.StatusForbidden, "DENIED", "image has been rejected"},
		{http.StatusBadRequest, "UNSUPPORTED", "bad path"},
		{http.StatusInternalServerError, "UNKNOWN", "internal error"},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.writeOCIError(rec, tc.status, tc.code, tc.message)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if v := rec.Header().Get("Docker-Distribution-API-Version"); v != "registry/2.0" {
				t.Errorf("Docker-Distribution-API-Version = %q, want registry/2.0", v)
			}

			var body ociErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if len(body.Errors) != 1 {
				t.Fatalf("len(errors) = %d, want 1", len(body.Errors))
			}
			if body.Errors[0].Code != tc.code {
				t.Errorf("error code = %q, want %q", body.Errors[0].Code, tc.code)
			}
			if body.Errors[0].Message != tc.message {
				t.Errorf("error message = %q, want %q", body.Errors[0].Message, tc.message)
			}
		})
	}
}

// ── healthz ───────────────────────────────────────────────────────────────────

func TestHealthz(t *testing.T) {
	s := newTestServer("http://localhost:8080", false)
	s.mux.HandleFunc("GET /healthz", s.serveHealthz)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
}

// ── serveOCI /v2/ root ────────────────────────────────────────────────────────

func TestServeOCI_v2Root(t *testing.T) {
	s := New(nil, &config.Config{
		Server: config.ServerConfig{Addr: ":8080", URL: "http://localhost:8080"},
	})

	for _, path := range []string{"/v2", "/v2/"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if v := rec.Header().Get("Docker-Distribution-API-Version"); v != "registry/2.0" {
				t.Errorf("Docker-Distribution-API-Version = %q, want registry/2.0", v)
			}
		})
	}
}

// ── serveOCI with mock DB ─────────────────────────────────────────────────────

func TestServeOCI_approved_tag(t *testing.T) {
	img := makeTestImage(db.StateApproved)
	store := &mockStorage{approved: img}
	s := newMockServer(store, "http://localhost:8080", true) // redirect mode to avoid proxy dial

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	// Redirect mode: should get 307 pointing to upstream.
	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Error("Location header not set for approved redirect")
	}
}

func TestServeOCI_approved_digest(t *testing.T) {
	img := makeTestImage(db.StateApproved)
	store := &mockStorage{approvedByDigest: img}
	s := newMockServer(store, "http://localhost:8080", true)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/sha256:abc123", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
}

func TestServeOCI_approved_tagAndDigest(t *testing.T) {
	img := makeTestImage(db.StateApproved)
	store := &mockStorage{approvedByTagDigest: img}
	s := newMockServer(store, "http://localhost:8080", true)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/latest@sha256:abc123", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
}

func TestServeOCI_approved_emptyDigest(t *testing.T) {
	// When image.Digest is empty, fall back to tag.
	img := makeTestImage(db.StateApproved)
	img.Digest = ""
	store := &mockStorage{approved: img}
	s := newMockServer(store, "http://localhost:8080", true)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
}

func TestServeOCI_approved_forwardsToCacheRegistry(t *testing.T) {
	// Approved image with a cache registry: the redirect Location must point
	// at the cache host, not the origin (p.Registry).
	img := makeTestImage(db.StateApproved)
	img.CacheRegistry = "cache.internal.example.com"
	store := &mockStorage{approved: img}
	s := newMockServer(store, "http://localhost:8080", true)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "cache.internal.example.com") {
		t.Errorf("Location = %q, want cache host", loc)
	}
	if strings.Contains(loc, "registry.example.com") {
		t.Errorf("Location = %q, must not reference origin", loc)
	}
}

func TestServeOCI_approved_uncachedForwardsToOrigin(t *testing.T) {
	img := makeTestImage(db.StateApproved)
	img.CacheRegistry = "" // uncached
	store := &mockStorage{approved: img}
	s := newMockServer(store, "http://localhost:8080", true)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "registry.example.com") {
		t.Errorf("Location = %q, want origin host", loc)
	}
}

func TestServeOCI_rejected(t *testing.T) {
	img := makeTestImage(db.StateRejected)
	store := &mockStorage{rejected: img}
	s := newMockServer(store, "http://localhost:8080", false)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	var body ociErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Errors[0].Code != "DENIED" {
		t.Errorf("code = %q, want DENIED", body.Errors[0].Code)
	}
}

func TestServeOCI_unknown_returns401(t *testing.T) {
	// No approved, no rejected, upstream returns 404 → our 401 UNAUTHORIZED.
	srv, host := newUpstreamBackend(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()

	store := &mockStorage{}
	s := newMockServer(store, "http://localhost:8080", false)
	s.transport = http.DefaultTransport

	req := httptest.NewRequest(http.MethodGet, "/v2/"+host+"/myrepo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestServeOCI_dbError(t *testing.T) {
	store := &mockStorage{approvedErr: fmt.Errorf("connection refused")}
	s := newMockServer(store, "http://localhost:8080", false)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestServeOCI_otherPath_redirect(t *testing.T) {
	// Tag-list paths (and other non-blob, non-manifest paths) should redirect
	// unconditionally.
	store := &mockStorage{}
	s := newMockServer(store, "http://localhost:8080", true) // redirect=true

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/tags/list", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
}

// ── serveOCI blob gatekeeping ─────────────────────────────────────────────────

func TestServeOCI_blob_authorized(t *testing.T) {
	store := &mockStorage{blobAuthorized: true}
	s := newMockServer(store, "http://localhost:8080", true)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/blobs/sha256:abc", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
	if store.blobAuthDigest != "sha256:abc" {
		t.Errorf("BlobAuthorized digest = %q, want sha256:abc", store.blobAuthDigest)
	}
	if store.blobAuthRepo != "myrepo" {
		t.Errorf("BlobAuthorized repo = %q, want myrepo", store.blobAuthRepo)
	}
}

func TestServeOCI_blob_authorized_forwardsToCache(t *testing.T) {
	store := &mockStorage{
		blobAuthorized: true,
		blobAuthCache:  "cache.internal.example.com",
	}
	s := newMockServer(store, "http://localhost:8080", true)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/blobs/sha256:abc", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "cache.internal.example.com") {
		t.Errorf("Location = %q, want cache host", loc)
	}
	if strings.Contains(loc, "registry.example.com") {
		t.Errorf("Location = %q, must not reference origin", loc)
	}
}

func TestServeOCI_blob_unauthorized(t *testing.T) {
	store := &mockStorage{blobAuthorized: false}
	s := newMockServer(store, "http://localhost:8080", false)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/blobs/sha256:abc", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	var body ociErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Errors[0].Code != "UNAUTHORIZED" {
		t.Errorf("code = %q, want UNAUTHORIZED", body.Errors[0].Code)
	}
}

func TestServeOCI_blob_dbError(t *testing.T) {
	store := &mockStorage{blobAuthErr: fmt.Errorf("connection refused")}
	s := newMockServer(store, "http://localhost:8080", false)

	req := httptest.NewRequest(http.MethodGet, "/v2/registry.example.com/myrepo/blobs/sha256:abc", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// ── serveOCI alt-tag adoption ─────────────────────────────────────────────────

// newUpstreamBackend returns an httptest.Server that pretends to be the
// upstream registry.  The handler is supplied by the caller so each test can
// control the status code, headers, and body returned for the manifest
// request.  The returned base host (without scheme) should be used as the
// registry segment of the request path.
func newUpstreamBackend(handler http.HandlerFunc) (*httptest.Server, string) {
	srv := httptest.NewServer(handler)
	// httptest URLs are "http://127.0.0.1:<port>" — strip the scheme.
	return srv, strings.TrimPrefix(srv.URL, "http://")
}

func TestServeOCI_altTag_adopted(t *testing.T) {
	srv, host := newUpstreamBackend(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/v2/myrepo/manifests/v2.0" {
			t.Errorf("upstream path = %q, want /v2/myrepo/manifests/v2.0", got)
		}
		w.Header().Set("Docker-Content-Digest", "sha256:adopted")
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"manifests":[]}`))
	})
	defer srv.Close()

	store := &mockStorage{adoptResult: true}
	s := newMockServer(store, "http://localhost:8080", false) // redirect forced off by hook
	s.transport = http.DefaultTransport

	req := httptest.NewRequest(http.MethodGet, "/v2/"+host+"/myrepo/manifests/v2.0", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if store.adoptCalls != 1 {
		t.Errorf("adoptCalls = %d, want 1", store.adoptCalls)
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != "sha256:adopted" {
		t.Errorf("Docker-Content-Digest = %q, want sha256:adopted", got)
	}
}

func TestServeOCI_altTag_notAdopted_rewritesTo401(t *testing.T) {
	// Upstream returns 200 with a digest that doesn't match anything
	// approved — hook should rewrite to 401 and stub-register.
	srv, host := newUpstreamBackend(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:unknown")
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"manifests":[]}`))
	})
	defer srv.Close()

	store := &mockStorage{adoptResult: false}
	s := newMockServer(store, "http://localhost:8080", false)
	s.transport = http.DefaultTransport

	req := httptest.NewRequest(http.MethodGet, "/v2/"+host+"/myrepo/manifests/v2.0", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if store.adoptCalls != 1 {
		t.Errorf("adoptCalls = %d, want 1", store.adoptCalls)
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != "" {
		t.Errorf("Docker-Content-Digest should be stripped, got %q", got)
	}
	var body ociErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Errors[0].Code != "UNAUTHORIZED" {
		t.Errorf("code = %q, want UNAUTHORIZED", body.Errors[0].Code)
	}
}

func TestServeOCI_altTag_upstreamError_rewritesTo401(t *testing.T) {
	// Upstream returns a 401 (auth failure) or 404 (not found).  Hermes
	// should still return its own 401 so the client's approval workflow
	// kicks in rather than retrying upstream auth.
	srv, host := newUpstreamBackend(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`))
	})
	defer srv.Close()

	store := &mockStorage{}
	s := newMockServer(store, "http://localhost:8080", false)
	s.transport = http.DefaultTransport

	req := httptest.NewRequest(http.MethodGet, "/v2/"+host+"/myrepo/manifests/v2.0", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if store.adoptCalls != 0 {
		t.Errorf("adoptCalls = %d, want 0 (upstream non-200 must not trigger adoption)", store.adoptCalls)
	}
}

func TestServeOCI_altTag_missingDigestHeader_rewritesTo401(t *testing.T) {
	// Upstream returns 200 but no Docker-Content-Digest header — no adoption
	// should be attempted; hook rewrites to 401.
	srv, host := newUpstreamBackend(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	})
	defer srv.Close()

	store := &mockStorage{}
	s := newMockServer(store, "http://localhost:8080", false)
	s.transport = http.DefaultTransport

	req := httptest.NewRequest(http.MethodGet, "/v2/"+host+"/myrepo/manifests/v2.0", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if store.adoptCalls != 0 {
		t.Errorf("adoptCalls = %d, want 0", store.adoptCalls)
	}
}

// ── proxyOrRedirect with hooks ────────────────────────────────────────────────

func TestProxyOrRedirect_hookForcesProxyMode(t *testing.T) {
	// Even in redirect mode, supplying a responseHook forces proxy so the
	// hook can see the upstream response.
	called := false
	srv, host := newUpstreamBackend(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	defer srv.Close()

	s := newTestServer("http://localhost:8080", true) // redirect=true
	s.db = &mockStorage{}
	s.transport = http.DefaultTransport

	req := httptest.NewRequest(http.MethodGet, "/v2/"+host+"/foo", nil)
	rec := httptest.NewRecorder()
	s.proxyOrRedirect(rec, req, host, "/v2/foo", func(_ *http.Response) error {
		called = true
		return nil
	})

	if !called {
		t.Error("responseHook was not invoked — redirect mode was not overridden")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// ── challengeParse ────────────────────────────────────────────────────────────

func TestChallengeParse(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		account string
		want    string
	}{
		{
			name:    "full bearer challenge",
			header:  `Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:myrepo:pull"`,
			account: "",
			want:    "https://auth.example.com/token?service=registry.example.com&scope=repository:myrepo:pull",
		},
		{
			name:    "with account",
			header:  `Bearer realm="https://auth.example.com/token",service="registry.example.com"`,
			account: "myuser",
			want:    "https://auth.example.com/token?account=myuser&service=registry.example.com",
		},
		{
			name:    "realm only",
			header:  `Bearer realm="https://auth.example.com/token"`,
			account: "",
			want:    "https://auth.example.com/token",
		},
		{
			name:    "empty header",
			header:  "",
			account: "",
			want:    "",
		},
		{
			name:    "no realm",
			header:  `Bearer service="registry.example.com"`,
			account: "",
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := challengeParse(tc.header, tc.account)
			if got != tc.want {
				t.Errorf("challengeParse() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── serveIdent ────────────────────────────────────────────────────────────────

func TestServeIdent_missingScope(t *testing.T) {
	s := newMockServer(nil, "http://localhost:8080", false)

	req := httptest.NewRequest(http.MethodGet, "/ident/?account=test", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var body ociErrorResponse
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body.Errors[0].Code != "UNSUPPORTED" {
		t.Errorf("code = %q, want UNSUPPORTED", body.Errors[0].Code)
	}
}

func TestServeIdent_malformedScope(t *testing.T) {
	s := newMockServer(nil, "http://localhost:8080", false)

	// scope= without "repository:registry/repo:pull" format
	req := httptest.NewRequest(http.MethodGet, "/ident/?scope=notavalidscope", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestServeIdent_noChallengeRetrieved(t *testing.T) {
	s := newMockServer(nil, "http://localhost:8080", false)
	// Override challengeRetrieve to return empty string.
	s.challengeRetrieveFn = func(_, _ string) string { return "" }

	req := httptest.NewRequest(http.MethodGet,
		"/ident/?scope=repository:registry.example.com/myrepo:pull", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFailedDependency {
		t.Errorf("status = %d, want 424", rec.Code)
	}
}

func TestServeIdent_badChallengeParsed(t *testing.T) {
	// challengeRetrieve returns a header with no realm → challengeParse returns "".
	s := newMockServer(nil, "http://localhost:8080", false)
	s.challengeRetrieveFn = func(_, _ string) string {
		return `Bearer service="registry.example.com"` // no realm
	}

	req := httptest.NewRequest(http.MethodGet,
		"/ident/?scope=repository:registry.example.com/myrepo:pull", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFailedDependency {
		t.Errorf("status = %d, want 424", rec.Code)
	}
}

func TestServeIdent_success(t *testing.T) {
	// Serve a fake token endpoint over plain HTTP.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"granted"}`))
	}))
	defer tokenSrv.Close()

	s := newMockServer(&mockStorage{}, "http://localhost:8080", false)
	// Use an identity transport so the proxy uses HTTP (not forced-HTTPS).
	s.transport = http.DefaultTransport
	s.challengeRetrieveFn = func(_, _ string) string {
		return fmt.Sprintf(`Bearer realm="%s/token",service="registry.example.com"`, tokenSrv.URL)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/ident/?scope=repository:registry.example.com/myrepo:pull&account=user1", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	// The proxy should forward to the token server and get 200.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if v := rec.Header().Get("Docker-Distribution-API-Version"); v != "registry/2.0" {
		t.Errorf("Docker-Distribution-API-Version = %q, want registry/2.0", v)
	}
}

// ── challengeRetrieve ─────────────────────────────────────────────────────────

func TestChallengeRetrieve_usesOverride(t *testing.T) {
	s := newMockServer(nil, "http://localhost:8080", false)
	called := false
	s.challengeRetrieveFn = func(registry, path string) string {
		called = true
		if registry != "registry.example.com" {
			t.Errorf("registry = %q, want registry.example.com", registry)
		}
		return `Bearer realm="https://auth.example.com/token"`
	}

	got := s.challengeRetrieve("registry.example.com", "myrepo/tags/list")
	if !called {
		t.Error("challengeRetrieveFn was not called")
	}
	if got != `Bearer realm="https://auth.example.com/token"` {
		t.Errorf("got = %q", got)
	}
}

// ── proxyOrRedirect ───────────────────────────────────────────────────────────

func TestProxyOrRedirect_redirect(t *testing.T) {
	s := newTestServer("http://localhost:8080", true) // redirect=true
	s.db = &mockStorage{}

	req := httptest.NewRequest(http.MethodGet, "/v2/repo/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.proxyOrRedirect(rec, req, "registry.example.com", "/v2/repo/manifests/sha256:abc")

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	want := "https://registry.example.com/v2/repo/manifests/sha256:abc"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

func TestProxyOrRedirect_redirect_withQuery(t *testing.T) {
	s := newTestServer("http://localhost:8080", true)
	s.db = &mockStorage{}

	req := httptest.NewRequest(http.MethodGet, "/v2/repo/tags/list?n=10&last=foo", nil)
	rec := httptest.NewRecorder()
	s.proxyOrRedirect(rec, req, "registry.example.com", "/v2/repo/tags/list")

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	want := "https://registry.example.com/v2/repo/tags/list?n=10&last=foo"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}
