package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leshaunj/hermes/internal/config"
)

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

// ── rewriteRealm ──────────────────────────────────────────────────────────────

func TestRewriteRealm(t *testing.T) {
	s := newTestServer("http://hermes.internal:8080", false)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard Bearer challenge",
			input: `Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:myrepo:pull"`,
			want:  `Bearer realm="http://hermes.internal:8080/ident/auth.example.com/token",service="registry.example.com",scope="repository:myrepo:pull"`,
		},
		{
			name:  "http realm",
			input: `Bearer realm="http://auth.example.com/oauth/token",service="example"`,
			want:  `Bearer realm="http://hermes.internal:8080/ident/auth.example.com/oauth/token",service="example"`,
		},
		{
			name:  "no realm",
			input: `Basic charset="utf-8"`,
			want:  `Basic charset="utf-8"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.rewriteRealm(tc.input)
			if got != tc.want {
				t.Errorf("rewriteRealm(%q)\n got  %q\n want %q", tc.input, got, tc.want)
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
	s.mux.HandleFunc("GET /healthz", s.healthz)

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
