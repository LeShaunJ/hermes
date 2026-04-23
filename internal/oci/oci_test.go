package oci

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
)

// ── ParseRef ──────────────────────────────────────────────────────────────────

func TestParseRef(t *testing.T) {
	tests := []struct {
		input    string
		registry string
		repo     string
		tag      string
		wantErr  bool
	}{
		{
			input:    "registry.example.com/myapp:v1.2.3",
			registry: "registry.example.com",
			repo:     "myapp",
			tag:      "v1.2.3",
		},
		{
			input:    "quay.io/org/myapp:latest",
			registry: "quay.io",
			repo:     "org/myapp",
			tag:      "latest",
		},
		{
			input:    "docker.io/library/nginx:1.25",
			registry: "index.docker.io",
			repo:     "library/nginx",
			tag:      "1.25",
		},
		{
			// Digest-only refs are not supported.
			input:   "registry.example.com/myapp@sha256:abc123",
			wantErr: true,
		},
		{
			input:   "not-a-ref::::",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			reg, repo, tag, err := ParseRef(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseRef(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRef(%q) unexpected error: %v", tc.input, err)
			}
			if reg != tc.registry {
				t.Errorf("registry = %q, want %q", reg, tc.registry)
			}
			if repo != tc.repo {
				t.Errorf("repository = %q, want %q", repo, tc.repo)
			}
			if tag != tc.tag {
				t.Errorf("tag = %q, want %q", tag, tc.tag)
			}
		})
	}
}

// ── RefHasRegistry ────────────────────────────────────────────────────────────

func TestRefHasRegistry(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"myapp", false},
		{"myapp:v1", false},
		{"myorg/myapp:v1", false},
		{"example.com/myapp:v1", true},
		{"example.com/myorg/myapp:v1", true},
		{"example.com:5000/myapp:v1", true},
		{"localhost/myapp:v1", true},
		{"localhost:5000/myapp:v1", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := RefHasRegistry(tc.in); got != tc.want {
				t.Errorf("RefHasRegistry(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// ── parseChallenge ────────────────────────────────────────────────────────────

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		input string
		want  map[string]string
	}{
		{
			input: `realm="https://auth.example.com/token",service="registry.example.com",scope="repository:myrepo:pull"`,
			want: map[string]string{
				"realm":   "https://auth.example.com/token",
				"service": "registry.example.com",
				"scope":   "repository:myrepo:pull",
			},
		},
		{
			input: `realm="https://token.docker.io/token",service="registry.docker.io"`,
			want: map[string]string{
				"realm":   "https://token.docker.io/token",
				"service": "registry.docker.io",
			},
		},
		{
			input: "",
			want:  map[string]string{},
		},
		{
			input: "no-kv-pairs",
			want:  map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseChallenge(tc.input)
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("param[%q] = %q, want %q", k, got[k], v)
				}
			}
			for k := range got {
				if _, ok := tc.want[k]; !ok {
					t.Errorf("unexpected param %q = %q", k, got[k])
				}
			}
		})
	}
}

// ── applyAuth ─────────────────────────────────────────────────────────────────

func TestApplyAuth(t *testing.T) {
	t.Run("nil authCfg", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		applyAuth(req, nil)
		if auth := req.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization = %q, want empty", auth)
		}
	})

	t.Run("username+password", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		applyAuth(req, &authn.AuthConfig{Username: "user", Password: "pass"})
		if auth := req.Header.Get("Authorization"); auth == "" {
			t.Error("Authorization header not set for username+password")
		}
	})

	t.Run("auth token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		applyAuth(req, &authn.AuthConfig{Auth: "dXNlcjpwYXNz"})
		if auth := req.Header.Get("Authorization"); auth != "Basic dXNlcjpwYXNz" {
			t.Errorf("Authorization = %q, want Basic token", auth)
		}
	})

	t.Run("registry token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		applyAuth(req, &authn.AuthConfig{RegistryToken: "mytoken"})
		if auth := req.Header.Get("Authorization"); auth != "Bearer mytoken" {
			t.Errorf("Authorization = %q, want Bearer mytoken", auth)
		}
	})

	t.Run("empty authCfg", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		applyAuth(req, &authn.AuthConfig{})
		if auth := req.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization = %q, want empty", auth)
		}
	})
}

// ── NewDefaultClient / NewBearerClient ────────────────────────────────────────

func TestNewClients(t *testing.T) {
	dc := NewDefaultClient()
	if dc == nil {
		t.Fatal("NewDefaultClient() returned nil")
	}
	if dc.authHeader != "" {
		t.Errorf("NewDefaultClient().authHeader = %q, want empty", dc.authHeader)
	}

	bc := NewBearerClient("Bearer token123")
	if bc == nil {
		t.Fatal("NewBearerClient() returned nil")
	}
	if bc.authHeader != "Bearer token123" {
		t.Errorf("NewBearerClient().authHeader = %q, want Bearer token123", bc.authHeader)
	}
}

// ── readResponse ──────────────────────────────────────────────────────────────

func TestReadResponse(t *testing.T) {
	t.Run("200 with body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Docker-Content-Digest", "sha256:abc123")
		rec.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.WriteString(`{"schemaVersion":2}`)

		body, digest, ct, err := readResponse(rec.Result())
		if err != nil {
			t.Fatalf("readResponse: %v", err)
		}
		if digest != "sha256:abc123" {
			t.Errorf("digest = %q, want sha256:abc123", digest)
		}
		if ct != "application/vnd.oci.image.manifest.v1+json" {
			t.Errorf("content-type = %q", ct)
		}
		if string(body) != `{"schemaVersion":2}` {
			t.Errorf("body = %q", body)
		}
	})

	t.Run("content-type with parameters stripped", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json; charset=utf-8")
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.WriteString(`{}`)

		_, _, ct, err := readResponse(rec.Result())
		if err != nil {
			t.Fatalf("readResponse: %v", err)
		}
		if ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusNotFound)
		_, _ = rec.WriteString("not found")

		_, _, _, err := readResponse(rec.Result())
		if err == nil {
			t.Error("expected error for 404, got nil")
		}
	})
}

// ── FetchManifest via httptest ────────────────────────────────────────────────

func TestFetchManifest(t *testing.T) {
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
	}
	manifestJSON, _ := json.Marshal(manifest)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write(manifestJSON)
	}))
	defer srv.Close()

	// Use scheme "http" so FetchManifest targets the plain httptest server.
	// The registry "host" is extracted from srv.URL (strip "http://").
	host := srv.URL[len("http://"):]
	c := &Client{authHeader: "Bearer test-token", scheme: "http"}
	digest, ct, body, err := c.FetchManifest(host, "myrepo", "latest")
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if digest != "sha256:deadbeef" {
		t.Errorf("digest = %q, want sha256:deadbeef", digest)
	}
	if ct != "application/vnd.oci.image.manifest.v1+json" {
		t.Errorf("content-type = %q", ct)
	}
	if len(body) == 0 {
		t.Error("body is empty")
	}
}

// TestFetchManifest_resolveAuth_bearerClient verifies that NewBearerClient
// skips keychain resolution and returns a nil AuthConfig.
func TestFetchManifest_resolveAuth_bearerClient(t *testing.T) {
	c := NewBearerClient("Bearer tok")
	cfg, err := c.resolveAuth("registry.example.com")
	if err != nil {
		t.Fatalf("resolveAuth: %v", err)
	}
	if cfg != nil {
		t.Errorf("resolveAuth with authHeader set should return nil, got %+v", cfg)
	}
}

// TestFetchConfig verifies FetchConfig decodes architecture and OS from the config blob.
func TestFetchConfig(t *testing.T) {
	configBody := `{"architecture":"amd64","os":"linux"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(configBody))
	}))
	defer srv.Close()

	host := srv.URL[len("http://"):]
	c := &Client{authHeader: "Bearer tok", scheme: "http"}
	arch, os, err := c.FetchConfig(host, "myrepo", "sha256:cfgdigest")
	if err != nil {
		t.Fatalf("FetchConfig: %v", err)
	}
	if arch != "amd64" {
		t.Errorf("arch = %q, want amd64", arch)
	}
	if os != "linux" {
		t.Errorf("os = %q, want linux", os)
	}
}

func TestFetchConfig_invalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	host := srv.URL[len("http://"):]
	c := &Client{authHeader: "Bearer tok", scheme: "http"}
	_, _, err := c.FetchConfig(host, "myrepo", "sha256:cfgdigest")
	if err == nil {
		t.Error("expected error for invalid config JSON, got nil")
	}
}

// ── fetchBearerToken via httptest ─────────────────────────────────────────────

func TestFetchBearerToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"mytoken123"}`))
		}))
		defer srv.Close()

		challenge := `Bearer realm="` + srv.URL + `/token",service="registry.example.com"`
		token, err := fetchBearerToken(challenge, nil)
		if err != nil {
			t.Fatalf("fetchBearerToken: %v", err)
		}
		if token != "mytoken123" {
			t.Errorf("token = %q, want mytoken123", token)
		}
	})

	t.Run("access_token fallback", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"accesstok"}`))
		}))
		defer srv.Close()

		challenge := `Bearer realm="` + srv.URL + `/token"`
		token, err := fetchBearerToken(challenge, nil)
		if err != nil {
			t.Fatalf("fetchBearerToken access_token fallback: %v", err)
		}
		if token != "accesstok" {
			t.Errorf("token = %q, want accesstok", token)
		}
	})

	t.Run("non-bearer scheme", func(t *testing.T) {
		_, err := fetchBearerToken("Basic realm=test", nil)
		if err == nil {
			t.Error("expected error for non-Bearer scheme, got nil")
		}
	})

	t.Run("missing realm", func(t *testing.T) {
		_, err := fetchBearerToken("Bearer service=test", nil)
		if err == nil {
			t.Error("expected error for missing realm, got nil")
		}
	})

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
		}))
		defer srv.Close()

		challenge := `Bearer realm="` + srv.URL + `/token"`
		_, err := fetchBearerToken(challenge, &authn.AuthConfig{Username: "u", Password: "p"})
		if err == nil {
			t.Error("expected error from 401 token server, got nil")
		}
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()

		challenge := `Bearer realm="` + srv.URL + `/token"`
		_, err := fetchBearerToken(challenge, nil)
		if err == nil {
			t.Error("expected error from invalid JSON, got nil")
		}
	})

	t.Run("with auth config auth field", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"token":"tok"}`))
		}))
		defer srv.Close()

		challenge := `Bearer realm="` + srv.URL + `/token"`
		token, err := fetchBearerToken(challenge, &authn.AuthConfig{Auth: "dXNlcjpwYXNz"})
		if err != nil {
			t.Fatalf("fetchBearerToken with Auth field: %v", err)
		}
		if token != "tok" {
			t.Errorf("token = %q, want tok", token)
		}
	})
}

// ── fetchContent via httptest ─────────────────────────────────────────────────

func TestFetchContent_bearerClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mytoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:abc")
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	}))
	defer srv.Close()

	c := NewBearerClient("Bearer mytoken")
	body, digest, ct, err := c.fetchContent(srv.URL+"/v2/repo/manifests/latest", nil, "example.com", "repo", true)
	if err != nil {
		t.Fatalf("fetchContent: %v", err)
	}
	if digest != "sha256:abc" {
		t.Errorf("digest = %q, want sha256:abc", digest)
	}
	if ct != "application/vnd.oci.image.manifest.v1+json" {
		t.Errorf("content-type = %q", ct)
	}
	if string(body) != `{"schemaVersion":2}` {
		t.Errorf("body = %q", body)
	}
}

func TestFetchContent_bearerChallenge(t *testing.T) {
	// Serve a token endpoint that returns a token.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"granted"}`))
	}))
	defer tokenSrv.Close()

	// Serve a registry that challenges on first request, then succeeds.
	attempts := 0
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="`+tokenSrv.URL+`/token",service="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:xyz")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer regSrv.Close()

	c := NewDefaultClient()
	body, digest, _, err := c.fetchContent(regSrv.URL+"/v2/repo/manifests/latest", nil, "example.com", "repo", false)
	if err != nil {
		t.Fatalf("fetchContent with bearer challenge: %v", err)
	}
	if digest != "sha256:xyz" {
		t.Errorf("digest = %q, want sha256:xyz", digest)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", body)
	}
}
