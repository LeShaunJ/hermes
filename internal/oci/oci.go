// Package oci provides OCI registry reference parsing and manifest/config fetching.
package oci

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// ── types ─────────────────────────────────────────────────────────────────────

// ManifestResult holds the data fetched from an OCI registry.
type ManifestResult struct {
	Digest    string // "sha256:abc..."
	MediaType string // Content-Type from the registry response
	Manifest  []byte // raw manifest JSON
}

// ── Client ────────────────────────────────────────────────────────────────────

// Client fetches manifests and configs from OCI registries.
// It satisfies db.Fetcher (duck-typed — this package does not import db).
type Client struct {
	authHeader string // non-empty: set Authorization header verbatim on all requests
	//                   empty: resolve credentials via authn.DefaultKeychain

	// scheme is the URL scheme used for registry requests; defaults to "https".
	// Override to "http" in tests to reach plain httptest servers.
	scheme string
}

// NewDefaultClient returns a Client that authenticates via the Docker credential
// keychain (~/.docker/config.json etc.).
func NewDefaultClient() *Client { return &Client{} }

// NewBearerClient returns a Client that forwards authHeader verbatim on every
// outbound registry request.  Pass r.Header.Get("Authorization") from the API
// server so the client's own credentials are reused for manifest fetching.
func NewBearerClient(authHeader string) *Client { return &Client{authHeader: authHeader} }

// FetchManifest fetches the manifest for registry/repository:reference.
// reference may be a tag ("v1.2.3") or a digest ("sha256:…").
// Returns the content-digest, content-type, and raw JSON body.
func (c *Client) FetchManifest(registry, repository, reference string) (digest, mediaType string, manifest []byte, err error) {
	authCfg, err := c.resolveAuth(registry)
	if err != nil {
		return "", "", nil, err
	}
	scheme := c.scheme
	if scheme == "" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, registry, repository, reference)
	body, dgst, ct, err := c.fetchContent(url, authCfg, registry, repository, true)
	return dgst, ct, body, err
}

// FetchConfig fetches the config blob at configDigest and returns arch and os.
func (c *Client) FetchConfig(registry, repository, configDigest string) (arch, os string, err error) {
	authCfg, err := c.resolveAuth(registry)
	if err != nil {
		return "", "", err
	}
	scheme := c.scheme
	if scheme == "" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", scheme, registry, repository, configDigest)
	body, _, _, err := c.fetchContent(url, authCfg, registry, repository, false)
	if err != nil {
		return "", "", err
	}

	var cfg struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return "", "", fmt.Errorf("decode image config: %w", err)
	}
	return cfg.Architecture, cfg.OS, nil
}

// resolveAuth returns auth credentials for the given registry hostname.
// If c.authHeader is set the AuthConfig is left empty (header applied manually).
func (c *Client) resolveAuth(registry string) (*authn.AuthConfig, error) {
	if c.authHeader != "" {
		return nil, nil // header applied in fetchContent
	}
	reg, err := name.NewRegistry(registry)
	if err != nil {
		return nil, fmt.Errorf("parse registry %q: %w", registry, err)
	}
	auth, err := authn.DefaultKeychain.Resolve(reg)
	if err != nil {
		return nil, fmt.Errorf("resolve credentials for %s: %w", registry, err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		return nil, fmt.Errorf("get authorization for %s: %w", registry, err)
	}
	return cfg, nil
}

// fetchContent is the core HTTP helper.  withAccept adds OCI manifest Accept headers.
func (c *Client) fetchContent(url string, authCfg *authn.AuthConfig, registry, repository string, withAccept bool) (body []byte, digest, contentType string, err error) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("build request: %w", err)
	}
	if withAccept {
		req.Header.Set("Accept", strings.Join([]string{
			"application/vnd.oci.image.manifest.v1+json",
			"application/vnd.docker.distribution.manifest.v2+json",
			"application/vnd.docker.distribution.manifest.list.v2+json",
			"application/vnd.oci.image.index.v1+json",
		}, ", "))
	}

	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	} else {
		applyAuth(req, authCfg)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle Bearer challenge (keychain path only — passthrough header callers get
	// a propagated error on 401).
	if resp.StatusCode == http.StatusUnauthorized && c.authHeader == "" {
		token, err := fetchBearerToken(resp.Header.Get("WWW-Authenticate"), authCfg)
		if err != nil {
			return nil, "", "", fmt.Errorf("bearer auth: %w", err)
		}
		req2, _ := http.NewRequest(http.MethodGet, url, nil)
		req2.Header = req.Header.Clone()
		req2.Header.Set("Authorization", "Bearer "+token)
		resp2, err := client.Do(req2)
		if err != nil {
			return nil, "", "", fmt.Errorf("GET %s (authed): %w", url, err)
		}
		defer func() { _ = resp2.Body.Close() }()
		return readResponse(resp2)
	}

	return readResponse(resp)
}

func readResponse(resp *http.Response) (body []byte, digest, contentType string, err error) {
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", "", fmt.Errorf("registry returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	digest = resp.Header.Get("Docker-Content-Digest")
	contentType = resp.Header.Get("Content-Type")
	// Strip parameters (e.g. "; charset=utf-8") from Content-Type.
	if idx := strings.IndexByte(contentType, ';'); idx >= 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", fmt.Errorf("read body: %w", err)
	}
	return body, digest, contentType, nil
}

// ── auth helpers ──────────────────────────────────────────────────────────────

func fetchBearerToken(challenge string, authCfg *authn.AuthConfig) (string, error) {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return "", fmt.Errorf("unsupported auth scheme: %q", challenge)
	}
	params := parseChallenge(challenge[len("Bearer "):])

	realm, ok := params["realm"]
	if !ok {
		return "", fmt.Errorf("missing realm in Bearer challenge")
	}

	req, err := http.NewRequest(http.MethodGet, realm, nil)
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	q := req.URL.Query()
	if svc, ok := params["service"]; ok {
		q.Set("service", svc)
	}
	if scope, ok := params["scope"]; ok {
		q.Set("scope", scope)
	}
	req.URL.RawQuery = q.Encode()

	if authCfg != nil && authCfg.Username != "" {
		req.SetBasicAuth(authCfg.Username, authCfg.Password)
	} else if authCfg != nil && authCfg.Auth != "" {
		req.Header.Set("Authorization", "Basic "+authCfg.Auth)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("token server %s: %s", resp.Status, string(b))
	}

	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tok.Token != "" {
		return tok.Token, nil
	}
	return tok.AccessToken, nil
}

func parseChallenge(s string) map[string]string {
	params := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		params[key] = val
	}
	return params
}

func applyAuth(req *http.Request, authCfg *authn.AuthConfig) {
	if authCfg == nil {
		return
	}
	if authCfg.Username != "" {
		req.SetBasicAuth(authCfg.Username, authCfg.Password)
	} else if authCfg.Auth != "" {
		req.Header.Set("Authorization", "Basic "+authCfg.Auth)
	} else if authCfg.RegistryToken != "" {
		req.Header.Set("Authorization", "Bearer "+authCfg.RegistryToken)
	}
}

// ── ParseRef ──────────────────────────────────────────────────────────────────

// ParseRef decomposes an image reference into registry, repository, and tag.
// Returns an error if the reference does not include a tag.
func ParseRef(imageRef string) (registry, repository, tag string, err error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", "", "", fmt.Errorf("parse reference %q: %w", imageRef, err)
	}

	t, ok := ref.(name.Tag)
	if !ok {
		return "", "", "", fmt.Errorf("reference must include a tag (digest-only refs not supported): %s", imageRef)
	}

	return ref.Context().RegistryStr(),
		ref.Context().RepositoryStr(),
		t.TagStr(),
		nil
}

// RefHasRegistry reports whether the given raw reference string includes an
// explicit registry prefix.  A registry is detected using the standard Docker
// heuristic: the first "/"-separated segment contains a "." or ":" or is
// exactly "localhost".  This lets callers distinguish `myrepo:v1` (no
// registry — go-containerregistry will default to docker.io) from
// `example.com/myrepo:v1` (explicit registry) without re-implementing the
// whole parser.
func RefHasRegistry(imageRef string) bool {
	i := strings.IndexByte(imageRef, '/')
	if i < 0 {
		return false
	}
	first := imageRef[:i]
	return first == "localhost" || strings.ContainsAny(first, ".:")
}
