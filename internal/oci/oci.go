// Package oci provides OCI registry reference parsing and manifest fetching.
package oci

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/leshaunj/hermes/internal/db"
)

// ManifestResult holds the data fetched from an OCI registry.
type ManifestResult struct {
	Digest   string // "sha256:abc..."
	Manifest []byte // raw manifest JSON
}

// FetchManifest fetches the manifest and digest for the given image reference.
// It authenticates using the Docker credential chain (~/.docker/config.json etc.).
func FetchManifest(imageRef string) (*ManifestResult, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", imageRef, err)
	}

	auth, err := authn.DefaultKeychain.Resolve(ref.Context().Registry)
	if err != nil {
		return nil, fmt.Errorf("resolve credentials: %w", err)
	}
	authCfg, err := auth.Authorization()
	if err != nil {
		return nil, fmt.Errorf("get authorization: %w", err)
	}

	t, ok := ref.(name.Tag)
	if !ok {
		return nil, fmt.Errorf("reference must include a tag, got: %s", imageRef)
	}

	registry := ref.Context().RegistryStr()
	repository := ref.Context().RepositoryStr()
	tag := t.TagStr()

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, tag)
	body, digest, err := fetchManifest(url, authCfg, registry, repository)
	if err != nil {
		return nil, err
	}

	return &ManifestResult{
		Digest:   digest,
		Manifest: body,
	}, nil
}

func fetchManifest(url string, authCfg *authn.AuthConfig, registry, repository string) ([]byte, string, error) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))
	applyAuth(req, authCfg)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		token, err := fetchBearerToken(resp.Header.Get("WWW-Authenticate"), authCfg)
		if err != nil {
			return nil, "", fmt.Errorf("bearer auth: %w", err)
		}
		req2, _ := http.NewRequest(http.MethodGet, url, nil)
		req2.Header = req.Header.Clone()
		req2.Header.Set("Authorization", "Bearer "+token)
		resp2, err := client.Do(req2)
		if err != nil {
			return nil, "", fmt.Errorf("GET manifest (authed): %w", err)
		}
		defer resp2.Body.Close()
		return readManifestResponse(resp2)
	}

	return readManifestResponse(resp)
}

func readManifestResponse(resp *http.Response) ([]byte, string, error) {
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("registry returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read manifest body: %w", err)
	}
	return body, digest, nil
}

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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("token server %s: %s", resp.Status, string(body))
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

// ParseRef decomposes an image reference into registry, repository, and tag.
// Returns an error if the reference does not include a tag.
func ParseRef(imageRef string) (db.ImageRef, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return db.ImageRef{}, fmt.Errorf("parse reference %q: %w", imageRef, err)
	}

	t, ok := ref.(name.Tag)
	if !ok {
		return db.ImageRef{}, fmt.Errorf("reference must include a tag (digest-only refs not supported): %s", imageRef)
	}

	return db.ImageRef{
		Registry:   ref.Context().RegistryStr(),
		Repository: ref.Context().RepositoryStr(),
		Tag:        t.TagStr(),
	}, nil
}
