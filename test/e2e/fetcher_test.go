//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// httpFetcher implements db.Fetcher against a plain-HTTP OCI registry.
// The production oci.Client hardcodes https, which is incompatible with
// the in-process httptest upstream used by these tests.  Keeping this in
// the test package means the production client stays untouched.
type httpFetcher struct {
	transport http.RoundTripper
}

func (f httpFetcher) client() *http.Client {
	return &http.Client{Transport: f.transport}
}

func (f httpFetcher) FetchManifest(registry, repository, reference string) (digest, mediaType string, manifest []byte, err error) {
	url := fmt.Sprintf("http://%s/v2/%s/manifests/%s", registry, repository, reference)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", nil, err
	}
	// Accept every manifest type the schema supports so the registry
	// returns the raw bytes the client stored (not a converted variant).
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json,"+
		"application/vnd.oci.image.index.v1+json,"+
		"application/vnd.docker.distribution.manifest.v2+json,"+
		"application/vnd.docker.distribution.manifest.list.v2+json")
	resp, err := f.client().Do(req)
	if err != nil {
		return "", "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("upstream %s: %s", url, resp.Status)
	}
	manifest, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, err
	}
	digest = resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		sum := sha256.Sum256(manifest)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	mediaType = resp.Header.Get("Content-Type")
	return digest, mediaType, manifest, nil
}

func (f httpFetcher) FetchConfig(registry, repository, configDigest string) (arch, os string, err error) {
	url := fmt.Sprintf("http://%s/v2/%s/blobs/%s", registry, repository, configDigest)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("upstream %s: %s", url, resp.Status)
	}
	var cfg struct {
		Arch string `json:"architecture"`
		OS   string `json:"os"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return "", "", err
	}
	return cfg.Arch, cfg.OS, nil
}
