//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/leshaunj/hermes/internal/db"
)

// TestPull_AlternateTag verifies the AdoptTagByDigest path: when a second
// tag in the same repository points to a manifest digest that is already
// approved, the gateway adopts the new tag and serves it without a fresh
// approval.  This exercises a code path (linked image rows, inherited
// state) that unit tests can only assert about via SQL-string matching.
func TestPull_AlternateTag(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	approve(t, s, "myorg/app", "v1")

	// Push the identical image bytes under a second tag.  The digest is
	// unchanged; from the DB's perspective this is "another location
	// observing the same manifest" — the canonical alternate-tag case.
	mustPush(t, s, img, s.upstreamRef("myorg/app", "latest"))

	hermesRef := s.ref(t, "myorg/app", "latest")
	pulled, err := crane.Pull(hermesRef, crane.Insecure, crane.WithTransport(s.transport))
	if err != nil {
		t.Fatalf("crane.Pull alternate tag: %v", err)
	}

	if got, want := mustDigest(t, pulled), mustDigest(t, img); got != want {
		t.Errorf("pulled digest = %s, want %s", got, want)
	}
}

// TestBlob_UnrelatedDigestDenied verifies the blob authorization gate:
// hermes must only forward a blob when its digest appears as a config or
// layer of an approved manifest for the same (registry, repository).
// Asking for an unrelated digest — even one that exists upstream in a
// different repository — must return 401.  This is the guardrail that
// stops clients from streaming arbitrary content through the gateway.
func TestBlob_UnrelatedDigestDenied(t *testing.T) {
	s := newStack(t)

	// Approved image.
	approved := mustRandomImage(t)
	mustPush(t, s, approved, s.upstreamRef("myorg/good", "v1"))
	approve(t, s, "myorg/good", "v1")

	// Separate image whose layers are *not* approved anywhere.
	other := mustRandomImage(t)
	mustPush(t, s, other, s.upstreamRef("myorg/other", "v1"))

	otherLayerDigest := firstLayerDigest(t, other)

	// Ask hermes for other's layer under the approved repository's path.
	// The digest exists upstream but not in any approved manifest for
	// myorg/good — so hermes must deny it.
	blobURL := s.hermes.URL + "/v2/" + s.upstreamName + "/myorg/good/blobs/" + otherLayerDigest
	resp := mustGet(t, blobURL)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("unrelated blob fetch status = %d, want 401; body=%s", resp.StatusCode, string(body))
	}
}

// TestPull_InheritedAcrossRepos pins down the README's "approval state is
// attached to the manifest digest — every (registry, repository) location
// observing the same digest inherits the verdict" rule.  Approving one
// repo's image must make the same content pullable at any repo that later
// observes the same manifest digest.  This is intentional — approvals are
// content-addressed — and a regression here would either break legitimate
// pulls or stealthily require re-approval.
func TestPull_InheritedAcrossRepos(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/good", "v1"))
	approve(t, s, "myorg/good", "v1")

	// Observe the same manifest bytes at a second repo without a fresh
	// approval call.
	mustPush(t, s, img, s.upstreamRef("myorg/other", "v1"))
	otherRef := db.ImageRef{Registry: s.upstreamName, Repository: "myorg/other", Tag: "v1"}
	if _, err := s.db.Queue(otherRef, httpFetcher{transport: s.transport}); err != nil {
		t.Fatalf("Queue myorg/other: %v", err)
	}

	hermesRef := s.ref(t, "myorg/other", "v1")
	pulled, err := crane.Pull(hermesRef, crane.Insecure, crane.WithTransport(s.transport))
	if err != nil {
		t.Fatalf("crane.Pull inherited-approval ref %s: %v", hermesRef, err)
	}
	if got, want := mustDigest(t, pulled), mustDigest(t, img); got != want {
		t.Errorf("pulled digest = %s, want %s", got, want)
	}
}

// ── fixture helpers (blob/adoption) ───────────────────────────────────────────

func firstLayerDigest(t *testing.T, img v1.Image) string {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("Layers: %v", err)
	}
	if len(layers) == 0 {
		t.Fatal("image has no layers")
	}
	d, err := layers[0].Digest()
	if err != nil {
		t.Fatalf("Layer digest: %v", err)
	}
	return d.String()
}

// mustGet issues an HTTP GET via the harness transport so pseudo-hosts
// resolve correctly.  The client follows no redirects so we can assert on
// the raw status hermes returns.
func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}
