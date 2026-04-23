//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"

	"github.com/leshaunj/hermes/internal/db"
)

// TestVoid_ManifestDisappears confirms hermes's void hook auto-voids an
// approved image when its digest is no longer present upstream.  The
// hook fires on MANIFEST_UNKNOWN / 410 responses to digest-addressed
// pulls in proxy mode — a silent regression here would leave operators
// approving images that stealthily no longer exist.
func TestVoid_ManifestDisappears(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	digest := mustDigest(t, img)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	images := approveReturning(t, s, "myorg/app", "v1")
	if len(images) != 1 {
		t.Fatalf("expected 1 platform image, got %d", len(images))
	}
	imgID := images[0].ID

	// Sanity: pull once through hermes to confirm baseline works.
	if _, err := crane.Pull(s.ref(t, "myorg/app", "v1"),
		crane.Insecure, crane.WithTransport(s.transport)); err != nil {
		t.Fatalf("baseline pull: %v", err)
	}

	// Delete the manifest upstream.
	deleteManifest(t, s, "myorg/app", digest)

	// Digest-addressed pull triggers the void hook when the upstream
	// returns MANIFEST_UNKNOWN.  Crane will error because the manifest
	// is gone — the assertion is on the DB state change.
	digestRef := fmt.Sprintf("%s/%s/myorg/app@%s", s.hermesHost(t), s.upstreamName, digest)
	_, _ = crane.Pull(digestRef, crane.Insecure, crane.WithTransport(s.transport))

	if state := currentState(t, s.db, imgID); state != db.StateVoided {
		t.Errorf("state after upstream deletion = %q, want %q", state, db.StateVoided)
	}
}

// TestVoid_BlobDisappears verifies the voidBlobHook path: when a blob
// from an approved manifest 404s upstream, every uncached image that
// references that blob is voided.  This is the other half of the void
// machinery and matters when layers (not just manifests) vanish.
func TestVoid_BlobDisappears(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	images := approveReturning(t, s, "myorg/app", "v1")
	imgID := images[0].ID

	// Sanity pull.
	if _, err := crane.Pull(s.ref(t, "myorg/app", "v1"),
		crane.Insecure, crane.WithTransport(s.transport)); err != nil {
		t.Fatalf("baseline pull: %v", err)
	}

	// Remove the layer bytes from upstream by deleting the manifest
	// (which drops the registry's in-memory refcount so subsequent blob
	// GETs 404 with BLOB_UNKNOWN).  We then fetch the blob directly
	// through hermes — the hook sees the 404 and voids the image.
	layer := firstLayerDigest(t, img)
	manifestDigest := mustDigest(t, img)
	deleteManifest(t, s, "myorg/app", manifestDigest)
	deleteBlob(t, s, "myorg/app", layer)

	blobURL := s.hermes.URL + "/v2/" + s.upstreamName + "/myorg/app/blobs/" + layer
	resp := mustGet(t, blobURL)
	_ = resp.Body.Close()

	if state := currentState(t, s.db, imgID); state != db.StateVoided {
		t.Errorf("state after upstream blob deletion = %q, want %q", state, db.StateVoided)
	}
}

// ── fixture helpers (void) ────────────────────────────────────────────────────

// deleteManifest sends an OCI DELETE /v2/<repo>/manifests/<digest> to the
// upstream.  go-containerregistry's in-process registry honours DELETE so
// subsequent lookups return 404 + MANIFEST_UNKNOWN.
func deleteManifest(t *testing.T, s *stack, repo, digest string) {
	t.Helper()
	url := fmt.Sprintf("http://%s/v2/%s/manifests/%s", s.upstreamName, repo, digest)
	sendUpstream(t, s, http.MethodDelete, url)
}

func deleteBlob(t *testing.T, s *stack, repo, digest string) {
	t.Helper()
	url := fmt.Sprintf("http://%s/v2/%s/blobs/%s", s.upstreamName, repo, digest)
	sendUpstream(t, s, http.MethodDelete, url)
}

func sendUpstream(t *testing.T, s *stack, method, url string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, url, err)
	}
	// Authenticate so the upstream middleware lets us through.
	req.Header.Set("Authorization", "Bearer stub-token")
	c := &http.Client{Transport: s.transport}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Logf("%s %s returned %d (may be expected if already deleted)", method, url, resp.StatusCode)
	}
}

// approveReturning queues + approves and returns the image rows so callers
// can assert on IDs (e.g. to re-query state later).
func approveReturning(t *testing.T, s *stack, repo, tag string) []*db.Image {
	t.Helper()
	ref := db.ImageRef{Registry: s.upstreamName, Repository: repo, Tag: tag}
	images, err := s.db.Queue(ref, httpFetcher{transport: s.transport})
	if err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if len(images) == 0 {
		t.Fatal("Queue returned no images")
	}
	for _, platformImg := range images {
		if err := s.db.Approve(platformImg.ID, ""); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}
	return images
}

// currentState re-reads the manifest state via GetByRef on the first
// image's (registry, repository, tag), returning the live state.
func currentState(t *testing.T, d *db.DB, imageID int64) db.State {
	t.Helper()
	// Re-read by scanning the images list; simplest way to get current
	// state for a specific image_id without adding a test-only method.
	images, err := d.List(db.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, img := range images {
		if img.ID == imageID {
			return img.State
		}
	}
	t.Fatalf("image id %d not found in List", imageID)
	return ""
}
