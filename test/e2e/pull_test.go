//go:build e2e

package e2e

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"

	"github.com/leshaunj/hermes/internal/db"
)

// TestPull_ApprovedImage is the bug-class test: an operator approves an
// image, then a real OCI client pulls it through hermes.  If any part of
// the auth/proxy/DB chain is broken — a SQL query returning wrong rows, a
// path parse mistake, a stripped content-type, a missing digest header —
// crane.Pull fails and this test catches it.  sqlmock and mockStorage do
// not.
func TestPull_ApprovedImage(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/myapp", "v1"))
	approve(t, s, "myorg/myapp", "v1")

	// Pull via crane through hermes.  This is the assertion that matters:
	// if any part of the stack is broken for a real OCI client, crane
	// returns an error here.
	hermesRef := s.ref(t, "myorg/myapp", "v1")
	pulled, err := crane.Pull(hermesRef, crane.Insecure, crane.WithTransport(s.transport))
	if err != nil {
		t.Fatalf("crane.Pull(%s): %v", hermesRef, err)
	}

	gotDigest := mustDigest(t, pulled)
	wantDigest := mustDigest(t, img)
	if gotDigest != wantDigest {
		t.Errorf("pulled digest = %s, want %s", gotDigest, wantDigest)
	}
}

// TestPull_UnapprovedImage_Denied verifies the gateway refuses a pull
// when the image is stub-registered but not approved.  If approval state
// leaks — e.g. a query returns rows regardless of state — this fails.
func TestPull_UnapprovedImage_Denied(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/pending", "v1"))

	ref := db.ImageRef{Registry: s.upstreamName, Repository: "myorg/pending", Tag: "v1"}
	if _, err := s.db.Queue(ref, httpFetcher{transport: s.transport}); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	// Intentionally do NOT approve.

	hermesRef := s.ref(t, "myorg/pending", "v1")
	_, err := crane.Pull(hermesRef, crane.Insecure, crane.WithTransport(s.transport))
	if err == nil {
		t.Fatalf("crane.Pull succeeded for unapproved image %s; expected denial", hermesRef)
	}
}

// TestPull_RejectedImage_Forbidden verifies a rejected image returns the
// gateway's hard-deny path (403).
func TestPull_RejectedImage_Forbidden(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/bad", "v1"))

	ref := db.ImageRef{Registry: s.upstreamName, Repository: "myorg/bad", Tag: "v1"}
	images, err := s.db.Queue(ref, httpFetcher{transport: s.transport})
	if err != nil {
		t.Fatalf("Queue: %v", err)
	}
	for _, platformImg := range images {
		if err := s.db.Reject(platformImg.ID); err != nil {
			t.Fatalf("Reject: %v", err)
		}
	}

	hermesRef := s.ref(t, "myorg/bad", "v1")
	_, err = crane.Pull(hermesRef, crane.Insecure, crane.WithTransport(s.transport))
	if err == nil {
		t.Fatalf("crane.Pull succeeded for rejected image %s; expected 403", hermesRef)
	}
}

// ── fixture helpers ───────────────────────────────────────────────────────────

func mustRandomImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := random.Image(1024, 3)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	return img
}

func mustPush(t *testing.T, s *stack, img v1.Image, ref string) {
	t.Helper()
	if err := crane.Push(img, ref, crane.Insecure, crane.WithTransport(s.transport)); err != nil {
		t.Fatalf("crane.Push(%s): %v", ref, err)
	}
}

func mustDigest(t *testing.T, img v1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("img.Digest: %v", err)
	}
	return d.String()
}

// approve simulates what `hermes scan` + `hermes approve` would do: queue
// the image through the real DB layer (which fetches the manifest via the
// test httpFetcher) and mark every resulting platform row approved.
func approve(t *testing.T, s *stack, repo, tag string) {
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
}
