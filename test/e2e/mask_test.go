//go:build e2e

package e2e

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"

	"github.com/leshaunj/hermes/internal/db"
)

// TestMask_DockerIOAliases verifies the registry-mask chain: approving
// an image at the canonical `docker.io` makes it pullable via the
// masked alias `registry-1.docker.io`, and vice-versa.  The migration
// seeds this chain automatically so hermes can normalize every
// Docker-Hub alias onto one row.  A subtle regression — a forgotten
// CanonicalRegistryURL call or a wrong column on the upsertRegistry
// recursive CTE — breaks every docker.io pull in production.  Fixed
// twice already per git log (`0dfbbda`, `e7e0a45`).
func TestMask_DockerIOAliases(t *testing.T) {
	s := newStack(t)

	// Route the two seeded aliases at the same httptest upstream.
	s.transport.(*rewriteTransport).registerPseudoHost("docker.io")
	s.transport.(*rewriteTransport).registerPseudoHost("registry-1.docker.io")
	s.transport.(*rewriteTransport).registerPseudoHost("index.docker.io")

	img := mustRandomImage(t)
	mustPush(t, s, img, "docker.io/library/app:v1")

	// Approve via the canonical display name.
	ref := db.ImageRef{Registry: "docker.io", Repository: "library/app", Tag: "v1"}
	images, err := s.db.Queue(ref, httpFetcher{transport: s.transport})
	if err != nil {
		t.Fatalf("Queue docker.io: %v", err)
	}
	for _, i := range images {
		if err := s.db.Approve(i.ID, ""); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}

	// Pull via each alias and assert all three resolve to the same
	// approved manifest.
	for _, alias := range []string{"docker.io", "registry-1.docker.io", "index.docker.io"} {
		hermesRef := s.hermesHost(t) + "/" + alias + "/library/app:v1"
		pulled, err := crane.Pull(hermesRef, crane.Insecure, crane.WithTransport(s.transport))
		if err != nil {
			t.Fatalf("crane.Pull via %s: %v", alias, err)
		}
		if got, want := mustDigest(t, pulled), mustDigest(t, img); got != want {
			t.Errorf("alias %s pulled digest = %s, want %s", alias, got, want)
		}
	}
}

// TestMask_ApproveViaAliasPullViaCanonical is the reverse-direction
// check: approving via `registry-1.docker.io` (a masked alias) must
// still let pulls through `docker.io` succeed.  Both directions must
// collapse to the same row or a subset of operators would see
// "approved but won't pull" depending on which alias they used.
func TestMask_ApproveViaAliasPullViaCanonical(t *testing.T) {
	s := newStack(t)

	s.transport.(*rewriteTransport).registerPseudoHost("docker.io")
	s.transport.(*rewriteTransport).registerPseudoHost("registry-1.docker.io")

	img := mustRandomImage(t)
	mustPush(t, s, img, "registry-1.docker.io/library/tool:latest")

	ref := db.ImageRef{Registry: "registry-1.docker.io", Repository: "library/tool", Tag: "latest"}
	images, err := s.db.Queue(ref, httpFetcher{transport: s.transport})
	if err != nil {
		t.Fatalf("Queue via alias: %v", err)
	}
	for _, i := range images {
		if err := s.db.Approve(i.ID, ""); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}

	pulled, err := crane.Pull(s.hermesHost(t)+"/docker.io/library/tool:latest",
		crane.Insecure, crane.WithTransport(s.transport))
	if err != nil {
		t.Fatalf("crane.Pull via canonical after approving via alias: %v", err)
	}
	if got, want := mustDigest(t, pulled), mustDigest(t, img); got != want {
		t.Errorf("pulled digest = %s, want %s", got, want)
	}
}
