//go:build e2e

package e2e

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
)

// TestPull_RedirectMode verifies that approved images are pullable when
// hermes is configured with server.redirect=true.  In this mode hermes
// issues HTTP 307 redirects to the upstream instead of reverse-proxying,
// so the client-side dial path is fundamentally different: the bearer
// token issued for the /ident realm must also work against the upstream,
// the redirect URL must round-trip through the rewriteTransport, and the
// WWW-Authenticate rewrite logic must still point clients at the
// hermes-side /ident proxy.  A regression here causes redirect-mode
// deployments to silently stop working.
func TestPull_RedirectMode(t *testing.T) {
	s := newStack(t, withRedirect())

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	approve(t, s, "myorg/app", "v1")

	pulled, err := crane.Pull(s.ref(t, "myorg/app", "v1"),
		crane.Insecure, crane.WithTransport(s.transport))
	if err != nil {
		t.Fatalf("crane.Pull (redirect mode): %v", err)
	}
	if got, want := mustDigest(t, pulled), mustDigest(t, img); got != want {
		t.Errorf("pulled digest = %s, want %s", got, want)
	}
}

// TestPull_RedirectMode_UnapprovedDenied verifies the gateway still
// refuses unapproved images in redirect mode — the 401 path short-circuits
// before the redirect decision, so there should be no upstream leakage.
func TestPull_RedirectMode_UnapprovedDenied(t *testing.T) {
	s := newStack(t, withRedirect())

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/pending", "v1"))
	// No approve.

	_, err := crane.Pull(s.ref(t, "myorg/pending", "v1"),
		crane.Insecure, crane.WithTransport(s.transport))
	if err == nil {
		t.Fatal("crane.Pull succeeded for unapproved image in redirect mode; expected denial")
	}
}
