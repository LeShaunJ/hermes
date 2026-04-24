//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/leshaunj/hermes/internal/db"
)

// TestLifecycle_FullStateMachine drives a single image through every
// state transition an operator can trigger and asserts gateway
// behaviour at each step.  The README documents the state graph but
// nothing in the suite verifies the graph holds end-to-end: unit tests
// assert on individual transitions, this test asserts on the sequence.
//
//	queued → scanned → approved  (pull works)
//	         approved → rescinded (pull denied)
//	         rescinded → approved (pull works)
//	         approved → rejected  (pull 403)
func TestLifecycle_FullStateMachine(t *testing.T) {
	s := newStack(t)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))

	// 1. Queue — creates image rows in state=queued.
	ref := db.ImageRef{Registry: s.upstreamName, Repository: "myorg/app", Tag: "v1"}
	images, err := s.db.Queue(ref, httpFetcher{transport: s.transport})
	if err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("expected 1 image row, got %d", len(images))
	}
	imgID := images[0].ID
	assertState(t, s.db, imgID, db.StateQueued)

	// 2. Save a stub scan report — transitions to state=scanned.
	scanDoc := json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	if _, err := s.db.SaveScan(imgID, scanDoc); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	assertState(t, s.db, imgID, db.StateScanned)

	// Pull at scanned must still be denied (not yet approved).
	if _, err := crane.Pull(s.ref(t, "myorg/app", "v1"),
		crane.Insecure, crane.WithTransport(s.transport)); err == nil {
		t.Fatal("crane.Pull succeeded in scanned state; expected denial")
	}

	// 3. Approve — pull works.
	if err := s.db.Approve(imgID, ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	assertState(t, s.db, imgID, db.StateApproved)
	mustCranePull(t, s, "myorg/app", "v1", img)

	// 4. Rescind — pull denied.
	if err := s.db.Rescind(imgID); err != nil {
		t.Fatalf("Rescind: %v", err)
	}
	assertState(t, s.db, imgID, db.StateRescinded)
	if _, err := crane.Pull(s.ref(t, "myorg/app", "v1"),
		crane.Insecure, crane.WithTransport(s.transport)); err == nil {
		t.Fatal("crane.Pull succeeded in rescinded state; expected denial")
	}

	// 5. Re-approve — pull works again.
	if err := s.db.Approve(imgID, ""); err != nil {
		t.Fatalf("re-Approve: %v", err)
	}
	assertState(t, s.db, imgID, db.StateApproved)
	mustCranePull(t, s, "myorg/app", "v1", img)

	// 6. Reject — pull 403 (hard deny).  GetRejected is keyed on tag,
	//    so the manifest lookup finds the rejected row and returns 403
	//    instead of the pending-default 401.
	if err := s.db.Reject(imgID); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	assertState(t, s.db, imgID, db.StateRejected)
	manifestURL := s.hermes.URL + "/v2/" + s.upstreamName + "/myorg/app/manifests/v1"
	resp := mustGet(t, manifestURL)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("rejected manifest GET status = %d, want 403", resp.StatusCode)
	}
}

// assertState fails the test unless the image at imgID is in want.
func assertState(t *testing.T, d *db.DB, imgID int64, want db.State) {
	t.Helper()
	if got := currentState(t, d, imgID); got != want {
		t.Fatalf("state = %q, want %q", got, want)
	}
}

// mustCranePull issues crane.Pull and asserts the digest matches.
func mustCranePull(t *testing.T, s *stack, repo, tag string, want v1.Image) {
	t.Helper()
	pulled, err := crane.Pull(s.ref(t, repo, tag),
		crane.Insecure, crane.WithTransport(s.transport))
	if err != nil {
		t.Fatalf("crane.Pull(%s:%s): %v", repo, tag, err)
	}
	if got, wantDigest := mustDigest(t, pulled), mustDigest(t, want); got != wantDigest {
		t.Errorf("pulled digest = %s, want %s", got, wantDigest)
	}
}
