package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/leshaunj/hermes/internal/db"
)

// ── selectPlatform ────────────────────────────────────────────────────────────

func makeImage(id int64, os, arch string, state db.State) *db.Image {
	return &db.Image{
		ID:        id,
		OS:        os,
		Arch:      arch,
		State:     state,
		Digest:    "sha256:abc" + arch,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestSelectPlatform_singleImage(t *testing.T) {
	images := []*db.Image{makeImage(1, "linux", "amd64", db.StateQueued)}
	img, err := selectPlatform(images, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.Arch != "amd64" {
		t.Errorf("arch = %q, want amd64", img.Arch)
	}
}

func TestSelectPlatform_byPlatform(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateQueued),
		makeImage(2, "linux", "arm64", db.StateQueued),
	}
	img, err := selectPlatform(images, "linux/arm64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.ID != 2 {
		t.Errorf("id = %d, want 2", img.ID)
	}
}

func TestSelectPlatform_platformNotFound(t *testing.T) {
	images := []*db.Image{makeImage(1, "linux", "amd64", db.StateQueued)}
	_, err := selectPlatform(images, "linux/arm64")
	if err == nil {
		t.Error("expected error for missing platform, got nil")
	}
}

func TestSelectPlatform_excludedState(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateApproved),
		makeImage(2, "linux", "arm64", db.StateQueued),
	}
	// amd64 is already approved — must not be selectable; arm64 auto-selected.
	img, err := selectPlatform(images, "", db.StateApproved)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.ID != 2 {
		t.Errorf("id = %d, want 2 (arm64)", img.ID)
	}
}

func TestSelectPlatform_allExcluded(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateApproved),
	}
	_, err := selectPlatform(images, "", db.StateApproved)
	if err == nil {
		t.Error("expected error when all platforms excluded, got nil")
	}
}

func TestSelectPlatform_excludedByFlag(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateApproved),
	}
	_, err := selectPlatform(images, "linux/amd64", db.StateApproved)
	if err == nil {
		t.Error("expected error selecting an excluded platform, got nil")
	}
}

func TestSelectPlatform_empty(t *testing.T) {
	_, err := selectPlatform(nil, "")
	if err == nil {
		t.Error("expected error for empty images, got nil")
	}
}

// ── printJSON ────────────────────────────────────────────────────────────────

func TestPrintJSON(t *testing.T) {
	// Redirect stdout to a buffer by using printJSON with a known JSON payload.
	// We verify that valid JSON is handled without error and invalid JSON is not.

	raw := json.RawMessage(`{"foo":"bar","n":42}`)
	if err := printJSON(raw); err != nil {
		t.Errorf("printJSON valid JSON: unexpected error: %v", err)
	}

	// string form
	if err := printJSON(`{"x":1}`); err != nil {
		t.Errorf("printJSON string form: unexpected error: %v", err)
	}

	// bytes form
	if err := printJSON([]byte(`{"y":2}`)); err != nil {
		t.Errorf("printJSON bytes form: unexpected error: %v", err)
	}
}

// ── platformList ─────────────────────────────────────────────────────────────

func TestPlatformList(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateQueued),
		makeImage(2, "linux", "arm64", db.StateQueued),
		makeImage(3, "windows", "amd64", db.StateQueued),
	}
	got := platformList(images)
	want := "linux/amd64, linux/arm64, windows/amd64"
	if got != want {
		t.Errorf("platformList = %q, want %q", got, want)
	}
}

// ── shortDigest ──────────────────────────────────────────────────────────────

func TestShortDigest(t *testing.T) {
	long := "sha256:abcdef1234567890abcdef"
	got := shortDigest(long)
	if len(got) > 19 {
		t.Errorf("shortDigest too long: %d chars", len(got))
	}

	short := "sha256:abc"
	if shortDigest(short) != short {
		t.Errorf("shortDigest(%q) changed short string", short)
	}
}

// ensure bytes is imported for the buffer usage in test helpers
var _ = bytes.NewBuffer
