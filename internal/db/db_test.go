package db

import (
	"encoding/json"
	"testing"
)

// ── GroupOf ───────────────────────────────────────────────────────────────────

func TestGroupOf(t *testing.T) {
	tests := []struct {
		state State
		want  Group
	}{
		{StateQueued, GroupPending},
		{StateScanned, GroupPending},
		{StateRescinded, GroupPending},
		{StateApproved, GroupVerified},
		{StateRejected, GroupVerified},
		{StateError, ""},
	}
	for _, tc := range tests {
		got := GroupOf(tc.state)
		if got != tc.want {
			t.Errorf("GroupOf(%q) = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// ── ParseStateOrGroup ─────────────────────────────────────────────────────────

func TestParseStateOrGroup(t *testing.T) {
	tests := []struct {
		input   string
		want    []State
		wantErr bool
	}{
		{"queued", []State{StateQueued}, false},
		{"scanned", []State{StateScanned}, false},
		{"approved", []State{StateApproved}, false},
		{"rescinded", []State{StateRescinded}, false},
		{"rejected", []State{StateRejected}, false},
		{"error", []State{StateError}, false},
		{"pending", []State{StateQueued, StateScanned, StateRescinded}, false},
		{"verified", []State{StateApproved, StateRejected}, false},
		{"unknown", nil, true},
		{"", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseStateOrGroup(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseStateOrGroup(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStateOrGroup(%q) unexpected error: %v", tc.input, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParseStateOrGroup(%q) len = %d, want %d", tc.input, len(got), len(tc.want))
			}
			for i, s := range got {
				if s != tc.want[i] {
					t.Errorf("ParseStateOrGroup(%q)[%d] = %q, want %q", tc.input, i, s, tc.want[i])
				}
			}
		})
	}
}

// ── isImageManifest / isImageIndex ────────────────────────────────────────────

func TestIsImageManifest(t *testing.T) {
	trueCases := []string{
		mediaTypeOCIManifest,
		mediaTypeDockerV2,
	}
	falseCases := []string{
		mediaTypeOCIIndex,
		mediaTypeDockerList,
		"application/json",
		"",
	}
	for _, mt := range trueCases {
		if !isImageManifest(mt) {
			t.Errorf("isImageManifest(%q) = false, want true", mt)
		}
	}
	for _, mt := range falseCases {
		if isImageManifest(mt) {
			t.Errorf("isImageManifest(%q) = true, want false", mt)
		}
	}
}

func TestIsImageIndex(t *testing.T) {
	trueCases := []string{
		mediaTypeOCIIndex,
		mediaTypeDockerList,
	}
	falseCases := []string{
		mediaTypeOCIManifest,
		mediaTypeDockerV2,
		"application/json",
		"",
	}
	for _, mt := range trueCases {
		if !isImageIndex(mt) {
			t.Errorf("isImageIndex(%q) = false, want true", mt)
		}
	}
	for _, mt := range falseCases {
		if isImageIndex(mt) {
			t.Errorf("isImageIndex(%q) = true, want false", mt)
		}
	}
}

// ── extractConfigDigest ───────────────────────────────────────────────────────

func TestExtractConfigDigest(t *testing.T) {
	manifest := struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}{
		Config: struct {
			Digest string `json:"digest"`
		}{Digest: "sha256:abc123"},
	}
	b, _ := json.Marshal(manifest)

	got, err := extractConfigDigest(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sha256:abc123" {
		t.Errorf("digest = %q, want sha256:abc123", got)
	}
}

func TestExtractConfigDigest_missing(t *testing.T) {
	b := []byte(`{"config":{}}`)
	_, err := extractConfigDigest(b)
	if err == nil {
		t.Error("expected error for missing digest, got nil")
	}
}

func TestExtractConfigDigest_invalidJSON(t *testing.T) {
	_, err := extractConfigDigest([]byte("{invalid}"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
