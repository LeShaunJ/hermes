package ui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/leshaunj/hermes/internal/db"
)

func TestStateClass(t *testing.T) {
	cases := []struct {
		state db.State
		want  string
	}{
		{db.StateApproved, "state state-approved"},
		{db.StateRejected, "state state-rejected"},
		{db.StateQueued, "state state-pending"},
		{db.StateScanned, "state state-pending"},
		{db.StateRescinded, "state state-pending"},
		{db.StateVoided, "state state-pending"},
		{db.StateErrored, "state state-errored"},
		{db.State("garbage"), "state"},
	}
	for _, c := range cases {
		if got := stateClass(c.state); got != c.want {
			t.Errorf("stateClass(%q) = %q, want %q", c.state, got, c.want)
		}
	}
}

func TestShortDigest(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"sha256:abcdefabcdefabcdef", "sha256:abcdefabcdef"},
		{"abcdefabcdefabcdef", "abcdefabcdef"},
		{"short", "short"},
	}
	for _, c := range cases {
		if got := shortDigest(c.in); got != c.want {
			t.Errorf("shortDigest(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatTime(t *testing.T) {
	if got := formatTime(time.Time{}); got != "" {
		t.Errorf("zero time should render empty, got %q", got)
	}
	ts := time.Date(2026, 4, 26, 12, 34, 56, 0, time.UTC)
	if got := formatTime(ts); got != "2026-04-26 12:34:56Z" {
		t.Errorf("formatTime = %q", got)
	}
}

func TestFormatRelative(t *testing.T) {
	if got := formatRelative(time.Time{}); got != "" {
		t.Errorf("zero time should render empty, got %q", got)
	}
	now := time.Now()
	cases := []struct {
		t        time.Time
		contains string
	}{
		{now.Add(-30 * time.Second), "just now"},
		{now.Add(-5 * time.Minute), "m ago"},
		{now.Add(-3 * time.Hour), "h ago"},
		{now.Add(-2 * 24 * time.Hour), "d ago"},
	}
	for _, c := range cases {
		got := formatRelative(c.t)
		if !strings.Contains(got, c.contains) {
			t.Errorf("formatRelative(%v) = %q, want contains %q", c.t, got, c.contains)
		}
	}
}

func TestVulnSummary(t *testing.T) {
	if got := vulnSummary(nil); got != nil {
		t.Errorf("nil report should yield nil, got %v", got)
	}
	if got := vulnSummary(json.RawMessage(`null`)); got != nil {
		t.Errorf("null report should yield nil, got %v", got)
	}
	if got := vulnSummary(json.RawMessage(`not json`)); got != nil {
		t.Errorf("bad json should yield nil, got %v", got)
	}

	report := json.RawMessage(`{
		"Results": [
			{"Vulnerabilities": [
				{"Severity":"CRITICAL"},
				{"Severity":"high"},
				{"Severity":"NEGLIGIBLE"}
			]},
			{"Vulnerabilities": [
				{"Severity":"HIGH"},
				{"Severity":"low"}
			]}
		]
	}`)
	got := vulnSummary(report)
	want := map[string]int{"CRITICAL": 1, "HIGH": 2, "LOW": 1, "NEGLIGIBLE": 1}
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4: %v", len(got), got)
	}
	for _, sc := range got {
		if want[sc.Severity] != sc.Count {
			t.Errorf("severity %s count = %d, want %d", sc.Severity, sc.Count, want[sc.Severity])
		}
	}
	// Canonical block must lead.
	if got[0].Severity != "CRITICAL" {
		t.Errorf("first = %s, want CRITICAL", got[0].Severity)
	}
}

func TestPrettyJSON(t *testing.T) {
	if got := prettyJSON(nil); got != "" {
		t.Errorf("nil = %q, want empty", got)
	}
	if got := prettyJSON(json.RawMessage(`{"a":1}`)); !strings.Contains(got, "  ") {
		t.Errorf("expected indented output, got %q", got)
	}
	// Invalid JSON falls back to the original bytes.
	if got := prettyJSON(json.RawMessage(`not json`)); got != "not json" {
		t.Errorf("invalid json fallback = %q", got)
	}
}

func TestIsStub(t *testing.T) {
	full := db.Image{Digest: "sha256:abc"}
	if isStub(full) {
		t.Error("full image flagged as stub")
	}
	stub := db.Image{}
	if !isStub(stub) {
		t.Error("stub not detected")
	}
}
