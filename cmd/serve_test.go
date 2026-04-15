package cmd

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/leshaunj/hermes/internal/db"
)

func TestStreamEvents_emitsOneSlogLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(orig) })

	id := int64(42)
	ch := make(chan *db.Event, 3)
	ch <- &db.Event{
		ID: 1, ImageID: &id, Source: db.SourceCLI, EventType: "scan",
		Details: `{"digest":"sha256:abc"}`,
	}
	ch <- &db.Event{
		ID: 2, Source: db.SourceAPI, EventType: "validate_approved",
	}
	ch <- &db.Event{
		ID: 3, Source: db.SourceAPI, EventType: "validate_denied",
		Details: "null",
	}
	close(ch)

	streamEvents(ch)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 slog lines, got %d: %q", len(lines), buf.String())
	}

	var scan map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &scan); err != nil {
		t.Fatalf("line 0 not JSON: %v", err)
	}
	if scan["event_type"] != "scan" || scan["source"] != "cli" {
		t.Errorf("line 0 = %v, want scan/cli", scan)
	}
	if scan["image_id"] != float64(42) {
		t.Errorf("line 0 image_id = %v, want 42", scan["image_id"])
	}
	details, ok := scan["details"].(map[string]any)
	if !ok {
		t.Fatalf("line 0 details missing or wrong type: %v", scan["details"])
	}
	if details["digest"] != "sha256:abc" {
		t.Errorf("line 0 details.digest = %v, want sha256:abc", details["digest"])
	}

	var approved map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &approved); err != nil {
		t.Fatalf("line 1 not JSON: %v", err)
	}
	if approved["event_type"] != "validate_approved" {
		t.Errorf("line 1 event_type = %v, want validate_approved", approved["event_type"])
	}
	if _, has := approved["image_id"]; has {
		t.Errorf("line 1 should not carry image_id for nil ID: %v", approved)
	}
	if _, has := approved["details"]; has {
		t.Errorf("line 1 should not carry details for empty string: %v", approved)
	}

	var denied map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &denied); err != nil {
		t.Fatalf("line 2 not JSON: %v", err)
	}
	if _, has := denied["details"]; has {
		t.Errorf("line 2 should not carry details for literal null: %v", denied)
	}
}
