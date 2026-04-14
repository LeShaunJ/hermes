package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"INFO":    slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"err":     slog.LevelError,
		"bogus":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJournaldPriority(t *testing.T) {
	cases := map[slog.Level]string{
		slog.LevelDebug:     "7",
		slog.LevelInfo:      "6",
		slog.LevelWarn:      "4",
		slog.LevelError:     "3",
		slog.LevelError + 4: "3", // above error still "err"
	}
	for in, want := range cases {
		if got := JournaldPriority(in); got != want {
			t.Errorf("JournaldPriority(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestInit_jsonFormat(t *testing.T) {
	var buf bytes.Buffer
	l := Init(Config{Format: FormatJSON, Level: "debug"}, &buf)
	if l == nil {
		t.Fatal("Init returned nil")
	}
	if slog.Default() != l {
		t.Error("Init did not install logger as slog.Default")
	}

	l.Debug("hello", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, buf.String())
	}
	if rec["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", rec["msg"])
	}
	if rec["level"] != "DEBUG" {
		t.Errorf("level = %v, want DEBUG", rec["level"])
	}
	if rec["k"] != "v" {
		t.Errorf("k = %v, want v", rec["k"])
	}
	if _, ok := rec["time"]; !ok {
		t.Error("standard JSON format should include time")
	}
}

func TestInit_journaldFormat(t *testing.T) {
	var buf bytes.Buffer
	l := Init(Config{Format: FormatJournald, Level: "info"}, &buf)

	l.Warn("boom", "reason", "x")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, buf.String())
	}
	if rec["MESSAGE"] != "boom" {
		t.Errorf("MESSAGE = %v, want boom", rec["MESSAGE"])
	}
	if rec["PRIORITY"] != "4" {
		t.Errorf("PRIORITY = %v, want 4", rec["PRIORITY"])
	}
	if _, ok := rec["time"]; ok {
		t.Error("journald format should drop time")
	}
	if _, ok := rec["msg"]; ok {
		t.Error("journald format should drop msg key")
	}
	if _, ok := rec["level"]; ok {
		t.Error("journald format should drop level key")
	}
	if rec["reason"] != "x" {
		t.Errorf("reason = %v, want x", rec["reason"])
	}
}

func TestInit_levelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := Init(Config{Format: FormatJSON, Level: "warn"}, &buf)
	l.Info("should not appear")
	if buf.Len() != 0 {
		t.Errorf("info should be filtered, got %q", buf.String())
	}
	l.Error("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("error missing from output: %q", buf.String())
	}
}

func TestInit_nilWriterDefaultsToStderr(t *testing.T) {
	// Just verify it doesn't panic and installs a non-nil default.
	l := Init(Config{}, nil)
	if l == nil {
		t.Fatal("nil logger")
	}
}

func TestInit_unknownFormatFallsBackToJSON(t *testing.T) {
	var buf bytes.Buffer
	l := Init(Config{Format: Format("yaml")}, &buf)
	l.Info("x")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec["msg"] != "x" {
		t.Errorf("msg = %v, want x", rec["msg"])
	}
}
