// Package logger initializes the global hermes slog logger from configuration.
//
// Two wire formats are supported:
//
//   - FormatJSON: standard slog JSON — a "time", "level" (slog label),
//     "msg", and attribute keys at the top level.  This format is what Loki,
//     Promtail, Vector, and similar pipelines expect out of the box.
//
//   - FormatJournald: JSON using systemd-journal field conventions — "MESSAGE"
//     for the message and "PRIORITY" for the syslog numeric priority (0-7).
//     Suitable for piping into systemd-cat, journald's native JSON forwarder,
//     or any downstream that reads structured journald records.
package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format selects the handler wire format.
type Format string

const (
	// FormatJSON is standard slog JSON, Loki-compatible.
	FormatJSON Format = "json"
	// FormatJournald is JSON with journald MESSAGE/PRIORITY field names.
	FormatJournald Format = "journald"
)

// Config configures the global logger.
//
// Both fields are optional: Format defaults to FormatJSON, Level to "info".
type Config struct {
	Format Format `mapstructure:"format"`
	Level  string `mapstructure:"level"`
}

// Init builds a logger from cfg writing to w and installs it as slog.Default().
// When w is nil, os.Stderr is used.
func Init(cfg Config, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	level := ParseLevel(cfg.Level)
	var h slog.Handler
	switch Format(strings.ToLower(string(cfg.Format))) {
	case FormatJournald:
		h = newJournaldHandler(w, level)
	default: // "" or FormatJSON
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

// ParseLevel maps a level name to a slog.Level.  Unknown values fall back to
// slog.LevelInfo.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default: // "" or "info"
		return slog.LevelInfo
	}
}

// newJournaldHandler returns a slog.Handler that emits journald-style JSON:
// "MESSAGE" instead of "msg", "PRIORITY" (syslog 0-7 as string) instead of
// "level", and no "time" (journald stamps its own).
func newJournaldHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) > 0 {
				return a
			}
			switch a.Key {
			case slog.TimeKey:
				return slog.Attr{}
			case slog.MessageKey:
				return slog.String("MESSAGE", a.Value.String())
			case slog.LevelKey:
				lv, _ := a.Value.Any().(slog.Level)
				return slog.String("PRIORITY", JournaldPriority(lv))
			}
			return a
		},
	})
}

// JournaldPriority maps a slog.Level to its syslog numeric priority, as a
// string (journald stores PRIORITY as text):
//
//	slog.LevelDebug -> "7" (debug)
//	slog.LevelInfo  -> "6" (info)
//	slog.LevelWarn  -> "4" (warning)
//	slog.LevelError -> "3" (err)
func JournaldPriority(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "3"
	case l >= slog.LevelWarn:
		return "4"
	case l >= slog.LevelInfo:
		return "6"
	default:
		return "7"
	}
}
