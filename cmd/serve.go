package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/api"
	"github.com/leshaunj/hermes/internal/db"
)

var serveAddr string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the REST API server",
	Long: `serve starts the hermes HTTP server which acts as an
authoritative gateway for OCI Distribution registries.`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "", "listen address (overrides config)")
	rootCmd.AddCommand(serveCmd)
}

func runServe(_ *cobra.Command, _ []string) error {
	if serveAddr != "" {
		cfg.Server.Addr = serveAddr
	}

	d, err := db.Open(cfg.DB.DSN())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer d.Close()

	// Start the Postgres LISTEN subscription so every event — from gateway
	// handlers AND from out-of-process CLI commands (docker exec, separate
	// binaries, etc.) — is streamed through serve's slog and therefore into
	// the container log.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := d.Listen(ctx)
	if err != nil {
		return fmt.Errorf("start event listener: %w", err)
	}
	go streamEvents(events)

	srv := api.New(d, cfg)
	return srv.ListenAndServe()
}

// streamEvents consumes events from ch and emits each one via slog so it
// lands on serve's stderr and, transitively, the container log.
func streamEvents(ch <-chan *db.Event) {
	for ev := range ch {
		attrs := []any{
			slog.String("source", string(ev.Source)),
			slog.String("event_type", ev.EventType),
		}
		if ev.ImageID != nil {
			attrs = append(attrs, slog.Int64("image_id", *ev.ImageID))
		}
		if ev.Details != "" && ev.Details != "null" {
			var details map[string]any
			if err := json.Unmarshal([]byte(ev.Details), &details); err == nil {
				detailAttrs := make([]any, 0, len(details))
				for k, v := range details {
					detailAttrs = append(detailAttrs, slog.Any(k, v))
				}
				attrs = append(attrs, slog.Group("details", detailAttrs...))
			}
		}
		slog.Info("event", attrs...)
	}
}
