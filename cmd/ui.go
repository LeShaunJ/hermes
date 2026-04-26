package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/ui"
)

var uiAddr string

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start the operator web console",
	Long: `ui starts the hermes operator web console, a server-rendered
HTML interface for browsing tracked images, viewing scan reports, and
running approve / reject / rescind / scan actions from the browser.

The console talks to the same Postgres database as the OCI gateway and
emits the same audit events, so CLI and UI activity remain interleaved in
a single event log.

This command does NOT terminate TLS or perform authentication; deploy
the listener behind a reverse proxy (nginx, oauth2-proxy, etc.) that
handles both.`,
	Args: cobra.NoArgs,
	RunE: runUI,
}

func init() {
	uiCmd.Flags().StringVar(&uiAddr, "addr", "", "listen address (overrides config)")
	rootCmd.AddCommand(uiCmd)
}

func runUI(_ *cobra.Command, _ []string) error {
	if uiAddr != "" {
		cfg.UI.Addr = uiAddr
	}

	d, err := db.Open(cfg.DB.DSN())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := d.Listen(ctx)
	if err != nil {
		return fmt.Errorf("start event listener: %w", err)
	}

	srv := ui.New(d, cfg)
	// Tee the event stream: the SSE hub fans out to connected browsers,
	// and slog mirrors every event to stderr so operators can tail the
	// container log just like they would for `hermes serve`.
	hubCh, slogCh := teeEvents(ctx, events)
	srv.Subscribe(hubCh)
	go streamEvents(slogCh)

	return srv.ListenAndServe()
}

// teeEvents fans a single db.Event channel into two downstream channels so
// both the SSE hub and the slog mirror receive every event.  Closes both
// outputs when the input is closed or ctx is cancelled.
func teeEvents(ctx context.Context, in <-chan *db.Event) (<-chan *db.Event, <-chan *db.Event) {
	a := make(chan *db.Event, 64)
	b := make(chan *db.Event, 64)
	go func() {
		defer close(a)
		defer close(b)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				// Best-effort fanout: drop on a slow consumer rather than
				// stalling the upstream listener.
				select {
				case a <- ev:
				default:
				}
				select {
				case b <- ev:
				default:
				}
			}
		}
	}()
	return a, b
}
