package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/logger"
)

// datastore is the subset of db.DB operations used by CLI commands.
// *db.DB satisfies this interface automatically.
type datastore interface {
	Queue(ref db.ImageRef, fetcher db.Fetcher) ([]*db.Image, error)
	SetError(imageID int64) error
	SaveScan(imageID int64, scanReport json.RawMessage) (*db.Image, error)
	LogEvent(imageID *int64, source db.EventSource, eventType string, details map[string]interface{}) error
	List(f db.ListFilter) ([]db.Image, error)
	GetByRef(ref db.ImageRef) ([]*db.Image, error)
	FindRegistriesForRef(repository, tag string) ([]string, error)
	Approve(imageID int64, cacheRegistry string) error
	Reject(imageID int64) error
	Rescind(imageID int64) error
	Close()
}

var (
	cfgPath  string
	cfg      *config.Config
	database datastore
)

var rootCmd = &cobra.Command{
	Use:   "hermes",
	Short: "OCI image approval system",
	Long: `hermes manages OCI image tag approvals and acts as an
authoritative gateway for OCI Distribution registries.`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration.
		c, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		cfg = c

		// Install the global logger before anything may log.  Only `serve`
		// streams events to its real sink — CLI commands route the slog
		// mirror to io.Discard so per-event JSON cannot interleave with
		// interactive output (the events still land in the events table
		// via db.LogEvent's INSERT either way).
		logger.Init(logger.Config{
			Format: logger.Format(cfg.Log.Format),
			Level:  cfg.Log.Level,
		}, loggerSinkFor(cmd.Name()))

		// serve and ui open their own DB connection, and health doesn't need
		// one at all — skip the connect for all three so a dead DB doesn't
		// block them either.
		switch cmd.Name() {
		case "serve", "ui", "health":
			return nil
		}

		d, err := db.Open(cfg.DB.DSN())
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		database = d
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if database != nil {
			database.Close()
		}
		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", config.DefaultPath, "path to hermes.yaml")
}

// loggerSinkFor picks the io.Writer the global slog logger should use for
// the given cobra command name.  Only the long-running daemons (`serve` and
// `ui`) write to os.Stderr so their logs can be tailed via journalctl/Loki;
// everything else (one-shot CLI commands) routes to io.Discard so the
// per-event slog mirror cannot interleave with interactive output.
func loggerSinkFor(cmdName string) io.Writer {
	switch cmdName {
	case "serve", "ui":
		return os.Stderr
	}
	return io.Discard
}
