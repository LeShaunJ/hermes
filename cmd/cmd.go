package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
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

		// serve opens its own DB connection; skip here.
		if cmd.Name() == "serve" {
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
