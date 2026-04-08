package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
)

var (
	cfgPath  string
	cfg      *config.Config
	database *db.DB
)

var rootCmd = &cobra.Command{
	Use:   "hermes",
	Short: "OCI image approval system",
	Long: `hermes manages OCI image tag approvals and gatekeeps OCI Distribution
registries via a REST API used as nginx auth_request middleware.`,
	SilenceUsage:      true,
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
