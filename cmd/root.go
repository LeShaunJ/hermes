package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
)

var (
	dbPath   string
	database *db.DB
)

var rootCmd = &cobra.Command{
	Use:   "hermes",
	Short: "OCI image approval system",
	Long: `hermes manages OCI image tag approvals and gatekeeps OCI Distribution
registries via a REST API used as nginx auth_request middleware.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// serve opens its own DB after parsing flags; skip here.
		if cmd.Name() == "serve" {
			return nil
		}
		d, err := db.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open database %q: %w", dbPath, err)
		}
		database = d
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if database != nil {
			return database.Close()
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
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "hermes.db", "path to the SQLite database")
}
