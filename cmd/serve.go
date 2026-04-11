package cmd

import (
	"fmt"

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

	srv := api.New(d, cfg)
	return srv.ListenAndServe()
}
