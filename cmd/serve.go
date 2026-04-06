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
	Long: `serve starts the hermes HTTP server which acts as nginx auth_request
middleware for OCI Distribution registry proxies.

The server exposes:
  GET /validate_image  — authorization check (returns 200 or 401)
  GET /healthz         — liveness probe

nginx configuration example:

  location ~ ^/v2/(?<repo>.+)/manifests/(?<tag>.+)$ {
      auth_request /validate_image;
      auth_request_set $approved_digest $upstream_http_x_approved_digest;
      auth_request_set $registry_domain $upstream_http_x_registry_domain;

      proxy_pass https://$registry_domain/v2/$repo/manifests/$approved_digest;
  }

  location = /validate_image {
      internal;
      proxy_pass http://hermes:8080/validate_image?repo=$repo&tag=$tag;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
  }`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":8080", "listen address")
	rootCmd.AddCommand(serveCmd)
}

func runServe(_ *cobra.Command, _ []string) error {
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database %q: %w", dbPath, err)
	}
	defer d.Close()

	srv := api.New(d, serveAddr)
	return srv.ListenAndServe()
}
