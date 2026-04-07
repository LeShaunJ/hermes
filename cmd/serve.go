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
  GET /validate/<registry>/v2/<repo>/manifests/<tag>
      Authorization check.  Returns 200 + X-HERMES-IMAGE-URI if approved.
      Queues unknown images for later CLI review.

  GET /healthz
      Liveness probe.

nginx configuration example (see dev/nginx.conf for a full example):

  location ~ ^/(?<registry>[^/]+)/(?<path>v2/.+)$ {
      auth_request     /hermes-validate/$registry/$path;
      auth_request_set $hermes_uri $upstream_http_x_hermes_image_uri;
      proxy_pass       https://$hermes_uri;
  }

  location /hermes-validate/ {
      internal;
      proxy_pass              http://hermes:8080/validate/;
      proxy_pass_request_body off;
      proxy_set_header        Content-Length "";
  }`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "", "listen address (overrides config)")
	rootCmd.AddCommand(serveCmd)
}

func runServe(_ *cobra.Command, _ []string) error {
	addr := cfg.Server.Addr
	if serveAddr != "" {
		addr = serveAddr
	}

	d, err := db.Open(cfg.DB.DSN())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer d.Close()

	srv := api.New(d, addr)
	return srv.ListenAndServe()
}
