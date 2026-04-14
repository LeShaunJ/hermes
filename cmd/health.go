package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// healthTimeout bounds the /healthz probe.  Kept small so a hung server does
// not stall container orchestrators during liveness checks.
const healthTimeout = 5 * time.Second

// healthClient is the HTTP client used by runHealth.  Tests override it.
var healthClient = &http.Client{Timeout: healthTimeout}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Probe the local hermes /healthz endpoint",
	Long: `health issues a GET against the running hermes server's /healthz endpoint
and exits 0 when the server responds with 200 OK.  It exists primarily as the
Containerfile HEALTHCHECK command — unlike a bare 'curl /healthz' it already
knows where to find the server from hermes.yaml.`,
	Args: cobra.NoArgs,
	RunE: runHealth,
}

func init() {
	rootCmd.AddCommand(healthCmd)
}

func runHealth(_ *cobra.Command, _ []string) error {
	url := healthURL(cfg.Server.Addr)
	return healthProbe(url)
}

// healthURL derives the local probe URL from a listen address.
// ":8080", "0.0.0.0:8080", and "[::]:8080" all resolve to
// "http://127.0.0.1:8080/healthz".
func healthURL(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = strings.TrimPrefix(addr, ":")
	}
	if port == "" {
		port = "8080"
	}
	return "http://127.0.0.1:" + port + "/healthz"
}

// healthProbe issues a GET against url and returns nil when the server
// responds 200.  Any other status or transport error is returned so cobra
// exits non-zero.
func healthProbe(url string) error {
	resp, err := healthClient.Get(url)
	if err != nil {
		return fmt.Errorf("health probe: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Drain a small prefix of the body for context in the error.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("health probe: %s: %s",
			resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
