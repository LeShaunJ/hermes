package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
	"github.com/leshaunj/hermes/internal/trivy"
)

var scanForce bool

var scanCmd = &cobra.Command{
	Use:   "scan IMAGE",
	Short: "Scan an OCI image with trivy",
	Long: `scan queues IMAGE if needed, runs a trivy vulnerability scan, saves the
report to the database, and prints the JSON report to stdout.

If the image already has a scan report (state is not 'queued') the existing
report is printed unless --force is provided.

Examples:
  hermes scan registry.example.com/myapp:v1.2.3
  hermes scan --force registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&scanForce, "force", false, "re-scan even if a report already exists")
	rootCmd.AddCommand(scanCmd)
}

func runScan(_ *cobra.Command, args []string) error {
	imageRef := args[0]

	ref, err := oci.ParseRef(imageRef)
	if err != nil {
		return err
	}

	// Ensure the image is in the DB.
	img, err := database.Queue(ref)
	if err != nil {
		return fmt.Errorf("queue image: %w", err)
	}

	// If already scanned (or beyond) and not forced, return the existing report.
	if !scanForce && img != nil && img.State != db.StateQueued && img.ScanReport != "" {
		fmt.Fprintf(os.Stderr, "state: %s (use --force to re-scan)\n", img.State)
		return printJSON(img.ScanReport)
	}

	fmt.Fprintf(os.Stderr, "Fetching manifest for %s...\n", imageRef)
	manifest, err := oci.FetchManifest(imageRef)
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Scanning %s with trivy...\n", imageRef)
	result, err := trivy.Scan(imageRef, cfg.Trivy)
	if err != nil {
		_ = database.SetError(ref)
		logEvent("scan_error", img, map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("trivy scan: %w", err)
	}

	img, err = database.SaveScan(ref, manifest.Digest, string(manifest.Manifest), string(result.Raw))
	if err != nil {
		return fmt.Errorf("save scan: %w", err)
	}

	logEvent("scan", img, map[string]interface{}{"digest": manifest.Digest})
	return printJSON(img.ScanReport)
}

// printJSON pretty-prints a JSON string to stdout.
func printJSON(raw string) error {
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		fmt.Println(raw)
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// logEvent logs a CLI event for img (which may be nil).
func logEvent(eventType string, img *db.Image, details map[string]interface{}) {
	var id *int64
	if img != nil {
		id = &img.ID
	}
	_ = database.LogEvent(id, db.SourceCLI, eventType, details)
}
