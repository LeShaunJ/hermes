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

var (
	scanForce    bool
	scanPlatform string
)

var scanCmd = &cobra.Command{
	Use:   "scan [--platform OS/ARCH] IMAGE",
	Short: "Scan an OCI image with trivy",
	Long: `scan queues IMAGE if needed, fetching manifests for all platforms.
Then it runs a trivy vulnerability scan on the selected platform and saves
the report to the database.

If the image already has a scan report (state is not 'queued') the existing
report is printed unless --force is provided.

Use --platform to select a specific platform (e.g. linux/amd64).
If the image is multi-platform and --platform is omitted, you will be prompted.

Examples:
  hermes scan registry.example.com/myapp:v1.2.3
  hermes scan --platform linux/amd64 registry.example.com/myapp:v1.2.3
  hermes scan --force registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&scanForce, "force", false, "re-scan even if a report already exists")
	addPlatformFlag(scanCmd, &scanPlatform, "scan")
	rootCmd.AddCommand(scanCmd)
}

func runScan(_ *cobra.Command, args []string) error {
	imageRef := args[0]

	ref, err := resolveRef(imageRef, false)
	if err != nil {
		return err
	}
	reg, repo, tag := ref.Registry, ref.Repository, ref.Tag

	// Ensure the image is in the DB (fetches manifests if new).
	fmt.Fprintf(os.Stderr, "Queuing %s/%s:%s...\n", reg, repo, tag)
	images, err := database.Queue(ref, oci.NewDefaultClient())
	if err != nil {
		return fmt.Errorf("queue image: %w", err)
	}

	// Select the target platform image.
	img, err := selectPlatform(images, scanPlatform)
	if err != nil {
		return err
	}

	// If already scanned (or beyond) and not forced, return the existing report.
	if !scanForce && img.State != db.StateQueued && len(img.ScanReport) > 0 && string(img.ScanReport) != "null" {
		fmt.Fprintf(os.Stderr, "state: %s (use --force to re-scan)\n", img.State)
		return printScanReport(os.Stdout, img.ScanReport)
	}

	// Build the digest-pinned ref for trivy so it scans the exact platform image.
	scanRef := fmt.Sprintf("%s/%s:%s", reg, repo, tag)
	if img.Digest != "" {
		scanRef = fmt.Sprintf("%s/%s@%s", reg, repo, img.Digest)
	}

	fmt.Fprintf(os.Stderr, "Scanning %s (%s/%s) with trivy...\n", scanRef, img.OS, img.Arch)
	result, err := trivy.Scan(scanRef, cfg.Trivy)
	if err != nil {
		_ = database.SetError(img.ID)
		logEvent("scan_error", img, map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("trivy scan: %w", err)
	}

	imgID := img.ID
	img, err = database.SaveScan(imgID, json.RawMessage(result.Raw))
	if err != nil {
		_ = database.SetError(imgID)
		logEvent("scan_error", img, map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("save scan: %w", err)
	}

	logEvent("scan", img, map[string]interface{}{"digest": img.Digest})
	return printScanReport(os.Stdout, img.ScanReport)
}
