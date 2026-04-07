package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
	scanCmd.Flags().StringVar(&scanPlatform, "platform", "", "platform to scan (os/arch, e.g. linux/amd64)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(_ *cobra.Command, args []string) error {
	imageRef := args[0]

	reg, repo, tag, err := oci.ParseRef(imageRef)
	if err != nil {
		return err
	}
	ref := db.ImageRef{Registry: reg, Repository: repo, Tag: tag}

	// Ensure the image is in the DB (fetches manifests if new).
	fmt.Fprintf(os.Stderr, "Queuing %s...\n", imageRef)
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
		return printJSON(img.ScanReport)
	}

	// Build the digest-pinned ref for trivy so it scans the exact platform image.
	scanRef := imageRef
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

	img, err = database.SaveScan(img.ID, json.RawMessage(result.Raw))
	if err != nil {
		return fmt.Errorf("save scan: %w", err)
	}

	logEvent("scan", img, map[string]interface{}{"digest": img.Digest})
	return printJSON(img.ScanReport)
}

// ── platform selection ────────────────────────────────────────────────────────

// selectPlatform returns the image matching the requested platform string
// ("os/arch"), or prompts the user if multiple images exist and no platform
// was specified.  Returns an error if images is empty or no match is found.
func selectPlatform(images []*db.Image, platform string) (*db.Image, error) {
	if len(images) == 0 {
		return nil, fmt.Errorf("no images found")
	}

	if platform != "" {
		parts := strings.SplitN(platform, "/", 2)
		wantOS, wantArch := parts[0], ""
		if len(parts) == 2 {
			wantArch = parts[1]
		}
		for _, img := range images {
			if strings.EqualFold(img.OS, wantOS) && (wantArch == "" || strings.EqualFold(img.Arch, wantArch)) {
				return img, nil
			}
		}
		return nil, fmt.Errorf("no image found for platform %q (available: %s)", platform, platformList(images))
	}

	if len(images) == 1 {
		return images[0], nil
	}

	// Multi-platform, no --platform given: prompt.
	fmt.Fprintln(os.Stderr, "Multiple platforms available:")
	for i, img := range images {
		fmt.Fprintf(os.Stderr, "  [%d] %s/%s  digest: %s\n", i+1, img.OS, img.Arch, shortDigest(img.Digest))
	}
	answer, err := prompt("Select platform [1]: ")
	if err != nil {
		return nil, err
	}
	answer = strings.TrimSpace(answer)
	if answer == "" {
		answer = "1"
	}
	idx := 0
	if _, err := fmt.Sscan(answer, &idx); err != nil || idx < 1 || idx > len(images) {
		return nil, fmt.Errorf("invalid selection %q", answer)
	}
	return images[idx-1], nil
}

func platformList(images []*db.Image) string {
	parts := make([]string, len(images))
	for i, img := range images {
		parts[i] = img.OS + "/" + img.Arch
	}
	return strings.Join(parts, ", ")
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

// printJSON pretty-prints a JSON value to stdout.
func printJSON(v interface{}) error {
	var raw json.RawMessage
	switch t := v.(type) {
	case json.RawMessage:
		raw = t
	case string:
		raw = json.RawMessage(t)
	case []byte:
		raw = json.RawMessage(t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		raw = b
	}
	// Pretty-print.
	var out interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		// Not valid JSON — just print it.
		_, err = os.Stdout.Write(raw)
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// logEvent logs a CLI event for img (which may be nil).
func logEvent(eventType string, img *db.Image, details map[string]interface{}) {
	var id *int64
	if img != nil {
		id = &img.ID
	}
	_ = database.LogEvent(id, db.SourceCLI, eventType, details)
}
