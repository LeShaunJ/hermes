package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
)

var viewPlatform string

var viewCmd = &cobra.Command{
	Use:   "view [--platform OS/ARCH] IMAGE",
	Short: "Show all stored information for an OCI image tag",
	Long: `view prints the database record and trivy scan report for IMAGE.

If the image is multi-platform, all platforms are shown unless --platform
is specified.

Examples:
  hermes view registry.example.com/myapp:v1.2.3
  hermes view --platform linux/amd64 registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runView,
}

func init() {
	addPlatformFlag(viewCmd, &viewPlatform, "show")
	rootCmd.AddCommand(viewCmd)
}

func runView(_ *cobra.Command, args []string) error {
	ref, err := resolveRef(args[0], true)
	if err != nil {
		return err
	}

	images, err := database.GetByRef(ref)
	if err != nil {
		return err
	}
	if len(images) == 0 {
		return fmt.Errorf("image not found: %s/%s:%s", ref.Registry, ref.Repository, ref.Tag)
	}

	// Filter by platform if requested.
	if viewPlatform != "" {
		img, err := selectPlatform(images, viewPlatform)
		if err != nil {
			return err
		}
		images = []*db.Image{img}
	}

	w := os.Stdout
	line := strings.Repeat("─", 72)

	for _, img := range images {
		_, _ = fmt.Fprintln(w, line)
		_, _ = fmt.Fprintf(w, "%-16s %s/%s:%s\n", "Image:", img.RegistryURL, img.Repository, img.TagName)
		_, _ = fmt.Fprintf(w, "%-16s %s/%s\n", "Platform:", img.OS, img.Arch)
		_, _ = fmt.Fprintf(w, "%-16s %s\n", "State:", img.State)
		if img.Digest != "" {
			_, _ = fmt.Fprintf(w, "%-16s %s\n", "Digest:", img.Digest)
		}
		if img.CacheRegistry != "" {
			_, _ = fmt.Fprintf(w, "%-16s %s\n", "Cache registry:", img.CacheRegistry)
		}
		_, _ = fmt.Fprintf(w, "%-16s %s\n", "Created:", img.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
		_, _ = fmt.Fprintf(w, "%-16s %s\n", "Updated:", img.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))

		if len(img.ScanReport) > 0 && string(img.ScanReport) != "null" {
			_, _ = fmt.Fprintln(w, line)
			_, _ = fmt.Fprintln(w, "Vulnerability Summary:")
			printVulnSummary(w, img.ScanReport)

			_, _ = fmt.Fprintln(w, line)
			_, _ = fmt.Fprintln(w, "Scan Report:")
			_ = printJSON(img.ScanReport)
		}
	}

	return nil
}

// printVulnSummary parses the trivy JSON and prints severity totals.
func printVulnSummary(w *os.File, raw json.RawMessage) {
	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				Severity string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		_, _ = fmt.Fprintln(w, "  (could not parse scan report)")
		return
	}

	counts := map[string]int{}
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			counts[v.Severity]++
		}
	}

	total := 0
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		_, _ = fmt.Fprintln(w, "  No vulnerabilities found.")
		return
	}

	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			_, _ = fmt.Fprintf(w, "  %-10s %d\n", sev+":", n)
		}
	}
	_, _ = fmt.Fprintf(w, "  %-10s %d\n", "TOTAL:", total)
}
