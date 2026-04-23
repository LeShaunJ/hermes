package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/trivy"
)

var (
	reportFormat   string
	reportOutput   string
	reportPlatform string
)

var reportCmd = &cobra.Command{
	Use:   "report [--platform OS/ARCH] [--format FORMAT] [--output FILE] IMAGE",
	Short: "Convert and output the trivy report for an OCI image tag",
	Long: `report retrieves the stored trivy JSON report for IMAGE and converts it
to the requested FORMAT using 'trivy convert'.

Use --platform to select a specific platform (e.g. linux/amd64).
If the image is multi-platform and --platform is omitted, you will be prompted.

Output is written to stdout or to FILE if --output is specified.

Supported formats: table, json, template, sarif, cyclonedx, spdx, spdx-json,
github, cosign-vuln.

Examples:
  hermes report registry.example.com/myapp:v1.2.3
  hermes report --platform linux/amd64 --format sarif --output report.sarif registry.example.com/myapp:v1.2.3
  hermes report --format cyclonedx registry.example.com/myapp:v1.2.3 | jq .`,
	Args: cobra.ExactArgs(1),
	RunE: runReport,
}

func init() {
	addPlatformFlag(reportCmd, &reportPlatform, "report on")
	reportCmd.Flags().StringVar(&reportFormat, "format", "table", "output format for trivy convert")
	reportCmd.Flags().StringVar(&reportOutput, "output", "", "write output to FILE instead of stdout")
	rootCmd.AddCommand(reportCmd)
}

func runReport(_ *cobra.Command, args []string) error {
	if err := trivy.ValidateFormat(reportFormat); err != nil {
		return err
	}

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

	img, err := selectPlatform(images, reportPlatform)
	if err != nil {
		return err
	}

	if len(img.ScanReport) == 0 || string(img.ScanReport) == "null" {
		return fmt.Errorf("no scan report available for %s/%s:%s %s/%s (state: %s)",
			ref.Registry, ref.Repository, ref.Tag, img.OS, img.Arch, img.State)
	}

	// json format — output the raw stored report directly.
	if reportFormat == "json" {
		if reportOutput == "" || reportOutput == "-" {
			_, err = os.Stdout.Write(img.ScanReport)
			return err
		}
		return os.WriteFile(reportOutput, img.ScanReport, 0o644)
	}

	return trivy.ConvertToFile(img.ScanReport, reportFormat, reportOutput, cfg.Trivy)
}
