package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/oci"
	"github.com/leshaunj/hermes/internal/trivy"
)

var (
	reportFormat string
	reportOutput string
)

var reportCmd = &cobra.Command{
	Use:   "report [--format FORMAT] [--output FILE] IMAGE",
	Short: "Convert and output the trivy report for an OCI image tag",
	Long: `report retrieves the stored trivy JSON report for IMAGE and converts it
to the requested FORMAT using 'trivy convert'.

Output is written to stdout or to FILE if --output is specified.

Supported formats: table, json, template, sarif, cyclonedx, spdx, spdx-json,
github, cosign-vuln.

Examples:
  hermes report registry.example.com/myapp:v1.2.3
  hermes report --format sarif --output report.sarif registry.example.com/myapp:v1.2.3
  hermes report --format cyclonedx registry.example.com/myapp:v1.2.3 | jq .`,
	Args: cobra.ExactArgs(1),
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportFormat, "format", "table", "output format for trivy convert")
	reportCmd.Flags().StringVar(&reportOutput, "output", "", "write output to FILE instead of stdout")
	rootCmd.AddCommand(reportCmd)
}

func runReport(_ *cobra.Command, args []string) error {
	if err := trivy.ValidateFormat(reportFormat); err != nil {
		return err
	}

	ref, err := oci.ParseRef(args[0])
	if err != nil {
		return err
	}

	img, err := database.GetByRef(ref)
	if err != nil {
		return err
	}
	if img == nil {
		return fmt.Errorf("image not found: %s/%s:%s", ref.Registry, ref.Repository, ref.Tag)
	}
	if img.ScanReport == "" {
		return fmt.Errorf("no scan report available for %s/%s:%s (state: %s)",
			ref.Registry, ref.Repository, ref.Tag, img.State)
	}

	// json format — just output the raw stored report directly (no trivy convert needed)
	if reportFormat == "json" {
		if reportOutput == "" || reportOutput == "-" {
			_, err = os.Stdout.WriteString(img.ScanReport)
			return err
		}
		return os.WriteFile(reportOutput, []byte(img.ScanReport), 0o644)
	}

	return trivy.ConvertToFile([]byte(img.ScanReport), reportFormat, reportOutput, cfg.Trivy)
}
