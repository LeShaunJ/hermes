package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/oci"
	"github.com/leshaunj/hermes/internal/trivy"
)

var approveCmd = &cobra.Command{
	Use:   "approve <image>",
	Short: "Scan and approve an OCI image tag",
	Long: `approve runs a Trivy vulnerability scan, fetches the manifest and digest
from the registry, then records the image as approved in the database.

If the image was previously approved, rescinded, or rejected, this command
re-approves it with a fresh scan and manifest.

Examples:
  hermes approve registry.example.com/myapp:v1.2.3
  hermes approve docker.io/library/nginx:1.27`,
	Args: cobra.ExactArgs(1),
	RunE: runApprove,
}

func init() {
	rootCmd.AddCommand(approveCmd)
}

func runApprove(_ *cobra.Command, args []string) error {
	imageRef := args[0]

	ref, err := oci.ParseRef(imageRef)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Scanning %s with Trivy...\n", imageRef)
	scanResult, err := trivy.Scan(imageRef)
	if err != nil {
		return fmt.Errorf("trivy scan: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Fetching manifest from %s...\n", ref.Registry)
	manifest, err := oci.FetchManifest(imageRef)
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}

	if err := database.UpsertApproved(ref, manifest.Digest, string(manifest.Manifest), string(scanResult.Raw)); err != nil {
		return fmt.Errorf("save to database: %w", err)
	}

	fmt.Printf("approved  %s/%s:%s\n", ref.Registry, ref.Repository, ref.Tag)
	fmt.Printf("digest    %s\n", manifest.Digest)
	return nil
}
