package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
)

var rejectCmd = &cobra.Command{
	Use:   "reject <image>",
	Short: "Reject an OCI image tag (do not use)",
	Long: `reject marks an image tag as rejected, signalling that it must not be
used. Unlike rescind, rejection is a deliberate "do not use" declaration.

If the image already has a record (e.g. from a prior approval), the existing
manifest and Trivy report are preserved and only the status is changed.
If the image has no prior record, a skeleton record is created.

Re-approving a rejected image requires an explicit 'hermes approve'.

Examples:
  hermes reject registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runReject,
}

func init() {
	rootCmd.AddCommand(rejectCmd)
}

func runReject(_ *cobra.Command, args []string) error {
	ref, err := oci.ParseRef(args[0])
	if err != nil {
		return err
	}

	if err := database.UpsertStatus(ref, db.StatusRejected); err != nil {
		return err
	}

	fmt.Printf("rejected  %s/%s:%s\n", ref.Registry, ref.Repository, ref.Tag)
	return nil
}
