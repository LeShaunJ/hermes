package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
)

var rescindCmd = &cobra.Command{
	Use:   "rescind IMAGE",
	Short: "Rescind approval for an OCI image tag",
	Long: `rescind sets a previously approved IMAGE to the 'rescinded' state,
immediately preventing it from passing the API's authorization check.

A rescinded image can be re-approved with 'hermes approve'.

Examples:
  hermes rescind registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runRescind,
}

func init() {
	rootCmd.AddCommand(rescindCmd)
}

func runRescind(_ *cobra.Command, args []string) error {
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
	if img.State != db.StateApproved {
		return fmt.Errorf("image is %s, not approved — cannot rescind", img.State)
	}

	if err := database.Rescind(ref); err != nil {
		return err
	}

	logEvent("rescind", img, nil)
	fmt.Printf("rescinded  %s/%s:%s\n", ref.Registry, ref.Repository, ref.Tag)
	return nil
}
