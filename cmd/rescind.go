package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
)

var rescindCmd = &cobra.Command{
	Use:   "rescind <image>",
	Short: "Rescind approval for an OCI image tag",
	Long: `rescind marks a previously approved image as rescinded, immediately
preventing it from passing the API's authorization check.

The image can be re-approved with 'hermes approve'.

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

	if err := database.UpsertStatus(ref, db.StatusRescinded); err != nil {
		return err
	}

	fmt.Printf("rescinded  %s/%s:%s\n", ref.Registry, ref.Repository, ref.Tag)
	return nil
}
