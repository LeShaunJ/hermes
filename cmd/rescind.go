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
	Long: `rescind sets all platform images for a previously approved IMAGE to the
'rescinded' state, immediately preventing them from passing the API's
authorization check.

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
	reg, repo, tag, err := oci.ParseRef(args[0])
	if err != nil {
		return err
	}
	ref := db.ImageRef{Registry: reg, Repository: repo, Tag: tag}

	images, err := database.GetByRef(ref)
	if err != nil {
		return err
	}
	if len(images) == 0 {
		return fmt.Errorf("image not found: %s/%s:%s", reg, repo, tag)
	}

	// All platform images must be approved to rescind.
	for _, img := range images {
		if img.State != db.StateApproved {
			return fmt.Errorf("platform %s/%s is %s, not approved — cannot rescind %s/%s:%s",
				img.OS, img.Arch, img.State, reg, repo, tag)
		}
	}

	for _, img := range images {
		if err := database.Rescind(img.ID); err != nil {
			return err
		}
		logEvent("rescind", img, nil)
	}

	fmt.Printf("rescinded  %s/%s:%s\n", reg, repo, tag)
	return nil
}
