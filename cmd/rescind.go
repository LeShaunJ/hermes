package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
)

var rescindPlatform string

var rescindCmd = &cobra.Command{
	Use:   "rescind [--platform OS/ARCH] IMAGE",
	Short: "Rescind approval for an OCI image tag",
	Long: `rescind sets platform images for a previously approved IMAGE to the
'rescinded' state, immediately preventing them from passing the API's
authorization check.

Without --platform every platform for IMAGE must be in the 'approved' state
and all of them are rescinded.  With --platform only the matching platform
is rescinded; other platforms are left untouched.

A rescinded image can be re-approved with 'hermes approve'.

Examples:
  hermes rescind registry.example.com/myapp:v1.2.3
  hermes rescind --platform linux/amd64 registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runRescind,
}

func init() {
	rescindCmd.Flags().StringVar(&rescindPlatform, "platform", "", "rescind only this platform (os/arch, e.g. linux/amd64)")
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

	// Narrow to a single platform when --platform is given.
	if rescindPlatform != "" {
		img, err := selectPlatform(images, rescindPlatform)
		if err != nil {
			return err
		}
		images = []*db.Image{img}
	}

	// Every target platform must currently be approved.
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
