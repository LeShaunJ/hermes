package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
)

var rescindPlatform string

var rescindCmd = &cobra.Command{
	Use:   "rescind [--platform OS/ARCH] IMAGE",
	Short: "Rescind approval for an OCI image tag",
	Long: `rescind sets a previously approved platform image for IMAGE to the
'rescinded' state, immediately preventing it from passing the gateway's
authorization check.

With --platform, only the matching platform is considered (and it must
currently be approved).  Without --platform, hermes filters IMAGE to its
approved platforms: if exactly one is approved it is selected automatically,
and if several are approved you are prompted to pick one.

You are asked to confirm before the rescind is recorded.  Enter YES to
confirm; anything else cancels the operation.

A rescinded image can be re-approved with 'hermes approve'.

Examples:
  hermes rescind registry.example.com/myapp:v1.2.3
  hermes rescind --platform linux/amd64 registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runRescind,
}

func init() {
	addPlatformFlag(rescindCmd, &rescindPlatform, "rescind")
	rootCmd.AddCommand(rescindCmd)
}

func runRescind(_ *cobra.Command, args []string) error {
	ref, err := resolveRef(args[0], true)
	if err != nil {
		return err
	}
	reg, repo, tag := ref.Registry, ref.Repository, ref.Tag

	images, err := database.GetByRef(ref)
	if err != nil {
		return err
	}
	if len(images) == 0 {
		return fmt.Errorf("image not found: %s/%s:%s", reg, repo, tag)
	}

	var target *db.Image
	if rescindPlatform != "" {
		img, err := selectPlatform(images, rescindPlatform)
		if err != nil {
			return err
		}
		if img.State != db.StateApproved {
			return fmt.Errorf("platform %s/%s is %s, not approved — cannot rescind %s/%s:%s",
				img.OS, img.Arch, img.State, reg, repo, tag)
		}
		target = img
	} else {
		approved := make([]*db.Image, 0, len(images))
		for _, img := range images {
			if img.State == db.StateApproved {
				approved = append(approved, img)
			}
		}
		if len(approved) == 0 {
			return fmt.Errorf("no approved platforms for %s/%s:%s", reg, repo, tag)
		}
		img, err := selectPlatform(approved, "")
		if err != nil {
			return err
		}
		target = img
	}

	answer, err := confirm(fmt.Sprintf(
		"Rescind %s/%s:%s (%s/%s)? [YES / NO] (default: NO): ",
		reg, repo, tag, target.OS, target.Arch,
	))
	if err != nil {
		return err
	}
	if answer != "YES" {
		fmt.Println("Cancelled.")
		return nil
	}

	if err := database.Rescind(target.ID); err != nil {
		return err
	}
	logEvent("rescind", target, nil)

	fmt.Printf("rescinded  %s/%s:%s  (%s/%s)\n", reg, repo, tag, target.OS, target.Arch)
	return nil
}
