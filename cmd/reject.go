package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
)

var rejectPlatform string

var rejectCmd = &cobra.Command{
	Use:   "reject [--platform OS/ARCH] IMAGE",
	Short: "Reject an OCI image tag",
	Long: `reject marks platform images for IMAGE as rejected — a deliberate
"do not use" declaration.

Without --platform, every platform image for IMAGE is rejected.  With
--platform only the matching platform is rejected; other platforms are
left untouched.

You will be asked to confirm before the rejection is recorded.
Enter YES to confirm; anything else cancels the operation.

A rejected image can be re-approved with 'hermes approve' (which forces a
fresh scan).

Examples:
  hermes reject registry.example.com/myapp:v1.2.3
  hermes reject --platform linux/amd64 registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runReject,
}

func init() {
	rejectCmd.Flags().StringVar(&rejectPlatform, "platform", "", "reject only this platform (os/arch, e.g. linux/amd64)")
	rootCmd.AddCommand(rejectCmd)
}

func runReject(_ *cobra.Command, args []string) error {
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
	if rejectPlatform != "" {
		img, err := selectPlatform(images, rejectPlatform)
		if err != nil {
			return err
		}
		images = []*db.Image{img}
	}

	scope := fmt.Sprintf("%d platform(s)", len(images))
	if rejectPlatform != "" && len(images) == 1 {
		scope = fmt.Sprintf("%s/%s", images[0].OS, images[0].Arch)
	}

	answer, err := prompt(fmt.Sprintf(
		"Reject %s/%s:%s (%s)? [YES / NO] (default: NO): ",
		reg, repo, tag, scope,
	))
	if err != nil {
		return err
	}

	if strings.ToUpper(strings.TrimSpace(answer)) != "YES" {
		fmt.Println("Cancelled.")
		return nil
	}

	for _, img := range images {
		if err := database.Reject(img.ID); err != nil {
			return err
		}
		logEvent("reject", img, nil)
	}

	fmt.Printf("rejected  %s/%s:%s\n", reg, repo, tag)
	return nil
}
