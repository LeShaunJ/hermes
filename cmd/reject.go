package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/oci"
)

var rejectCmd = &cobra.Command{
	Use:   "reject IMAGE",
	Short: "Reject an OCI image tag",
	Long: `reject marks an IMAGE as rejected — a deliberate "do not use" declaration.

You will be asked to confirm before the rejection is recorded.
Enter YES to confirm; anything else cancels the operation.

A rejected image can be re-approved with 'hermes approve' (which forces a
fresh scan).

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

	img, err := database.GetByRef(ref)
	if err != nil {
		return err
	}

	answer, err := prompt(fmt.Sprintf(
		"Reject %s/%s:%s? [YES / NO] (default: NO): ",
		ref.Registry, ref.Repository, ref.Tag,
	))
	if err != nil {
		return err
	}

	if strings.ToUpper(strings.TrimSpace(answer)) != "YES" {
		fmt.Println("Cancelled.")
		return nil
	}

	if err := database.Reject(ref); err != nil {
		return err
	}

	logEvent("reject", img, nil)
	fmt.Printf("rejected  %s/%s:%s\n", ref.Registry, ref.Repository, ref.Tag)
	return nil
}
