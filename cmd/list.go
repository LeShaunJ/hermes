package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
)

var listStatus string

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List tracked OCI image tags",
	Long: `list prints all image records in the database as a table.

Use --status to filter by approval state.

Examples:
  hermes list
  hermes list --status approved
  hermes list --status rejected`,
	Args: cobra.NoArgs,
	RunE: runList,
}

func init() {
	listCmd.Flags().StringVar(&listStatus, "status", "", "filter by status: approved, rescinded, or rejected")
	rootCmd.AddCommand(listCmd)
}

func runList(_ *cobra.Command, _ []string) error {
	var statusFilter db.ImageStatus
	switch listStatus {
	case "approved":
		statusFilter = db.StatusApproved
	case "rescinded":
		statusFilter = db.StatusRescinded
	case "rejected":
		statusFilter = db.StatusRejected
	case "":
		statusFilter = ""
	default:
		return fmt.Errorf("unknown status %q: must be approved, rescinded, or rejected", listStatus)
	}

	images, err := database.List(statusFilter)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "REGISTRY\tREPOSITORY\tTAG\tDIGEST\tSTATUS\tUPDATED")
	for _, img := range images {
		digest := img.Digest
		if len(digest) > 19 {
			digest = digest[:19] // "sha256:" + 12 hex chars
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			img.Registry,
			img.Repository,
			img.Tag,
			digest,
			img.Status,
			img.UpdatedAt.Format("2006-01-02 15:04"),
		)
	}
	return w.Flush()
}
