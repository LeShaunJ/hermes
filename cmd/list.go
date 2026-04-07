package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
)

var (
	listStates []string
	listJSON   bool
)

var listCmd = &cobra.Command{
	Use:   "list [--state STATE[,...]] [--json] [REF ...]",
	Short: "List tracked OCI image tags",
	Long: `list prints image records from the database as a table (or JSON).

STATE may be any individual state (queued, scanned, approved, rescinded,
rejected, error) or a group name (pending, verified).  Multiple values can
be combined with commas or by repeating the flag.

REF filters by [namespace/]name[:tag].  Multiple REFs are OR-ed together.

Examples:
  hermes list
  hermes list --state approved
  hermes list --state pending,verified
  hermes list --state approved --json
  hermes list myapp:v1.2.3 otherapp`,
	RunE: runList,
}

func init() {
	listCmd.Flags().StringArrayVar(&listStates, "state", nil, "filter by state or group (comma-separated or repeated)")
	listCmd.Flags().BoolVar(&listJSON, "json", false, "output as JSON array")
	rootCmd.AddCommand(listCmd)
}

func runList(_ *cobra.Command, args []string) error {
	// Build state filter.
	var states []db.State
	for _, raw := range listStates {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			matched, err := db.ParseStateOrGroup(part)
			if err != nil {
				return err
			}
			states = append(states, matched...)
		}
	}

	// Deduplicate states.
	if len(states) > 0 {
		seen := map[db.State]bool{}
		deduped := states[:0]
		for _, s := range states {
			if !seen[s] {
				seen[s] = true
				deduped = append(deduped, s)
			}
		}
		states = deduped
	}

	images, err := database.List(db.ListFilter{
		States: states,
		Refs:   args,
	})
	if err != nil {
		return err
	}

	if listJSON {
		return outputJSON(images)
	}

	return outputTable(images)
}

func outputTable(images []db.Image) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "REGISTRY\tREPOSITORY\tTAG\tOS\tARCH\tDIGEST\tSTATE\tUPDATED")
	for _, img := range images {
		digest := img.Digest
		if len(digest) > 19 {
			digest = digest[:19] // "sha256:" + 12 hex chars
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			img.RegistryURL,
			img.Repository,
			img.TagName,
			img.OS,
			img.Arch,
			digest,
			img.State,
			img.UpdatedAt.Format("2006-01-02 15:04"),
		)
	}
	return w.Flush()
}

func outputJSON(images []db.Image) error {
	type jsonImage struct {
		ID            int64  `json:"id"`
		Registry      string `json:"registry"`
		Repository    string `json:"repository"`
		Tag           string `json:"tag"`
		OS            string `json:"os,omitempty"`
		Arch          string `json:"arch,omitempty"`
		Digest        string `json:"digest,omitempty"`
		State         string `json:"state"`
		CacheRegistry string `json:"cache_registry,omitempty"`
		CreatedAt     string `json:"created_at"`
		UpdatedAt     string `json:"updated_at"`
	}
	out := make([]jsonImage, len(images))
	for i, img := range images {
		out[i] = jsonImage{
			ID:            img.ID,
			Registry:      img.RegistryURL,
			Repository:    img.Repository,
			Tag:           img.TagName,
			OS:            img.OS,
			Arch:          img.Arch,
			Digest:        img.Digest,
			State:         string(img.State),
			CacheRegistry: img.CacheRegistry,
			CreatedAt:     img.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:     img.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
