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
	listStates   []string
	listJSON     bool
	listPlatform string
)

var listCmd = &cobra.Command{
	Use:   "list [--platform OS/ARCH] [--state STATE[,...]] [--json] [REF ...]",
	Short: "List tracked OCI image tags",
	Long: `list prints image records from the database as a table (or JSON).

STATE may be any individual state (queued, scanned, approved, rescinded,
rejected, error) or a group name (pending, verified).  Multiple values can
be combined with commas or by repeating the flag.

--platform narrows to a single OS/ARCH pair (e.g. linux/amd64).  A single
segment with no slash (e.g. "linux") matches any architecture.  Stub tags
are excluded when --platform is set since they have no resolved platform yet.

REF filters by [namespace/]name[:tag].  Multiple REFs are OR-ed together.

Examples:
  hermes list
  hermes list --state approved
  hermes list --state pending,verified
  hermes list --state approved --json
  hermes list --platform linux/amd64 --state pending
  hermes list myapp:v1.2.3 otherapp`,
	RunE: runList,
}

func init() {
	listCmd.Flags().StringArrayVar(&listStates, "state", nil, "filter by state or group (comma-separated or repeated)")
	listCmd.Flags().BoolVar(&listJSON, "json", false, "output as JSON array")
	listCmd.Flags().StringVar(&listPlatform, "platform", "", "filter by platform (os/arch, e.g. linux/amd64)")
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

	platformOS, platformArch, err := parsePlatformFilter(listPlatform)
	if err != nil {
		return err
	}

	images, err := database.List(db.ListFilter{
		States: states,
		Refs:   args,
		OS:     platformOS,
		Arch:   platformArch,
	})
	if err != nil {
		return err
	}

	if listJSON {
		return outputJSON(images)
	}

	return outputTable(images)
}

// parsePlatformFilter splits "os/arch" into its two components.  A single
// segment ("linux") leaves arch empty for a match-any filter.  An empty
// input yields two empty strings (no filter).
func parsePlatformFilter(platform string) (os, arch string, err error) {
	platform = strings.TrimSpace(platform)
	if platform == "" {
		return "", "", nil
	}
	parts := strings.SplitN(platform, "/", 2)
	os = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		arch = strings.TrimSpace(parts[1])
	}
	if os == "" {
		return "", "", fmt.Errorf("invalid --platform %q", platform)
	}
	return os, arch, nil
}

func outputTable(images []db.Image) error {
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "REGISTRY\tREPOSITORY\tTAG\tOS\tARCH\tDIGEST\tSTATE\tUPDATED")
	for _, img := range images {
		digest := img.Digest
		if len(digest) > 19 {
			digest = digest[:19] // "sha256:" + 12 hex chars
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			img.RegistryURL,
			img.Repository,
			img.TagName,
			dash(img.OS),
			dash(img.Arch),
			dash(digest),
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
