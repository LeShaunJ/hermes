package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
	"github.com/leshaunj/hermes/internal/trivy"
)

// ── ref resolution ────────────────────────────────────────────────────────────

// resolveRef parses imageRef and picks the right registry.  When the operator
// explicitly included a registry prefix (as detected by oci.RefHasRegistry),
// the reference is used as-is.  Otherwise the DB is queried for every
// registry currently hosting (repository, tag) so the command can act on the
// one the operator meant rather than silently defaulting to docker.io:
//
//   - 0 matches — if mustExist, error out; otherwise fall back to the default
//     registry so scan/approve can still queue a brand-new image from Docker
//     Hub.
//   - 1 match  — use that registry.
//   - >1 match — prompt the operator to choose.
func resolveRef(imageRef string, mustExist bool) (db.ImageRef, error) {
	reg, repo, tag, err := oci.ParseRef(imageRef)
	if err != nil {
		return db.ImageRef{}, err
	}
	if oci.RefHasRegistry(imageRef) {
		return db.ImageRef{Registry: reg, Repository: repo, Tag: tag}, nil
	}

	regs, err := database.FindRegistriesForRef(repo, tag)
	if err != nil {
		return db.ImageRef{}, fmt.Errorf("resolve registry: %w", err)
	}
	switch len(regs) {
	case 0:
		if mustExist {
			return db.ImageRef{}, fmt.Errorf("image not found: %s:%s", repo, tag)
		}
		return db.ImageRef{Registry: reg, Repository: repo, Tag: tag}, nil
	case 1:
		return db.ImageRef{Registry: regs[0], Repository: repo, Tag: tag}, nil
	}

	fmt.Fprintf(os.Stderr, "Multiple registries host %s:%s:\n", repo, tag)
	for i, r := range regs {
		fmt.Fprintf(os.Stderr, "  [%d] %s\n", i+1, r)
	}
	answer, err := prompt("Select registry [1]: ")
	if err != nil {
		return db.ImageRef{}, err
	}
	answer = strings.TrimSpace(answer)
	if answer == "" {
		answer = "1"
	}
	idx := 0
	if _, err := fmt.Sscan(answer, &idx); err != nil || idx < 1 || idx > len(regs) {
		return db.ImageRef{}, fmt.Errorf("invalid selection %q", answer)
	}
	return db.ImageRef{Registry: regs[idx-1], Repository: repo, Tag: tag}, nil
}

// ── platform selection ────────────────────────────────────────────────────────

// selectPlatform returns the image matching the requested platform string
// ("os/arch"), or prompts the user if multiple images exist and no platform
// was specified.  Returns an error if images is empty or no match is found.
//
// excludeStates lists states whose images are shown in the prompt but are not
// available for selection (e.g. pass db.StateApproved for the approve command).
// Pass no excludeStates to make all images selectable.
func selectPlatform(images []*db.Image, platform string, excludeStates ...db.State) (*db.Image, error) {
	if len(images) == 0 {
		return nil, fmt.Errorf("no images found")
	}

	isExcluded := func(img *db.Image) bool {
		for _, s := range excludeStates {
			if img.State == s {
				return true
			}
		}
		return false
	}

	if platform != "" {
		parts := strings.SplitN(platform, "/", 2)
		wantOS, wantArch := parts[0], ""
		if len(parts) == 2 {
			wantArch = parts[1]
		}
		for _, img := range images {
			if strings.EqualFold(img.OS, wantOS) && (wantArch == "" || strings.EqualFold(img.Arch, wantArch)) {
				if isExcluded(img) {
					return nil, fmt.Errorf("platform %q is already %s", platform, img.State)
				}
				return img, nil
			}
		}
		return nil, fmt.Errorf("no image found for platform %q (available: %s)", platform, platformList(images))
	}

	// Build the selectable subset.
	var selectable []*db.Image
	for _, img := range images {
		if !isExcluded(img) {
			selectable = append(selectable, img)
		}
	}

	if len(selectable) == 1 && len(images) == 1 {
		return selectable[0], nil
	}
	if len(selectable) == 0 {
		return nil, fmt.Errorf("all platforms are already %s", excludeStates[0])
	}
	if len(selectable) == 1 {
		// Only one selectable platform — auto-select without prompting.
		return selectable[0], nil
	}

	// Multi-platform, no --platform given: prompt.
	fmt.Fprintln(os.Stderr, "Multiple platforms available:")
	selIdx := 0
	for _, img := range images {
		if isExcluded(img) {
			fmt.Fprintf(os.Stderr, "      %s/%s  (%s) — already %s\n",
				img.OS, img.Arch, img.State, img.State)
		} else {
			selIdx++
			fmt.Fprintf(os.Stderr, "  [%d] %s/%s  (%s)  digest: %s\n",
				selIdx, img.OS, img.Arch, img.State, shortDigest(img.Digest))
		}
	}
	answer, err := prompt("Select platform [1]: ")
	if err != nil {
		return nil, err
	}
	answer = strings.TrimSpace(answer)
	if answer == "" {
		answer = "1"
	}
	idx := 0
	if _, err := fmt.Sscan(answer, &idx); err != nil || idx < 1 || idx > len(selectable) {
		return nil, fmt.Errorf("invalid selection %q", answer)
	}
	return selectable[idx-1], nil
}

func platformList(images []*db.Image) string {
	parts := make([]string, len(images))
	for i, img := range images {
		parts[i] = img.OS + "/" + img.Arch
	}
	return strings.Join(parts, ", ")
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

// ── flag helpers ──────────────────────────────────────────────────────────────

// addPlatformFlag registers a --platform string flag on c.  verb is inserted
// into the usage string (e.g. "scan", "approve").
func addPlatformFlag(c *cobra.Command, target *string, verb string) {
	c.Flags().StringVar(target, "platform", "",
		verb+" only this platform (os/arch, e.g. linux/amd64)")
}

// ── prompts ───────────────────────────────────────────────────────────────────

// prompt writes message to stderr and reads a line from stdin.
func prompt(message string) (string, error) {
	fmt.Fprint(os.Stderr, message)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}

// confirm wraps prompt and returns the uppercased/trimmed answer so callers
// can compare against "YES", "NO", "REJECT", etc. without repeating the
// normalisation at each site.
func confirm(message string) (string, error) {
	ans, err := prompt(message)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(strings.TrimSpace(ans)), nil
}

// ── output helpers ────────────────────────────────────────────────────────────

// printJSON pretty-prints a JSON value to stdout.
func printJSON(v interface{}) error {
	var raw json.RawMessage
	switch t := v.(type) {
	case json.RawMessage:
		raw = t
	case string:
		raw = json.RawMessage(t)
	case []byte:
		raw = json.RawMessage(t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		raw = b
	}
	// Pretty-print.
	var out interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		// Not valid JSON — just print it.
		_, err = os.Stdout.Write(raw)
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// printScanReport renders a stored trivy JSON report as the human-readable
// trivy table format and writes it to w.  Empty/null reports are a no-op.
func printScanReport(w io.Writer, report json.RawMessage) error {
	if len(report) == 0 || string(report) == "null" {
		return nil
	}
	out, err := trivy.Convert(report, "table", cfg.Trivy)
	if err != nil {
		return fmt.Errorf("render scan table: %w", err)
	}
	_, err = w.Write(out)
	return err
}

// ── event logging ─────────────────────────────────────────────────────────────

// logEvent logs a CLI event for img (which may be nil).
func logEvent(eventType string, img *db.Image, details map[string]interface{}) {
	var id *int64
	if img != nil {
		id = &img.ID
	}
	_ = database.LogEvent(id, db.SourceCLI, eventType, details)
}
