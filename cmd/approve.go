package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
	"github.com/leshaunj/hermes/internal/trivy"
)

var (
	approveCache    string
	approveCacheSet bool
)

var approveCmd = &cobra.Command{
	Use:   "approve [--cache [URL]] IMAGE",
	Short: "Review the scan report and approve an OCI image tag",
	Long: `approve queues IMAGE if needed, scans it if needed (rejected images are
always re-scanned), presents the JSON report, and prompts for YES / NO / REJECT.

  YES    — approves the image (state: approved)
  NO     — does nothing (leaves state unchanged); exits 0
  REJECT — rejects the image immediately (state: rejected); exits 1

If --cache is provided the image is pushed to the specified URL upon YES
(or to cache_url in hermes.yaml if the flag is given with no value).
A successful push records the cache registry in the database.
A failed push sets state to 'error' and exits non-zero.

Examples:
  hermes approve registry.example.com/myapp:v1.2.3
  hermes approve --cache registry.example.com/myapp:v1.2.3
  hermes approve --cache cache.internal.example.com registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runApprove,
}

func init() {
	// --cache may be given with or without a URL value.
	approveCmd.Flags().StringVar(&approveCache, "cache", "", "push image to this registry upon approval (uses cache_url from config if empty)")
	approveCmd.Flags().Lookup("cache").NoOptDefVal = "__use_config__"
	rootCmd.AddCommand(approveCmd)
}

func runApprove(cmd *cobra.Command, args []string) error {
	imageRef := args[0]

	ref, err := oci.ParseRef(imageRef)
	if err != nil {
		return err
	}

	// Resolve cache URL.
	cacheURL := ""
	if cmd.Flags().Changed("cache") {
		cacheURL = approveCache
		if cacheURL == "__use_config__" || cacheURL == "" {
			cacheURL = cfg.CacheURL
		}
	}

	// Get or create the DB record.
	img, err := database.Queue(ref)
	if err != nil {
		return fmt.Errorf("queue image: %w", err)
	}

	// Determine whether a (re-)scan is needed.
	needsScan := img.State == db.StateQueued || img.State == db.StateRejected || img.ScanReport == ""

	if needsScan {
		fmt.Fprintf(os.Stderr, "Fetching manifest for %s...\n", imageRef)
		manifest, err := oci.FetchManifest(imageRef)
		if err != nil {
			return fmt.Errorf("fetch manifest: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Scanning %s with trivy...\n", imageRef)
		result, err := trivy.Scan(imageRef, cfg.Trivy)
		if err != nil {
			_ = database.SetError(ref)
			logEvent("scan_error", img, map[string]interface{}{"error": err.Error()})
			return fmt.Errorf("trivy scan: %w", err)
		}

		img, err = database.SaveScan(ref, manifest.Digest, string(manifest.Manifest), string(result.Raw))
		if err != nil {
			return fmt.Errorf("save scan: %w", err)
		}
		logEvent("scan", img, map[string]interface{}{"digest": manifest.Digest})
	}

	// Display the report.
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 72))
	if err := printJSON(img.ScanReport); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 72))
	fmt.Fprintf(os.Stderr, "Image: %s/%s:%s  (digest: %s)\n", ref.Registry, ref.Repository, ref.Tag, img.Digest)
	fmt.Fprintln(os.Stderr)

	// Prompt.
	answer, err := prompt("Approve this image? [YES / NO / REJECT] (default: NO): ")
	if err != nil {
		return err
	}

	switch strings.ToUpper(strings.TrimSpace(answer)) {
	case "YES":
		// Push to cache if requested.
		if cacheURL != "" {
			fmt.Fprintf(os.Stderr, "Pushing %s to %s...\n", imageRef, cacheURL)
			if err := pushToCache(imageRef, ref, cacheURL); err != nil {
				_ = database.SetError(ref)
				logEvent("cache_push_error", img, map[string]interface{}{
					"cache_url": cacheURL,
					"error":     err.Error(),
				})
				return fmt.Errorf("cache push failed: %w", err)
			}
		}

		if err := database.Approve(ref, cacheURL); err != nil {
			return fmt.Errorf("approve: %w", err)
		}
		logEvent("approve", img, map[string]interface{}{"cache_url": cacheURL})
		fmt.Printf("approved  %s/%s:%s\n", ref.Registry, ref.Repository, ref.Tag)

	case "REJECT":
		if err := database.Reject(ref); err != nil {
			return fmt.Errorf("reject: %w", err)
		}
		logEvent("reject", img, nil)
		fmt.Printf("rejected  %s/%s:%s\n", ref.Registry, ref.Repository, ref.Tag)
		return fmt.Errorf("image rejected")

	default: // NO or empty
		fmt.Fprintln(os.Stderr, "No action taken.")
	}

	return nil
}

// prompt writes the message to stderr and reads a line from stdin.
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

// pushToCache pushes imageRef to the cache registry using `docker` commands.
func pushToCache(imageRef string, ref db.ImageRef, cacheURL string) error {
	// Build the destination tag: <cacheURL>/<repository>:<tag>
	dest := fmt.Sprintf("%s/%s:%s", cacheURL, ref.Repository, ref.Tag)

	// Pull the image locally.
	if out, err := exec.Command("docker", "pull", imageRef).CombinedOutput(); err != nil {
		return fmt.Errorf("docker pull: %s: %w", string(out), err)
	}

	// Re-tag.
	if out, err := exec.Command("docker", "tag", imageRef, dest).CombinedOutput(); err != nil {
		return fmt.Errorf("docker tag: %s: %w", string(out), err)
	}

	// Push.
	if out, err := exec.Command("docker", "push", dest).CombinedOutput(); err != nil {
		return fmt.Errorf("docker push: %s: %w", string(out), err)
	}

	// Clean up the local re-tagged image.
	_ = exec.Command("docker", "rmi", dest).Run()

	return nil
}
