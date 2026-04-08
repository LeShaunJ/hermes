package cmd

import (
	"bufio"
	"encoding/json"
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
	approvePlatform string
)

var approveCmd = &cobra.Command{
	Use:   "approve [--platform OS/ARCH] [--cache [URL]] IMAGE",
	Short: "Review the scan report and approve an OCI image tag",
	Long: `approve queues IMAGE if needed, scans it if needed (rejected images are
always re-scanned), presents the JSON report, and prompts for YES / NO / REJECT.

  YES    — approves the image (state: approved)
  NO     — does nothing (leaves state unchanged); exits 0
  REJECT — rejects the image immediately (state: rejected); exits 1

Use --platform to select a specific platform (e.g. linux/amd64).
If the image is multi-platform and --platform is omitted, you will be prompted.

If --cache is provided the image is pushed to the specified URL upon YES
(or to cache_url in hermes.yaml if the flag is given with no value).
A successful push records the cache registry in the database.
A failed push sets state to 'error' and exits non-zero.

Examples:
  hermes approve registry.example.com/myapp:v1.2.3
  hermes approve --platform linux/amd64 registry.example.com/myapp:v1.2.3
  hermes approve --cache registry.example.com/myapp:v1.2.3
  hermes approve --cache cache.internal.example.com registry.example.com/myapp:v1.2.3`,
	Args: cobra.ExactArgs(1),
	RunE: runApprove,
}

func init() {
	approveCmd.Flags().StringVar(&approvePlatform, "platform", "", "platform to approve (os/arch, e.g. linux/amd64)")
	approveCmd.Flags().StringVar(&approveCache, "cache", "", "push image to this registry upon approval (uses cache_url from config if empty)")
	approveCmd.Flags().Lookup("cache").NoOptDefVal = "__use_config__"
	rootCmd.AddCommand(approveCmd)
}

func runApprove(cmd *cobra.Command, args []string) error {
	imageRef := args[0]

	reg, repo, tag, err := oci.ParseRef(imageRef)
	if err != nil {
		return err
	}
	ref := db.ImageRef{Registry: reg, Repository: repo, Tag: tag}

	// Resolve cache URL.
	cacheURL := ""
	if cmd.Flags().Changed("cache") {
		cacheURL = approveCache
		if cacheURL == "__use_config__" || cacheURL == "" {
			cacheURL = cfg.CacheURL
		}
	}

	// Queue the image (fetches manifests if new).
	fmt.Fprintf(os.Stderr, "Queuing %s...\n", imageRef)
	images, err := database.Queue(ref, oci.NewDefaultClient())
	if err != nil {
		return fmt.Errorf("queue image: %w", err)
	}

	// Select the target platform (already-approved platforms are shown but not selectable).
	img, err := selectPlatform(images, approvePlatform, db.StateApproved)
	if err != nil {
		return err
	}

	// Determine whether a (re-)scan is needed.
	needsScan := img.State == db.StateQueued || img.State == db.StateRejected ||
		len(img.ScanReport) == 0 || string(img.ScanReport) == "null"

	if needsScan {
		scanRef := imageRef
		if img.Digest != "" {
			scanRef = fmt.Sprintf("%s/%s@%s", reg, repo, img.Digest)
		}

		fmt.Fprintf(os.Stderr, "Scanning %s (%s/%s) with trivy...\n", scanRef, img.OS, img.Arch)
		result, err := trivy.Scan(scanRef, cfg.Trivy)
		if err != nil {
			_ = database.SetError(img.ID)
			logEvent("scan_error", img, map[string]interface{}{"error": err.Error()})
			return fmt.Errorf("trivy scan: %w", err)
		}

		img, err = database.SaveScan(img.ID, json.RawMessage(result.Raw))
		if err != nil {
			return fmt.Errorf("save scan: %w", err)
		}
		logEvent("scan", img, map[string]interface{}{"digest": img.Digest})
	}

	// Display the report.
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 72))
	if err := printJSON(img.ScanReport); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 72))
	fmt.Fprintf(os.Stderr, "Image: %s/%s:%s  platform: %s/%s  (digest: %s)\n",
		reg, repo, tag, img.OS, img.Arch, img.Digest)
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
			// Build digest-pinned source ref for docker push.
			pushSrc := imageRef
			if img.Digest != "" {
				pushSrc = fmt.Sprintf("%s/%s@%s", reg, repo, img.Digest)
			}
			fmt.Fprintf(os.Stderr, "Pushing %s to %s...\n", pushSrc, cacheURL)
			if err := pushToCache(pushSrc, ref, cacheURL); err != nil {
				_ = database.SetError(img.ID)
				logEvent("cache_push_error", img, map[string]interface{}{
					"cache_url": cacheURL,
					"error":     err.Error(),
				})
				return fmt.Errorf("cache push failed: %w", err)
			}
		}

		if err := database.Approve(img.ID, cacheURL); err != nil {
			return fmt.Errorf("approve: %w", err)
		}
		logEvent("approve", img, map[string]interface{}{"cache_url": cacheURL})
		fmt.Printf("approved  %s/%s:%s  (%s/%s)\n", reg, repo, tag, img.OS, img.Arch)

	case "REJECT":
		if err := database.Reject(img.ID); err != nil {
			return fmt.Errorf("reject: %w", err)
		}
		logEvent("reject", img, nil)
		fmt.Printf("rejected  %s/%s:%s  (%s/%s)\n", reg, repo, tag, img.OS, img.Arch)
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
	dest := fmt.Sprintf("%s/%s:%s", cacheURL, ref.Repository, ref.Tag)

	if out, err := exec.Command("docker", "pull", imageRef).CombinedOutput(); err != nil {
		return fmt.Errorf("docker pull: %s: %w", string(out), err)
	}
	if out, err := exec.Command("docker", "tag", imageRef, dest).CombinedOutput(); err != nil {
		return fmt.Errorf("docker tag: %s: %w", string(out), err)
	}
	if out, err := exec.Command("docker", "push", dest).CombinedOutput(); err != nil {
		return fmt.Errorf("docker push: %s: %w", string(out), err)
	}
	_ = exec.Command("docker", "rmi", dest).Run()
	return nil
}
