package trivy

import (
	"errors"
	"fmt"
	"os/exec"
)

// ScanResult holds the raw JSON output of a Trivy scan.
type ScanResult struct {
	Raw []byte
}

// Scan runs `trivy image --format json --quiet` against imageRef and returns
// the raw JSON report. Trivy must be installed and on the PATH.
func Scan(imageRef string) (*ScanResult, error) {
	cmd := exec.Command("trivy", "image",
		"--format", "json",
		"--quiet",
		imageRef,
	)

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("trivy exited %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("run trivy: %w", err)
	}

	return &ScanResult{Raw: out}, nil
}
