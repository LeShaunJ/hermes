// Package trivy runs trivy via Docker containers using the host Docker socket.
// hermes mounts /var/run/docker.sock so it can spin up ephemeral trivy
// containers without trivy being installed inside the hermes image itself.
package trivy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/leshaunj/hermes/internal/config"
)

// ScanResult holds the raw JSON output of a trivy image scan.
type ScanResult struct {
	Raw []byte
}

// Scan runs `docker run --rm aquasec/trivy image --format json --quiet <imageRef>`
// and returns the raw JSON report.
//
// Extra args from cfg.Trivy.Args are appended before the image reference.
func Scan(imageRef string, cfg config.TrivyConfig) (*ScanResult, error) {
	trivyImage := cfg.Image
	if trivyImage == "" {
		trivyImage = "aquasec/trivy:latest"
	}

	args := []string{
		"run", "--rm",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		trivyImage,
		"image",
		"--format", "json",
		"--quiet",
	}
	args = append(args, cfg.Args...)
	args = append(args, imageRef)

	cmd := exec.Command("docker", args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("trivy exited %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("run trivy: %w", err)
	}

	// Strip any non-JSON lines that trivy may emit before the report (e.g.
	// database download progress) even when --quiet is set.
	raw, err := extractJSON(out)
	if err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}
	return &ScanResult{Raw: raw}, nil
}

// extractJSON returns the first complete JSON object found in b, compacted.
// It skips any leading non-JSON content (log lines, progress messages, etc.).
func extractJSON(b []byte) ([]byte, error) {
	start := bytes.IndexByte(b, '{')
	if start < 0 {
		return nil, fmt.Errorf("no JSON object found in output (first 200 bytes: %.200s)", b)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b[start:]); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w (first 200 bytes: %.200s)", err, b[start:])
	}
	return buf.Bytes(), nil
}

// Convert converts a trivy JSON report to another format using
// `docker run --rm -i aquasec/trivy convert --format <format>`.
//
// It pipes the report JSON to trivy via stdin (trivy reads "-").
// Extra args from cfg.Trivy.ConvertArgs are appended after --format <format>.
func Convert(report []byte, format string, cfg config.TrivyConfig) ([]byte, error) {
	trivyImage := cfg.Image
	if trivyImage == "" {
		trivyImage = "aquasec/trivy:latest"
	}

	args := []string{
		"run", "--rm", "-i",
		trivyImage,
		"convert",
		"--format", format,
	}
	args = append(args, cfg.ConvertArgs...)
	args = append(args, "-") // read from stdin

	cmd := exec.Command("docker", args...)
	cmd.Stdin = bytes.NewReader(report)

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("trivy convert exited %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("run trivy convert: %w", err)
	}

	return out, nil
}

// ConvertToFile converts a report and writes it to outPath.
// If outPath is "-", the result is written to os.Stdout.
func ConvertToFile(report []byte, format, outPath string, cfg config.TrivyConfig) error {
	out, err := Convert(report, format, cfg)
	if err != nil {
		return err
	}

	if outPath == "" || outPath == "-" {
		_, err = os.Stdout.Write(out)
		return err
	}

	return os.WriteFile(outPath, out, 0o644)
}

// SupportedFormats lists the formats trivy convert accepts.
var SupportedFormats = []string{
	"table", "json", "template", "sarif", "cyclonedx", "spdx", "spdx-json", "github", "cosign-vuln",
}

// ValidateFormat returns an error if format is not in SupportedFormats.
func ValidateFormat(format string) error {
	for _, f := range SupportedFormats {
		if strings.EqualFold(f, format) {
			return nil
		}
	}
	return fmt.Errorf("unsupported trivy format %q (supported: %s)",
		format, strings.Join(SupportedFormats, ", "))
}
