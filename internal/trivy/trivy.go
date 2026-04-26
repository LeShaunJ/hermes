// Package trivy runs trivy via Docker containers using the host Docker socket.
// hermes mounts /var/run/docker.sock so it can spin up ephemeral trivy
// containers without trivy being installed inside the hermes image itself.
package trivy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/leshaunj/hermes/internal/config"
)

// ScanResult holds the raw JSON output of a trivy image scan.
type ScanResult struct {
	Raw []byte
}

// execCommand is the constructor for external commands; overridden in tests.
var execCommand = exec.Command

// SetExecCommand replaces the command constructor used by Scan and Convert.
// Intended for use in external package tests only.
func SetExecCommand(fn func(string, ...string) *exec.Cmd) { execCommand = fn }

// ExecCommandVar returns the current execCommand for save-and-restore in tests.
func ExecCommandVar() func(string, ...string) *exec.Cmd { return execCommand }

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
		"--disable-telemetry",
		"--format", "json",
		"--quiet",
	}
	args = append(args, cfg.Args...)
	args = append(args, imageRef)

	cmd := execCommand("docker", args...)

	stdout, _ := cmd.StdoutPipe()
	// Capture stderr explicitly: cmd.Wait does NOT populate
	// ExitError.Stderr unless the command was constructed with cmd.Output,
	// so the previous formatter consistently reported an empty string and
	// hid the real failure (e.g. "permission denied while trying to
	// connect to the Docker daemon socket" or "Error: image not found").
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("run cmd: %w", err)
	}

	out, err := io.ReadAll(stdout)
	if err != nil {
		return nil, fmt.Errorf("read stdout: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		errBody := strings.TrimSpace(stderr.String())
		if errBody == "" {
			errBody = "(no stderr; check that the docker daemon is reachable from this container)"
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("trivy exited %d: %s", exitErr.ExitCode(), errBody)
		}
		return nil, fmt.Errorf("run trivy: %w: %s", err, errBody)
	}

	// Strip any non-JSON lines that trivy may emit before the report (e.g.
	// database download progress) even when --quiet is set.
	raw, err := extractJSON(out)
	if err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}
	return &ScanResult{Raw: raw}, nil
}

// extractJSON returns the first complete JSON object found in b.
// It skips any leading non-JSON content (log lines, progress messages, etc.)
// and ignores any trailing content after the first complete JSON value.
func extractJSON(b []byte) ([]byte, error) {
	start := bytes.IndexByte(b, '{')
	if start < 0 {
		return nil, fmt.Errorf("no JSON object found in output (size: %d, first 200 bytes: %.200s)", len(b), b)
	}
	dec := json.NewDecoder(bytes.NewReader(b[start:]))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return raw, nil
}

// stagedReportPath is the in-container path where Convert writes the report
// JSON before invoking trivy convert against it.  Lives under /tmp because
// the trivy image is alpine-based and /tmp is always writable there.
const stagedReportPath = "/tmp/hermes-report.json"

// convertScript is the shell wrapper executed inside the trivy container.
// It reads the report JSON from stdin into a file, then runs `trivy convert`
// with all extra arguments forwarded via "$@".  Splitting staging from the
// trivy invocation is required because `trivy convert` expects a file path
// argument and does NOT read from stdin (passing "-" yields a literal
// "open -: no such file or directory" error from trivy).
//
// Wrapping the call in sh inside the trivy image (via --entrypoint sh)
// avoids the alternative of bind-mounting a host scratch directory, which
// would not work when hermes itself runs in a container without sharing
// that directory with the host docker daemon.
const convertScript = `cat > ` + stagedReportPath +
	` && trivy convert "$@" ` + stagedReportPath

// Convert converts a trivy JSON report to another format using
// `docker run --rm -i --entrypoint sh aquasec/trivy -c <wrapper> ...`.
//
// The wrapper script stages the report from stdin into a file inside the
// trivy container and then invokes `trivy convert` against it.  Extra args
// from cfg.Trivy.ConvertArgs are appended after `--format <format>` and are
// forwarded into the script via positional parameters, so no shell quoting
// is performed in Go.
func Convert(report []byte, format string, cfg config.TrivyConfig) ([]byte, error) {
	trivyImage := cfg.Image
	if trivyImage == "" {
		trivyImage = "aquasec/trivy:latest"
	}

	args := []string{
		"run", "--rm", "-i",
		"--entrypoint", "sh",
		trivyImage,
		"-c", convertScript,
		"sh", // $0 placeholder for the script
		"--format", format,
	}
	args = append(args, cfg.ConvertArgs...)

	cmd := execCommand("docker", args...)
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
