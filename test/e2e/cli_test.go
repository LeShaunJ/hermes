//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/leshaunj/hermes/internal/db"
)

// buildBinary compiles `hermes` once per process and returns the path.
// The `go test` working directory is test/e2e, so we jump to the module
// root before building.  Cleanup is a no-op — the binary lives in the
// OS temp dir for the lifetime of the test process.
var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func hermesBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		tmp, err := os.MkdirTemp("", "hermes-bin-")
		if err != nil {
			binErr = fmt.Errorf("mkdtemp: %w", err)
			return
		}
		binPath = filepath.Join(tmp, "hermes")
		build := exec.Command("go", "build", "-o", binPath, "github.com/leshaunj/hermes")
		build.Stdout, build.Stderr = os.Stdout, os.Stderr
		if err := build.Run(); err != nil {
			binErr = fmt.Errorf("go build hermes: %w", err)
			return
		}
	})
	if binErr != nil {
		t.Fatalf("build hermes: %v", binErr)
	}
	return binPath
}

// writeConfig materialises a hermes.yaml with the given DB parameters
// and returns its path.  Keeping the YAML file on disk (rather than
// passing everything via HERMES_* env) exercises the viper load path
// that CLI tests otherwise miss.
func writeConfig(t *testing.T, port int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hermes.yaml")
	body := fmt.Sprintf(`server:
  addr: ":0"
db:
  host:     127.0.0.1
  port:     %d
  user:     hermes
  password: ""
  name:     hermes
  sslmode:  disable
log:
  format: json
  level:  warn
`, port)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// runHermes invokes the compiled binary with the given args and stdin,
// returning (stdout, stderr, exitCode).  It never fails the test
// directly; callers decide whether a non-zero exit is expected.
func runHermes(t *testing.T, cfgPath, stdinBody string, args ...string) (string, string, int) {
	t.Helper()
	cmdArgs := append([]string{"--config", cfgPath}, args...)
	cmd := exec.Command(hermesBinary(t), cmdArgs...)
	if stdinBody != "" {
		cmd.Stdin = strings.NewReader(stdinBody)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exitCode := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run hermes: %v", err)
	}
	return stdout.String(), stderr.String(), exitCode
}

// TestCLI_Help verifies the binary builds and the root help command
// runs — the smallest smoke test, catching cobra-wiring breakage.
func TestCLI_Help(t *testing.T) {
	bin := hermesBinary(t)
	out, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("hermes --help: %v: %s", err, string(out))
	}
	for _, want := range []string{"approve", "reject", "rescind", "scan", "serve"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("--help output missing %q subcommand:\n%s", want, out)
		}
	}
}

// TestCLI_ListJSON runs `hermes list --json` against an empty real DB
// and asserts the output is a valid empty JSON array.  This exercises
// the viper config-load path, the DB open+migrate path, and the JSON
// encoder — all of which the in-process tests stub out.
func TestCLI_ListJSON_Empty(t *testing.T) {
	s := newStack(t)
	cfg := writeConfig(t, s.pg.port)

	out, stderr, code := runHermes(t, cfg, "", "list", "--json")
	if code != 0 {
		t.Fatalf("exit=%d, stderr=%s", code, stderr)
	}
	var arr []any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &arr); err != nil {
		t.Fatalf("parse JSON %q: %v", out, err)
	}
	if len(arr) != 0 {
		t.Errorf("list --json on empty DB returned %d rows, want 0", len(arr))
	}
}

// TestCLI_RescindYesFlow pipes "YES\n" into `hermes rescind` and
// verifies exit 0 plus state transition.  Rescind has the same
// prompt+confirm+mutate mechanics as approve/reject but skips the
// trivy-backed scan-report rendering, so it exercises the full argv →
// cobra → prompt → DB chain without depending on Docker.  Unit tests
// stub os.Stdin at the function level — only a blackbox subprocess
// catches a cobra flag wiring or bufio.Scanner regression end-to-end.
func TestCLI_RescindYesFlow(t *testing.T) {
	s := newStack(t)
	cfg := writeConfig(t, s.pg.port)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	images := approveReturning(t, s, "myorg/app", "v1")
	imgID := images[0].ID

	ref := s.upstreamName + "/myorg/app:v1"
	_, stderr, code := runHermes(t, cfg, "YES\n", "rescind", ref)
	if code != 0 {
		t.Fatalf("hermes rescind exit=%d, stderr=%s", code, stderr)
	}

	if got := currentState(t, s.db, imgID); got != db.StateRescinded {
		t.Errorf("state after YES = %q, want %q", got, db.StateRescinded)
	}
}

// TestCLI_RejectCancel verifies that anything-but-YES cancels the
// reject flow without mutating state.  Regressions in the confirm()
// helper (e.g. accepting "y" as "yes") would flip state unexpectedly.
func TestCLI_RejectCancel(t *testing.T) {
	s := newStack(t)
	cfg := writeConfig(t, s.pg.port)

	img := mustRandomImage(t)
	mustPush(t, s, img, s.upstreamRef("myorg/app", "v1"))
	images := approveReturning(t, s, "myorg/app", "v1")
	imgID := images[0].ID

	ref := s.upstreamName + "/myorg/app:v1"
	out, stderr, code := runHermes(t, cfg, "n\n", "reject", ref)
	if code != 0 {
		t.Fatalf("exit=%d, stderr=%s", code, stderr)
	}
	if !strings.Contains(out, "Cancelled") && !strings.Contains(stderr, "Cancelled") {
		t.Errorf("reject without YES did not print Cancelled; stdout=%q stderr=%q", out, stderr)
	}
	if got := currentState(t, s.db, imgID); got != db.StateApproved {
		t.Errorf("state after cancel = %q, want %q (unchanged)", got, db.StateApproved)
	}
}

// TestCLI_ConfigEnvOverride confirms HERMES_DB_PORT in the environment
// beats the YAML's db.port.  Viper's env-override wiring is CLI-only
// and isn't touched by any in-process test.
func TestCLI_ConfigEnvOverride(t *testing.T) {
	s := newStack(t)
	cfg := writeConfig(t, 1 /* deliberately wrong port in YAML */)

	bin := hermesBinary(t)
	cmd := exec.Command(bin, "--config", cfg, "list", "--json")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HERMES_DB_PORT=%d", s.pg.port),
		"HERMES_DB_PASSWORD=",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("hermes list with HERMES_DB_PORT override: %v; stderr=%s", err, stderr.String())
	}
	if s := strings.TrimSpace(stdout.String()); s != "[]" {
		t.Errorf("stdout = %q, want %q", s, "[]")
	}
}
