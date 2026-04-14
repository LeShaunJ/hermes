package trivy

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leshaunj/hermes/internal/config"
)

// ── exec capture harness ──────────────────────────────────────────────────────

// capturedCall records one (name, args) pair seen by execCommand.
type capturedCall struct {
	name string
	args []string
}

// recorder collects every execCommand invocation made through its function.
// Each Recorder.fn returned closure prepends a real subprocess that the test
// chooses; the production code's *exec.Cmd is genuine so cmd.Stdin / cmd.Output
// behave normally, which is what lets the harness verify stdin wiring.
type recorder struct {
	calls []capturedCall
}

// useReal returns an execCommand replacement that captures the call and then
// constructs an exec.Cmd that runs realName with realArgs.  The production
// code's Stdin assignment is preserved, so a "cat" backend echoes the report
// bytes through to stdout — which proves the production code actually wired
// Stdin to the subprocess.
func (r *recorder) useReal(realName string, realArgs ...string) func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		r.calls = append(r.calls, capturedCall{
			name: name,
			args: append([]string(nil), args...),
		})
		return exec.Command(realName, realArgs...)
	}
}

// last returns the last captured call, or fails the test if none exist.
func (r *recorder) last(t *testing.T) capturedCall {
	t.Helper()
	if len(r.calls) == 0 {
		t.Fatalf("no execCommand calls captured")
	}
	return r.calls[len(r.calls)-1]
}

// withExec swaps execCommand for the duration of a test and restores it on
// cleanup.  Tests should always go through this helper rather than
// hand-rolling save/restore so a panic in the body cannot leak the override.
func withExec(t *testing.T, fn func(string, ...string) *exec.Cmd) {
	t.Helper()
	orig := execCommand
	execCommand = fn
	t.Cleanup(func() { execCommand = orig })
}

// containsSubsequence reports whether want appears as a contiguous slice
// inside got — used to assert that "--format" is followed by the expected
// value rather than just present somewhere in args.
func containsSubsequence(got, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for i := 0; i+len(want) <= len(got); i++ {
		if slices.Equal(got[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

// ── extractJSON ───────────────────────────────────────────────────────────────

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    string
		wantErr bool
	}{
		{
			name:  "plain JSON object",
			input: []byte(`{"foo":"bar"}`),
			want:  `{"foo":"bar"}`,
		},
		{
			name:  "JSON with leading log lines",
			input: []byte("2024/01/01 INFO: downloading db\n{\"foo\":\"bar\"}"),
			want:  `{"foo":"bar"}`,
		},
		{
			name:  "JSON with trailing log lines",
			input: []byte("{\"foo\":\"bar\"}\nsome trailing output\n"),
			want:  `{"foo":"bar"}`,
		},
		{
			name:  "JSON with leading and trailing noise",
			input: []byte("noise before\n{\"results\":[]}\ntrailing noise"),
			want:  `{"results":[]}`,
		},
		{
			name:    "no JSON object",
			input:   []byte("no json here at all"),
			wantErr: true,
		},
		{
			name:    "invalid JSON after opening brace",
			input:   []byte("{invalid json}"),
			wantErr: true,
		},
		{
			name:  "nested JSON object",
			input: []byte(`{"a":{"b":1},"c":[1,2,3]}`),
			want:  `{"a":{"b":1},"c":[1,2,3]}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractJSON(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ── ValidateFormat ────────────────────────────────────────────────────────────

func TestValidateFormat(t *testing.T) {
	for _, f := range SupportedFormats {
		if err := ValidateFormat(f); err != nil {
			t.Errorf("ValidateFormat(%q) unexpected error: %v", f, err)
		}
	}
	for _, f := range []string{"xml", "html", "pdf", ""} {
		if err := ValidateFormat(f); err == nil {
			t.Errorf("ValidateFormat(%q) expected error, got nil", f)
		}
	}
}

// ── Scan ──────────────────────────────────────────────────────────────────────

func TestScan_constructsDockerInvocation(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("echo", `{"SchemaVersion":2,"Results":[]}`))

	cfg := config.TrivyConfig{Image: "aquasec/trivy:0.50.0"}
	result, err := Scan("registry.example.com/myapp:v1.2.3", cfg)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if string(result.Raw) != `{"SchemaVersion":2,"Results":[]}` {
		t.Errorf("Raw = %q, want the JSON our fake printed", result.Raw)
	}

	call := rec.last(t)
	if call.name != "docker" {
		t.Errorf("name = %q, want docker", call.name)
	}
	wantSequence := [][]string{
		{"run", "--rm"},
		{"-v", "/var/run/docker.sock:/var/run/docker.sock"},
		{"aquasec/trivy:0.50.0"},
		{"image"},
		{"--disable-telemetry"},
		{"--format", "json"},
		{"--quiet"},
		{"registry.example.com/myapp:v1.2.3"},
	}
	for _, want := range wantSequence {
		if !containsSubsequence(call.args, want) {
			t.Errorf("args missing subsequence %v\nargs: %v", want, call.args)
		}
	}
	// imageRef must be the last positional, after --quiet, so trivy treats it
	// as the scan target rather than a flag value.
	if call.args[len(call.args)-1] != "registry.example.com/myapp:v1.2.3" {
		t.Errorf("last arg = %q, want image ref", call.args[len(call.args)-1])
	}
}

func TestScan_defaultImage(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("echo", `{"SchemaVersion":2}`))

	if _, err := Scan("myimage:latest", config.TrivyConfig{}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	call := rec.last(t)
	if !slices.Contains(call.args, "aquasec/trivy:latest") {
		t.Errorf("args missing default image\nargs: %v", call.args)
	}
}

func TestScan_extraArgsAppearBeforeImageRef(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("echo", `{"SchemaVersion":2}`))

	cfg := config.TrivyConfig{Args: []string{"--ignore-unfixed", "--severity", "HIGH,CRITICAL"}}
	if _, err := Scan("myimage:latest", cfg); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	call := rec.last(t)

	for _, want := range []string{"--ignore-unfixed", "--severity", "HIGH,CRITICAL"} {
		if !slices.Contains(call.args, want) {
			t.Errorf("args missing %q\nargs: %v", want, call.args)
		}
	}
	// The extra args must precede the image ref so trivy parses them as
	// flags rather than positional arguments.
	imageIdx := slices.Index(call.args, "myimage:latest")
	severityIdx := slices.Index(call.args, "--severity")
	if imageIdx < 0 || severityIdx < 0 || severityIdx > imageIdx {
		t.Errorf("expected --severity before image ref\nargs: %v", call.args)
	}
}

func TestScan_commandFails(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("false"))

	_, err := Scan("myimage:latest", config.TrivyConfig{})
	if err == nil {
		t.Error("expected error from failing command, got nil")
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 call, got %d", len(rec.calls))
	}
}

func TestScan_noJSON(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("echo", "no json output here"))

	_, err := Scan("myimage:latest", config.TrivyConfig{})
	if err == nil {
		t.Error("expected error when no JSON, got nil")
	}
}

// ── Convert ───────────────────────────────────────────────────────────────────

// TestConvert_pipesReportThroughStdin is the regression test for the
// "trivy convert -" bug.  By mocking execCommand with `cat`, the test
// confirms that the production code actually wires cmd.Stdin to a reader
// over the report bytes — if Stdin were nil (the old `-` form), `cat` would
// produce empty output and the assertion would fail.
func TestConvert_pipesReportThroughStdin(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("cat"))

	report := []byte(`{"SchemaVersion":2,"Results":[{"Target":"alpine"}]}`)
	out, err := Convert(report, "table", config.TrivyConfig{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if string(out) != string(report) {
		t.Errorf("Convert output = %q, want %q\n(if these differ, Stdin was not wired through)",
			out, report)
	}
}

// TestConvert_constructsShellWrapperInvocation pins the docker invocation
// to the in-container staging design so a future refactor cannot silently
// regress to passing "-" as an input path.
func TestConvert_constructsShellWrapperInvocation(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("cat"))

	cfg := config.TrivyConfig{Image: "aquasec/trivy:0.50.0"}
	if _, err := Convert([]byte(`{}`), "sarif", cfg); err != nil {
		t.Fatalf("Convert: %v", err)
	}

	call := rec.last(t)
	if call.name != "docker" {
		t.Errorf("name = %q, want docker", call.name)
	}
	// `-i` keeps stdin open so the wrapper's `cat` can read the report.
	if !slices.Contains(call.args, "-i") {
		t.Errorf("args missing -i (stdin must be open)\nargs: %v", call.args)
	}
	// Override the image entrypoint so we can run sh.
	if !containsSubsequence(call.args, []string{"--entrypoint", "sh"}) {
		t.Errorf("args missing --entrypoint sh\nargs: %v", call.args)
	}
	// The shell script must stage stdin into a file *before* invoking trivy.
	scriptIdx := slices.IndexFunc(call.args, func(s string) bool {
		return strings.Contains(s, "cat >") && strings.Contains(s, "trivy convert")
	})
	if scriptIdx < 0 {
		t.Errorf("args missing cat-then-trivy shell wrapper\nargs: %v", call.args)
	}
	// trivy convert MUST NOT receive "-" as an input file — that's the
	// regression we are guarding against.
	if slices.Contains(call.args, "-") {
		t.Errorf("args contain literal '-' input path; trivy does not read stdin\nargs: %v", call.args)
	}
	// Format flag must be present and follow the script positional.
	if !containsSubsequence(call.args, []string{"--format", "sarif"}) {
		t.Errorf("args missing --format sarif sequence\nargs: %v", call.args)
	}
	// Configured trivy image is honoured.
	if !slices.Contains(call.args, "aquasec/trivy:0.50.0") {
		t.Errorf("args missing configured image\nargs: %v", call.args)
	}
}

func TestConvert_defaultImage(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("cat"))

	if _, err := Convert([]byte(`{}`), "sarif", config.TrivyConfig{}); err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if !slices.Contains(rec.last(t).args, "aquasec/trivy:latest") {
		t.Errorf("default image not honoured\nargs: %v", rec.last(t).args)
	}
}

// TestConvert_extraArgsForwardedAfterFormat verifies that ConvertArgs land
// after `--format <format>` and become positional arguments to the in-container
// shell wrapper, which forwards them to trivy via "$@".
func TestConvert_extraArgsForwardedAfterFormat(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("cat"))

	cfg := config.TrivyConfig{ConvertArgs: []string{"--template", "@/contrib/html.tpl"}}
	if _, err := Convert([]byte(`{}`), "template", cfg); err != nil {
		t.Fatalf("Convert: %v", err)
	}
	call := rec.last(t)
	if !containsSubsequence(call.args, []string{"--format", "template", "--template", "@/contrib/html.tpl"}) {
		t.Errorf("ConvertArgs not appended in order\nargs: %v", call.args)
	}
}

func TestConvert_commandFails(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("false"))

	_, err := Convert([]byte(`{}`), "table", config.TrivyConfig{})
	if err == nil {
		t.Error("expected error from failing command, got nil")
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 call, got %d", len(rec.calls))
	}
}

// ── ConvertToFile ─────────────────────────────────────────────────────────────

func TestConvertToFile_writesStdoutOnDash(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("cat"))

	report := []byte(`{"converted":"contents"}`)

	// Capture stdout to verify the bytes were written there.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	doneCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		doneCh <- buf[:n]
	}()

	if err := ConvertToFile(report, "table", "-", config.TrivyConfig{}); err != nil {
		t.Fatalf("ConvertToFile(-): %v", err)
	}
	_ = w.Close()
	got := <-doneCh

	if string(got) != string(report) {
		t.Errorf("stdout = %q, want %q", got, report)
	}
}

func TestConvertToFile_writesFileWhenPathGiven(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("cat"))

	report := []byte(`{"sarif":"data"}`)
	outPath := filepath.Join(t.TempDir(), "report.sarif")

	if err := ConvertToFile(report, "sarif", outPath, config.TrivyConfig{}); err != nil {
		t.Fatalf("ConvertToFile(file): %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(got) != string(report) {
		t.Errorf("file contents = %q, want %q", got, report)
	}
}

func TestConvertToFile_emptyPathWritesStdout(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("cat"))

	// Empty outPath should behave like "-". We don't need to capture stdout
	// here; the goal is to assert no error and that exec was actually called.
	if err := ConvertToFile([]byte(`{}`), "table", "", config.TrivyConfig{}); err != nil {
		t.Fatalf("ConvertToFile(empty): %v", err)
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(rec.calls))
	}
}

func TestConvertToFile_propagatesConvertError(t *testing.T) {
	rec := &recorder{}
	withExec(t, rec.useReal("false"))

	err := ConvertToFile([]byte(`{}`), "table", filepath.Join(t.TempDir(), "out"), config.TrivyConfig{})
	if err == nil {
		t.Error("expected error from failing convert, got nil")
	}
}
