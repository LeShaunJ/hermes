package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/trivy"
)

// ── selectPlatform ────────────────────────────────────────────────────────────

func makeImage(id int64, os, arch string, state db.State) *db.Image {
	return &db.Image{
		ID:        id,
		OS:        os,
		Arch:      arch,
		State:     state,
		Digest:    "sha256:abc" + arch,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestSelectPlatform_singleImage(t *testing.T) {
	images := []*db.Image{makeImage(1, "linux", "amd64", db.StateQueued)}
	img, err := selectPlatform(images, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.Arch != "amd64" {
		t.Errorf("arch = %q, want amd64", img.Arch)
	}
}

func TestSelectPlatform_byPlatform(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateQueued),
		makeImage(2, "linux", "arm64", db.StateQueued),
	}
	img, err := selectPlatform(images, "linux/arm64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.ID != 2 {
		t.Errorf("id = %d, want 2", img.ID)
	}
}

func TestSelectPlatform_platformNotFound(t *testing.T) {
	images := []*db.Image{makeImage(1, "linux", "amd64", db.StateQueued)}
	_, err := selectPlatform(images, "linux/arm64")
	if err == nil {
		t.Error("expected error for missing platform, got nil")
	}
}

func TestSelectPlatform_excludedState(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateApproved),
		makeImage(2, "linux", "arm64", db.StateQueued),
	}
	// amd64 is already approved — must not be selectable; arm64 auto-selected.
	img, err := selectPlatform(images, "", db.StateApproved)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.ID != 2 {
		t.Errorf("id = %d, want 2 (arm64)", img.ID)
	}
}

func TestSelectPlatform_allExcluded(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateApproved),
	}
	_, err := selectPlatform(images, "", db.StateApproved)
	if err == nil {
		t.Error("expected error when all platforms excluded, got nil")
	}
}

func TestSelectPlatform_excludedByFlag(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateApproved),
	}
	_, err := selectPlatform(images, "linux/amd64", db.StateApproved)
	if err == nil {
		t.Error("expected error selecting an excluded platform, got nil")
	}
}

func TestSelectPlatform_empty(t *testing.T) {
	_, err := selectPlatform(nil, "")
	if err == nil {
		t.Error("expected error for empty images, got nil")
	}
}

// ── printJSON ────────────────────────────────────────────────────────────────

func TestPrintJSON(t *testing.T) {
	// Redirect stdout to a buffer by using printJSON with a known JSON payload.
	// We verify that valid JSON is handled without error and invalid JSON is not.

	raw := json.RawMessage(`{"foo":"bar","n":42}`)
	if err := printJSON(raw); err != nil {
		t.Errorf("printJSON valid JSON: unexpected error: %v", err)
	}

	// string form
	if err := printJSON(`{"x":1}`); err != nil {
		t.Errorf("printJSON string form: unexpected error: %v", err)
	}

	// bytes form
	if err := printJSON([]byte(`{"y":2}`)); err != nil {
		t.Errorf("printJSON bytes form: unexpected error: %v", err)
	}
}

// ── platformList ─────────────────────────────────────────────────────────────

func TestPlatformList(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateQueued),
		makeImage(2, "linux", "arm64", db.StateQueued),
		makeImage(3, "windows", "amd64", db.StateQueued),
	}
	got := platformList(images)
	want := "linux/amd64, linux/arm64, windows/amd64"
	if got != want {
		t.Errorf("platformList = %q, want %q", got, want)
	}
}

// ── shortDigest ──────────────────────────────────────────────────────────────

func TestShortDigest(t *testing.T) {
	long := "sha256:abcdef1234567890abcdef"
	got := shortDigest(long)
	if len(got) > 19 {
		t.Errorf("shortDigest too long: %d chars", len(got))
	}

	short := "sha256:abc"
	if shortDigest(short) != short {
		t.Errorf("shortDigest(%q) changed short string", short)
	}
}

// ── selectPlatform — prompt path ─────────────────────────────────────────────

func TestSelectPlatform_multiPrompt_firstOption(t *testing.T) {
	// Two selectable platforms → prompt; answer "1" selects first.
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateQueued),
		makeImage(2, "linux", "arm64", db.StateQueued),
	}
	fakeStdin(t, "1")
	img, err := selectPlatform(images, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.ID != 1 {
		t.Errorf("id = %d, want 1 (first option)", img.ID)
	}
}

func TestSelectPlatform_multiPrompt_invalidAnswer(t *testing.T) {
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateQueued),
		makeImage(2, "linux", "arm64", db.StateQueued),
	}
	fakeStdin(t, "99") // out of range
	_, err := selectPlatform(images, "")
	if err == nil {
		t.Error("expected error for out-of-range selection, got nil")
	}
}

func TestSelectPlatform_multiPrompt_defaultFirst(t *testing.T) {
	// Empty answer → default "1".
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateQueued),
		makeImage(2, "linux", "arm64", db.StateQueued),
	}
	fakeStdin(t, "") // empty → default "1"
	img, err := selectPlatform(images, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.ID != 1 {
		t.Errorf("id = %d, want 1 (default)", img.ID)
	}
}

func TestSelectPlatform_multiPrompt_withExcluded(t *testing.T) {
	// One excluded (approved), two selectable.
	images := []*db.Image{
		makeImage(1, "linux", "amd64", db.StateApproved),
		makeImage(2, "linux", "arm64", db.StateQueued),
		makeImage(3, "windows", "amd64", db.StateQueued),
	}
	fakeStdin(t, "2") // select second selectable (windows/amd64)
	img, err := selectPlatform(images, "", db.StateApproved)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img.ID != 3 {
		t.Errorf("id = %d, want 3 (windows/amd64)", img.ID)
	}
}

// ── prompt ────────────────────────────────────────────────────────────────────

func TestPrompt_emptyEOF(t *testing.T) {
	// Close stdin immediately → scanner.Scan() returns false, no error → "".
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	_ = w.Close() // EOF immediately
	t.Cleanup(func() { os.Stdin = orig })

	answer, err := prompt("test: ")
	if err != nil {
		t.Errorf("prompt on EOF: %v", err)
	}
	if answer != "" {
		t.Errorf("prompt on EOF = %q, want empty", answer)
	}
}

// ── mock datastore ────────────────────────────────────────────────────────────

type mockDB struct {
	images      []*db.Image
	listOut     []db.Image
	queueErr    error
	listErr     error
	getRefErr   error
	saveScanImg *db.Image
	saveScanErr error
	approveErr  error
	rejectErr   error
	rescindErr  error
}

func (m *mockDB) Queue(_ db.ImageRef, _ db.Fetcher) ([]*db.Image, error) {
	return m.images, m.queueErr
}
func (m *mockDB) SetError(_ int64) error { return nil }
func (m *mockDB) SaveScan(_ int64, _ json.RawMessage) (*db.Image, error) {
	return m.saveScanImg, m.saveScanErr
}
func (m *mockDB) LogEvent(_ *int64, _ db.EventSource, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockDB) List(_ db.ListFilter) ([]db.Image, error)    { return m.listOut, m.listErr }
func (m *mockDB) GetByRef(_ db.ImageRef) ([]*db.Image, error) { return m.images, m.getRefErr }
func (m *mockDB) Approve(_ int64, _ string) error             { return m.approveErr }
func (m *mockDB) Reject(_ int64) error                        { return m.rejectErr }
func (m *mockDB) Rescind(_ int64) error                       { return m.rescindErr }
func (m *mockDB) Close()                                      {}

// captureStdout temporarily replaces os.Stdout, runs f, and returns the output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = orig
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

// fakeStdin injects s as a single line of stdin and restores it after the test.
func fakeStdin(t *testing.T, s string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe for stdin: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	_, _ = fmt.Fprintln(w, s)
	_ = w.Close()
	t.Cleanup(func() { os.Stdin = orig })
}

// makeImg constructs a *db.Image for testing.
func makeImg(id int64, imgOS, arch string, state db.State) *db.Image {
	return &db.Image{
		ID:          id,
		RegistryURL: "registry.example.com",
		Repository:  "myrepo",
		TagName:     "v1.0",
		Digest:      "sha256:abc" + arch,
		OS:          imgOS,
		Arch:        arch,
		State:       state,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func makeListImg(id int64, imgOS, arch string, state db.State) db.Image {
	return *makeImg(id, imgOS, arch, state)
}

// fakeCmd returns a func(string, ...string) *exec.Cmd that runs name with fixedArgs.
func fakeCmd(name string, fixedArgs ...string) func(string, ...string) *exec.Cmd {
	return func(_ string, _ ...string) *exec.Cmd {
		return exec.Command(name, fixedArgs...)
	}
}

// withTrivyExec temporarily replaces the trivy execCommand.
func withTrivyExec(t *testing.T, fn func(string, ...string) *exec.Cmd) {
	t.Helper()
	orig := trivy.ExecCommandVar()
	trivy.SetExecCommand(fn)
	t.Cleanup(func() { trivy.SetExecCommand(orig) })
}

// withConfig temporarily sets the global cfg for a test.
func withConfig(t *testing.T) {
	t.Helper()
	cfg = &config.Config{}
	t.Cleanup(func() { cfg = nil })
}

// ── outputTable ───────────────────────────────────────────────────────────────

func TestOutputTable_empty(t *testing.T) {
	out := captureStdout(t, func() {
		if err := outputTable(nil); err != nil {
			t.Errorf("outputTable(nil): %v", err)
		}
	})
	if !strings.Contains(out, "REGISTRY") {
		t.Errorf("outputTable header not printed: %q", out)
	}
}

func TestOutputTable_rows(t *testing.T) {
	images := []db.Image{
		makeListImg(1, "linux", "amd64", db.StateQueued),
		makeListImg(2, "linux", "arm64", db.StateApproved),
	}
	out := captureStdout(t, func() {
		if err := outputTable(images); err != nil {
			t.Errorf("outputTable: %v", err)
		}
	})
	if !strings.Contains(out, "amd64") {
		t.Errorf("outputTable missing amd64: %q", out)
	}
	if !strings.Contains(out, "approved") {
		t.Errorf("outputTable missing approved: %q", out)
	}
}

func TestOutputTable_emptyFields(t *testing.T) {
	// Image with empty OS/Arch/Digest → those columns should show "-".
	img := db.Image{
		ID:          3,
		RegistryURL: "registry.example.com",
		Repository:  "myrepo",
		TagName:     "latest",
		State:       db.StateQueued,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	out := captureStdout(t, func() {
		if err := outputTable([]db.Image{img}); err != nil {
			t.Errorf("outputTable empty fields: %v", err)
		}
	})
	if strings.Count(out, "-") < 2 {
		t.Errorf("expected dash placeholders in empty fields: %q", out)
	}
}

func TestOutputTable_longDigest(t *testing.T) {
	img := makeListImg(1, "linux", "amd64", db.StateScanned)
	img.Digest = "sha256:abcdef1234567890abcdef1234567890"
	out := captureStdout(t, func() {
		if err := outputTable([]db.Image{img}); err != nil {
			t.Errorf("outputTable long digest: %v", err)
		}
	})
	if !strings.Contains(out, "sha256:") {
		t.Errorf("outputTable missing truncated digest: %q", out)
	}
}

// ── outputJSON ────────────────────────────────────────────────────────────────

func TestOutputJSON_empty(t *testing.T) {
	out := captureStdout(t, func() {
		if err := outputJSON(nil); err != nil {
			t.Errorf("outputJSON(nil): %v", err)
		}
	})
	if !strings.HasPrefix(strings.TrimSpace(out), "[") && strings.TrimSpace(out) != "null" {
		t.Errorf("outputJSON empty = %q, want JSON array/null", out)
	}
}

func TestOutputJSON_rows(t *testing.T) {
	images := []db.Image{makeListImg(1, "linux", "amd64", db.StateApproved)}
	out := captureStdout(t, func() {
		if err := outputJSON(images); err != nil {
			t.Errorf("outputJSON: %v", err)
		}
	})
	var result []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("outputJSON not valid JSON: %v — output: %q", err, out)
	}
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	if result[0]["state"] != "approved" {
		t.Errorf("state = %v, want approved", result[0]["state"])
	}
}

// ── printVulnSummary ──────────────────────────────────────────────────────────

func TestPrintVulnSummary_noVulns(t *testing.T) {
	raw := json.RawMessage(`{"Results":[{"Vulnerabilities":[]}]}`)
	out := captureStdout(t, func() { printVulnSummary(os.Stdout, raw) })
	if !strings.Contains(out, "No vulnerabilities") {
		t.Errorf("expected no-vulnerabilities message: %q", out)
	}
}

func TestPrintVulnSummary_withVulns(t *testing.T) {
	raw := json.RawMessage(`{"Results":[{"Vulnerabilities":[
		{"Severity":"CRITICAL"},{"Severity":"CRITICAL"},
		{"Severity":"HIGH"},{"Severity":"MEDIUM"}
	]}]}`)
	out := captureStdout(t, func() { printVulnSummary(os.Stdout, raw) })
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected CRITICAL in output: %q", out)
	}
	if !strings.Contains(out, "TOTAL") {
		t.Errorf("expected TOTAL in output: %q", out)
	}
}

func TestPrintVulnSummary_invalidJSON(t *testing.T) {
	raw := json.RawMessage(`not json`)
	out := captureStdout(t, func() { printVulnSummary(os.Stdout, raw) })
	if !strings.Contains(out, "could not parse") {
		t.Errorf("expected parse-error message: %q", out)
	}
}

// ── printJSON extra branches ──────────────────────────────────────────────────

func TestPrintJSON_structDefault(t *testing.T) {
	type payload struct{ X int }
	out := captureStdout(t, func() {
		if err := printJSON(payload{X: 42}); err != nil {
			t.Errorf("printJSON struct: %v", err)
		}
	})
	if !strings.Contains(out, "42") {
		t.Errorf("printJSON struct = %q, missing value 42", out)
	}
}

func TestPrintJSON_invalidJSONString(t *testing.T) {
	// A string that is not JSON → raw-write path.
	out := captureStdout(t, func() {
		if err := printJSON("not-valid-json"); err != nil {
			t.Errorf("printJSON invalid string: %v", err)
		}
	})
	if !strings.Contains(out, "not-valid-json") {
		t.Errorf("printJSON invalid = %q, want raw string", out)
	}
}

// ── runList ───────────────────────────────────────────────────────────────────

func TestRunList_table(t *testing.T) {
	database = &mockDB{listOut: []db.Image{makeListImg(1, "linux", "amd64", db.StateQueued)}}
	listStates = nil
	listJSON = false

	out := captureStdout(t, func() {
		if err := runList(listCmd, nil); err != nil {
			t.Errorf("runList: %v", err)
		}
	})
	if !strings.Contains(out, "amd64") {
		t.Errorf("runList table missing amd64: %q", out)
	}
}

func TestRunList_jsonFlag(t *testing.T) {
	database = &mockDB{listOut: []db.Image{makeListImg(1, "linux", "amd64", db.StateApproved)}}
	listStates = nil
	listJSON = true
	t.Cleanup(func() { listJSON = false })

	out := captureStdout(t, func() {
		if err := runList(listCmd, nil); err != nil {
			t.Errorf("runList JSON: %v", err)
		}
	})
	var result []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("runList JSON not valid: %v — %q", err, out)
	}
}

func TestRunList_stateFilter(t *testing.T) {
	database = &mockDB{listOut: nil}
	listStates = []string{"approved"}
	listJSON = false
	t.Cleanup(func() { listStates = nil })

	_ = captureStdout(t, func() {
		if err := runList(listCmd, nil); err != nil {
			t.Errorf("runList state filter: %v", err)
		}
	})
}

func TestRunList_commaStates(t *testing.T) {
	database = &mockDB{listOut: nil}
	listStates = []string{"approved,queued"}
	listJSON = false
	t.Cleanup(func() { listStates = nil })

	_ = captureStdout(t, func() {
		if err := runList(listCmd, nil); err != nil {
			t.Errorf("runList comma states: %v", err)
		}
	})
}

func TestRunList_invalidState(t *testing.T) {
	database = &mockDB{}
	listStates = []string{"badstate"}
	t.Cleanup(func() { listStates = nil })

	err := runList(listCmd, nil)
	if err == nil {
		t.Error("expected error for invalid state, got nil")
	}
}

func TestRunList_dbError(t *testing.T) {
	database = &mockDB{listErr: os.ErrPermission}
	listStates = nil

	err := runList(listCmd, nil)
	if err == nil {
		t.Error("expected error from db.List, got nil")
	}
}

func TestRunList_withRef(t *testing.T) {
	database = &mockDB{listOut: nil}
	listStates = nil
	listJSON = false

	_ = captureStdout(t, func() {
		if err := runList(listCmd, []string{"myrepo:v1.0"}); err != nil {
			t.Errorf("runList with ref: %v", err)
		}
	})
}

// ── runScan ───────────────────────────────────────────────────────────────────

func TestRunScan_badRef(t *testing.T) {
	err := runScan(scanCmd, []string{"not-a-ref::::"})
	if err == nil {
		t.Error("expected error for bad image ref, got nil")
	}
}

func TestRunScan_queueError(t *testing.T) {
	withConfig(t)
	database = &mockDB{queueErr: os.ErrPermission}
	err := runScan(scanCmd, []string{"registry.example.com/repo:tag"})
	if err == nil {
		t.Error("expected error from Queue, got nil")
	}
}

func TestRunScan_noImages(t *testing.T) {
	withConfig(t)
	database = &mockDB{images: nil}
	err := runScan(scanCmd, []string{"registry.example.com/repo:tag"})
	if err == nil {
		t.Error("expected error for empty image list, got nil")
	}
}

func TestRunScan_alreadyScanned_noForce(t *testing.T) {
	withConfig(t)
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = json.RawMessage(`{"SchemaVersion":2}`)
	database = &mockDB{images: []*db.Image{img}}
	scanForce = false
	scanPlatform = ""

	out := captureStdout(t, func() {
		if err := runScan(scanCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runScan already scanned: %v", err)
		}
	})
	if !strings.Contains(out, "SchemaVersion") {
		t.Errorf("expected scan report in output: %q", out)
	}
}

func TestRunScan_success(t *testing.T) {
	withConfig(t)
	withTrivyExec(t, fakeCmd("echo", `{"SchemaVersion":2,"Results":[]}`))
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	scanned := makeImg(1, "linux", "amd64", db.StateScanned)
	scanned.ScanReport = json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	database = &mockDB{images: []*db.Image{img}, saveScanImg: scanned}
	scanForce = false
	scanPlatform = ""

	_ = captureStdout(t, func() {
		if err := runScan(scanCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runScan success: %v", err)
		}
	})
}

func TestRunScan_trivyError(t *testing.T) {
	withConfig(t)
	withTrivyExec(t, fakeCmd("false")) // exits non-zero
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	database = &mockDB{images: []*db.Image{img}}
	scanForce = false
	scanPlatform = ""

	err := runScan(scanCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected trivy error, got nil")
	}
}

func TestRunScan_saveScanError(t *testing.T) {
	withConfig(t)
	withTrivyExec(t, fakeCmd("echo", `{"SchemaVersion":2,"Results":[]}`))
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	database = &mockDB{images: []*db.Image{img}, saveScanErr: os.ErrPermission}
	scanForce = false
	scanPlatform = ""

	err := runScan(scanCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error from SaveScan, got nil")
	}
}

// ── runView ───────────────────────────────────────────────────────────────────

func TestRunView_badRef(t *testing.T) {
	err := runView(viewCmd, []string{"not-a-ref::::"})
	if err == nil {
		t.Error("expected error for bad ref, got nil")
	}
}

func TestRunView_dbError(t *testing.T) {
	database = &mockDB{getRefErr: os.ErrPermission}
	err := runView(viewCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error from GetByRef, got nil")
	}
}

func TestRunView_notFound(t *testing.T) {
	database = &mockDB{images: nil}
	err := runView(viewCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for not-found image, got nil")
	}
}

func TestRunView_success(t *testing.T) {
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	database = &mockDB{images: []*db.Image{img}}
	viewPlatform = ""

	out := captureStdout(t, func() {
		if err := runView(viewCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runView: %v", err)
		}
	})
	if !strings.Contains(out, "linux") {
		t.Errorf("expected linux in view output: %q", out)
	}
}

func TestRunView_noScanReport(t *testing.T) {
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	database = &mockDB{images: []*db.Image{img}}
	viewPlatform = ""

	_ = captureStdout(t, func() {
		if err := runView(viewCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runView no scan: %v", err)
		}
	})
}

// ── runRescind ────────────────────────────────────────────────────────────────

func TestRunRescind_badRef(t *testing.T) {
	err := runRescind(rescindCmd, []string{"not-a-ref::::"})
	if err == nil {
		t.Error("expected error for bad ref, got nil")
	}
}

func TestRunRescind_notFound(t *testing.T) {
	database = &mockDB{images: nil}
	err := runRescind(rescindCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for not-found image, got nil")
	}
}

func TestRunRescind_notApproved(t *testing.T) {
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	database = &mockDB{images: []*db.Image{img}}
	err := runRescind(rescindCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for non-approved image, got nil")
	}
}

func TestRunRescind_success(t *testing.T) {
	img := makeImg(1, "linux", "amd64", db.StateApproved)
	database = &mockDB{images: []*db.Image{img}}
	_ = captureStdout(t, func() {
		if err := runRescind(rescindCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runRescind: %v", err)
		}
	})
}

// ── runReject ─────────────────────────────────────────────────────────────────

func TestRunReject_badRef(t *testing.T) {
	err := runReject(rejectCmd, []string{"not-a-ref::::"})
	if err == nil {
		t.Error("expected error for bad ref, got nil")
	}
}

func TestRunReject_cancelled(t *testing.T) {
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	database = &mockDB{images: []*db.Image{img}}
	fakeStdin(t, "NO")

	out := captureStdout(t, func() {
		if err := runReject(rejectCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runReject cancelled: %v", err)
		}
	})
	if !strings.Contains(out, "Cancelled") {
		t.Errorf("expected Cancelled in output: %q", out)
	}
}

func TestRunReject_confirmed(t *testing.T) {
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	database = &mockDB{images: []*db.Image{img}}
	fakeStdin(t, "YES")

	_ = captureStdout(t, func() {
		if err := runReject(rejectCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runReject confirmed: %v", err)
		}
	})
}

// ── runReport ─────────────────────────────────────────────────────────────────

func TestRunReport_invalidFormat(t *testing.T) {
	reportFormat = "pdf"
	t.Cleanup(func() { reportFormat = "table" })
	err := runReport(reportCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for invalid format, got nil")
	}
}

func TestRunReport_badRef(t *testing.T) {
	reportFormat = "table"
	err := runReport(reportCmd, []string{"not-a-ref::::"})
	if err == nil {
		t.Error("expected error for bad ref, got nil")
	}
}

func TestRunReport_notFound(t *testing.T) {
	reportFormat = "table"
	database = &mockDB{images: nil}
	err := runReport(reportCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for not-found image, got nil")
	}
}

func TestRunReport_noScanReport(t *testing.T) {
	reportFormat = "table"
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	database = &mockDB{images: []*db.Image{img}}
	err := runReport(reportCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for missing scan report, got nil")
	}
}

func TestRunReport_jsonFormat(t *testing.T) {
	reportFormat = "json"
	reportOutput = ""
	t.Cleanup(func() { reportFormat = "table"; reportOutput = "" })

	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = json.RawMessage(`{"SchemaVersion":2}`)
	database = &mockDB{images: []*db.Image{img}}

	_ = captureStdout(t, func() {
		if err := runReport(reportCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runReport json: %v", err)
		}
	})
}

func TestRunReport_tableFormat(t *testing.T) {
	withConfig(t)
	withTrivyExec(t, fakeCmd("echo", "table output"))
	reportFormat = "table"
	reportOutput = ""
	t.Cleanup(func() { reportFormat = "table"; reportOutput = "" })

	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = json.RawMessage(`{"SchemaVersion":2}`)
	database = &mockDB{images: []*db.Image{img}}

	_ = captureStdout(t, func() {
		if err := runReport(reportCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runReport table: %v", err)
		}
	})
}

// ── runApprove ────────────────────────────────────────────────────────────────

func TestRunApprove_badRef(t *testing.T) {
	err := runApprove(approveCmd, []string{"not-a-ref::::"})
	if err == nil {
		t.Error("expected error for bad ref, got nil")
	}
}

func TestRunApprove_queueError(t *testing.T) {
	withConfig(t)
	database = &mockDB{queueErr: os.ErrPermission}
	err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error from Queue, got nil")
	}
}

func TestRunApprove_noImages(t *testing.T) {
	withConfig(t)
	database = &mockDB{images: nil}
	err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for empty image list, got nil")
	}
}

func TestRunApprove_answerNO(t *testing.T) {
	withConfig(t)
	withTrivyExec(t, fakeCmd("echo", `{"SchemaVersion":2,"Results":[]}`))
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	scanned := makeImg(1, "linux", "amd64", db.StateScanned)
	scanned.ScanReport = json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	database = &mockDB{images: []*db.Image{img}, saveScanImg: scanned}
	approvePlatform = ""
	fakeStdin(t, "NO")

	_ = captureStdout(t, func() {
		if err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runApprove NO: %v", err)
		}
	})
}

func TestRunApprove_answerYES(t *testing.T) {
	withConfig(t)
	withTrivyExec(t, fakeCmd("echo", `{"SchemaVersion":2,"Results":[]}`))
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	scanned := makeImg(1, "linux", "amd64", db.StateScanned)
	scanned.ScanReport = json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	database = &mockDB{images: []*db.Image{img}, saveScanImg: scanned}
	approvePlatform = ""
	fakeStdin(t, "YES")

	_ = captureStdout(t, func() {
		if err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runApprove YES: %v", err)
		}
	})
}

func TestRunApprove_answerREJECT(t *testing.T) {
	withConfig(t)
	withTrivyExec(t, fakeCmd("echo", `{"SchemaVersion":2,"Results":[]}`))
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	scanned := makeImg(1, "linux", "amd64", db.StateScanned)
	scanned.ScanReport = json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	database = &mockDB{images: []*db.Image{img}, saveScanImg: scanned}
	approvePlatform = ""
	fakeStdin(t, "REJECT")

	_ = captureStdout(t, func() {
		err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"})
		if err == nil {
			t.Error("expected error from REJECT answer, got nil")
		}
	})
}

func TestRunApprove_alreadyScanned(t *testing.T) {
	withConfig(t)
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	database = &mockDB{images: []*db.Image{img}}
	approvePlatform = ""
	fakeStdin(t, "NO")

	_ = captureStdout(t, func() {
		if err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runApprove already scanned: %v", err)
		}
	})
}

// ensure bytes is imported for the buffer usage in test helpers
var _ = bytes.NewBuffer
