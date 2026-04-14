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

	// call captures — populated by the mock methods for tests to assert on.
	listFilter    db.ListFilter
	rejectIDs     []int64
	rescindIDs    []int64
	approveIDs    []int64
	approveCaches []string
	setErrorIDs   []int64
}

func (m *mockDB) Queue(_ db.ImageRef, _ db.Fetcher) ([]*db.Image, error) {
	return m.images, m.queueErr
}
func (m *mockDB) SetError(id int64) error {
	m.setErrorIDs = append(m.setErrorIDs, id)
	return nil
}
func (m *mockDB) SaveScan(_ int64, _ json.RawMessage) (*db.Image, error) {
	return m.saveScanImg, m.saveScanErr
}
func (m *mockDB) LogEvent(_ *int64, _ db.EventSource, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockDB) List(f db.ListFilter) ([]db.Image, error) {
	m.listFilter = f
	return m.listOut, m.listErr
}
func (m *mockDB) GetByRef(_ db.ImageRef) ([]*db.Image, error) { return m.images, m.getRefErr }
func (m *mockDB) Approve(id int64, cacheRegistry string) error {
	m.approveIDs = append(m.approveIDs, id)
	m.approveCaches = append(m.approveCaches, cacheRegistry)
	return m.approveErr
}
func (m *mockDB) Reject(id int64) error {
	m.rejectIDs = append(m.rejectIDs, id)
	return m.rejectErr
}
func (m *mockDB) Rescind(id int64) error {
	m.rescindIDs = append(m.rescindIDs, id)
	return m.rescindErr
}
func (m *mockDB) Close() {}

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

// trivyCall is one captured invocation of the trivy execCommand var.
type trivyCall struct {
	name string
	args []string
}

// trivyExecRecorder records every call routed through the trivy execCommand
// var and lets each test pick the real backend (echo, cat, false) so the
// production code's *exec.Cmd remains genuine.  Routing trivy.Convert through
// `cat` proves the production code wired Stdin to the report bytes; routing
// trivy.Scan through `echo <json>` simulates a successful scan output.  Tests
// can then assert on .calls to confirm the exec actually happened and inspect
// the constructed argv.
type trivyExecRecorder struct {
	calls []trivyCall
}

// use installs the recorder on trivy's execCommand var with a single fixed
// backend that every captured call routes through.  Convenient when the
// production code only makes one trivy invocation per test.
func (r *trivyExecRecorder) use(t *testing.T, realName string, realArgs ...string) {
	t.Helper()
	r.useSequence(t, execResponse{name: realName, args: realArgs})
}

// useSequence installs the recorder with one backend per call, advancing
// through responses in order.  Calls beyond the end fall through to `true`
// (succeed silently) so tests don't have to pad tail slots they don't care
// about.  Required for runScan and runApprove now that both make a Scan +
// Convert pair of docker invocations.
func (r *trivyExecRecorder) useSequence(t *testing.T, responses ...execResponse) {
	t.Helper()
	idx := 0
	orig := trivy.ExecCommandVar()
	trivy.SetExecCommand(func(name string, args ...string) *exec.Cmd {
		r.calls = append(r.calls, trivyCall{
			name: name,
			args: append([]string(nil), args...),
		})
		var resp execResponse
		if idx < len(responses) {
			resp = responses[idx]
		}
		idx++
		if resp.name == "" {
			resp = execResponse{name: "true"}
		}
		return exec.Command(resp.name, resp.args...)
	})
	t.Cleanup(func() { trivy.SetExecCommand(orig) })
}

// approveCall is one captured invocation of cmd/approve.go's
// approveExecCommand var.  Stored separately from trivyCall so future
// changes to either recorder are independent.
type approveCall struct {
	name string
	args []string
}

// execResponse describes one real subprocess the approveExecRecorder should
// stand in for when its sequenced mode is used.  A zero execResponse (name
// == "") means "succeed silently" — handy when a test needs N slots and
// only cares about K < N of them.
type execResponse struct {
	name string
	args []string
}

// approveExecRecorder records every call routed through cmd/approve.go's
// approveExecCommand var.  Unlike trivyExecRecorder it supports sequenced
// backends: pushToCache makes four docker calls (pull, tag, push, rmi), and
// a realistic regression test has to simulate e.g. "pull and tag succeed,
// push fails" — a single fixed response cannot express that.
type approveExecRecorder struct {
	calls []approveCall
}

// use installs the recorder with a single fixed backend that every call
// routes through — convenient for "everything succeeds" or "everything fails"
// tests.  Use useSequence when different calls need different outcomes.
func (r *approveExecRecorder) use(t *testing.T, realName string, realArgs ...string) {
	t.Helper()
	r.useSequence(t, execResponse{name: realName, args: realArgs})
}

// useSequence installs the recorder with a list of backends, one per call.
// The Nth production call gets the Nth response; calls beyond the end of
// the sequence fall through to `true` (succeed silently) so a test that
// only cares about the first few failures doesn't have to pad the tail.
func (r *approveExecRecorder) useSequence(t *testing.T, responses ...execResponse) {
	t.Helper()
	idx := 0
	orig := approveExecCommand
	approveExecCommand = func(name string, args ...string) *exec.Cmd {
		r.calls = append(r.calls, approveCall{
			name: name,
			args: append([]string(nil), args...),
		})
		var resp execResponse
		if idx < len(responses) {
			resp = responses[idx]
		}
		idx++
		if resp.name == "" {
			resp = execResponse{name: "true"}
		}
		return exec.Command(resp.name, resp.args...)
	}
	t.Cleanup(func() { approveExecCommand = orig })
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

func TestRunList_platformFilter(t *testing.T) {
	m := &mockDB{listOut: nil}
	database = m
	listStates = nil
	listJSON = false
	listPlatform = "linux/arm64"
	t.Cleanup(func() { listPlatform = "" })

	_ = captureStdout(t, func() {
		if err := runList(listCmd, nil); err != nil {
			t.Errorf("runList --platform: %v", err)
		}
	})
	if m.listFilter.OS != "linux" || m.listFilter.Arch != "arm64" {
		t.Errorf("listFilter = %+v, want OS=linux Arch=arm64", m.listFilter)
	}
}

func TestRunList_platformOSOnly(t *testing.T) {
	m := &mockDB{listOut: nil}
	database = m
	listPlatform = "windows"
	t.Cleanup(func() { listPlatform = "" })

	_ = captureStdout(t, func() {
		if err := runList(listCmd, nil); err != nil {
			t.Errorf("runList --platform os-only: %v", err)
		}
	})
	if m.listFilter.OS != "windows" || m.listFilter.Arch != "" {
		t.Errorf("listFilter = %+v, want OS=windows Arch=''", m.listFilter)
	}
}

func TestRunList_platformInvalid(t *testing.T) {
	database = &mockDB{listOut: nil}
	listPlatform = "/amd64"
	t.Cleanup(func() { listPlatform = "" })

	err := runList(listCmd, nil)
	if err == nil {
		t.Error("expected error for empty OS in --platform, got nil")
	}
}

func TestParsePlatformFilter(t *testing.T) {
	cases := []struct {
		in, os, arch string
		wantErr      bool
	}{
		{"", "", "", false},
		{"linux", "linux", "", false},
		{"linux/amd64", "linux", "amd64", false},
		{"  linux/arm64  ", "linux", "arm64", false},
		{"/amd64", "", "", true},
	}
	for _, c := range cases {
		os, arch, err := parsePlatformFilter(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parsePlatformFilter(%q) err = %v, wantErr = %v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && (os != c.os || arch != c.arch) {
			t.Errorf("parsePlatformFilter(%q) = (%q, %q), want (%q, %q)",
				c.in, os, arch, c.os, c.arch)
		}
	}
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

// ── printScanReport ───────────────────────────────────────────────────────────

func TestPrintScanReport_writesTrivyTable(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	// Use cat so the report bytes round-trip through the fake exec — proves
	// that printScanReport actually wired the report into trivy.Convert's
	// stdin rather than passing it through some other path.
	rec.use(t, "cat")

	report := json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	var buf bytes.Buffer
	if err := printScanReport(&buf, report); err != nil {
		t.Fatalf("printScanReport: %v", err)
	}
	if buf.String() != string(report) {
		t.Errorf("output = %q, want %q", buf.String(), report)
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 trivy exec call, got %d", len(rec.calls))
	}
}

func TestPrintScanReport_emptyReportNoExec(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.use(t, "false") // any exec attempt would be a regression
	var buf bytes.Buffer
	if err := printScanReport(&buf, nil); err != nil {
		t.Errorf("printScanReport(nil): %v", err)
	}
	if err := printScanReport(&buf, json.RawMessage(`null`)); err != nil {
		t.Errorf("printScanReport(null): %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("buf = %q, want empty", buf.String())
	}
	if len(rec.calls) != 0 {
		t.Errorf("empty/null reports must not invoke trivy, got %d calls", len(rec.calls))
	}
}

func TestPrintScanReport_propagatesConvertError(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.use(t, "false")
	var buf bytes.Buffer
	err := printScanReport(&buf, json.RawMessage(`{"SchemaVersion":2}`))
	if err == nil {
		t.Error("expected error from failing convert, got nil")
	}
}

func TestRunScan_alreadyScanned_noForce(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	// Pre-scanned image: only the render step shells out (no scan).
	rec.use(t, "echo", "rendered table contents")
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
	if !strings.Contains(out, "rendered table contents") {
		t.Errorf("expected rendered table in stdout: %q", out)
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 trivy exec (render only), got %d", len(rec.calls))
	}
}

func TestRunScan_success(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	// Scan + printScanReport (Convert) — two trivy invocations now.
	rec.useSequence(t,
		execResponse{name: "echo", args: []string{`{"SchemaVersion":2,"Results":[]}`}},
		execResponse{name: "echo", args: []string{"fake table"}},
	)
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
	if len(rec.calls) != 2 {
		t.Errorf("expected 2 trivy exec calls (scan + render), got %d", len(rec.calls))
	}
}

func TestRunScan_trivyError(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.use(t, "false") // exits non-zero
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	database = &mockDB{images: []*db.Image{img}}
	scanForce = false
	scanPlatform = ""

	err := runScan(scanCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected trivy error, got nil")
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 trivy exec call (the failing one), got %d", len(rec.calls))
	}
}

func TestRunScan_saveScanError(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.use(t, "echo", `{"SchemaVersion":2,"Results":[]}`)
	img := makeImg(1, "linux", "amd64", db.StateQueued)
	database = &mockDB{images: []*db.Image{img}, saveScanErr: os.ErrPermission}
	scanForce = false
	scanPlatform = ""

	err := runScan(scanCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error from SaveScan, got nil")
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 trivy exec call before the SaveScan failure, got %d", len(rec.calls))
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

func TestRunReject_platformNarrows(t *testing.T) {
	// Two platforms; --platform linux/arm64 should reject only the arm64 one.
	amd := makeImg(1, "linux", "amd64", db.StateScanned)
	arm := makeImg(2, "linux", "arm64", db.StateScanned)
	m := &mockDB{images: []*db.Image{amd, arm}}
	database = m
	rejectPlatform = "linux/arm64"
	t.Cleanup(func() { rejectPlatform = "" })
	fakeStdin(t, "YES")

	_ = captureStdout(t, func() {
		if err := runReject(rejectCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runReject --platform: %v", err)
		}
	})
	if len(m.rejectIDs) != 1 || m.rejectIDs[0] != 2 {
		t.Errorf("rejectIDs = %v, want [2]", m.rejectIDs)
	}
}

func TestRunReject_platformNotFound(t *testing.T) {
	amd := makeImg(1, "linux", "amd64", db.StateScanned)
	database = &mockDB{images: []*db.Image{amd}}
	rejectPlatform = "linux/arm64"
	t.Cleanup(func() { rejectPlatform = "" })

	err := runReject(rejectCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error for unknown --platform, got nil")
	}
}

func TestRunRescind_platformNarrows(t *testing.T) {
	amd := makeImg(1, "linux", "amd64", db.StateApproved)
	arm := makeImg(2, "linux", "arm64", db.StateApproved)
	m := &mockDB{images: []*db.Image{amd, arm}}
	database = m
	rescindPlatform = "linux/amd64"
	t.Cleanup(func() { rescindPlatform = "" })

	_ = captureStdout(t, func() {
		if err := runRescind(rescindCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runRescind --platform: %v", err)
		}
	})
	if len(m.rescindIDs) != 1 || m.rescindIDs[0] != 1 {
		t.Errorf("rescindIDs = %v, want [1]", m.rescindIDs)
	}
}

func TestRunRescind_platformNotApproved(t *testing.T) {
	amd := makeImg(1, "linux", "amd64", db.StateApproved)
	arm := makeImg(2, "linux", "arm64", db.StateScanned)
	database = &mockDB{images: []*db.Image{amd, arm}}
	rescindPlatform = "linux/arm64"
	t.Cleanup(func() { rescindPlatform = "" })

	err := runRescind(rescindCmd, []string{"registry.example.com/myrepo:v1.0"})
	if err == nil {
		t.Error("expected error rescinding non-approved platform, got nil")
	}
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

// TestRunReport_jsonFormat verifies that the json fast-path writes the
// stored scan_report bytes verbatim to stdout AND bypasses trivy entirely
// (no exec call should be made).  Both invariants matter: the bytes must
// reach the user, and we must not pay the trivy round-trip when we already
// have JSON.
func TestRunReport_jsonFormat(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.use(t, "false") // any exec attempt would be a regression

	reportFormat = "json"
	reportOutput = ""
	t.Cleanup(func() { reportFormat = "table"; reportOutput = "" })

	stored := json.RawMessage(`{"SchemaVersion":2,"Results":[{"Target":"alpine"}]}`)
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = stored
	database = &mockDB{images: []*db.Image{img}}

	out := captureStdout(t, func() {
		if err := runReport(reportCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runReport json: %v", err)
		}
	})
	if out != string(stored) {
		t.Errorf("stdout = %q, want stored report bytes %q", out, stored)
	}
	if len(rec.calls) != 0 {
		t.Errorf("json fast-path must not invoke trivy, got %d calls", len(rec.calls))
	}
}

// TestRunReport_tableFormat is the regression test for the
// "trivy convert -" bug.  It pipes the report through a `cat` backend so
// any byte that reaches stdout demonstrably traversed the production
// Stdin → trivy.Convert → ConvertToFile → os.Stdout pipeline; if Convert
// were broken (e.g. `-` arg, missing Stdin wiring, fast-path skip), the
// captured stdout would not equal the stored report bytes.
func TestRunReport_tableFormat(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.use(t, "cat") // pipes Stdin → Stdout; only works if Convert wires Stdin

	reportFormat = "table"
	reportOutput = ""
	t.Cleanup(func() { reportFormat = "table"; reportOutput = "" })

	stored := json.RawMessage(`{"SchemaVersion":2,"Results":[{"Target":"alpine"}]}`)
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = stored
	database = &mockDB{images: []*db.Image{img}}

	out := captureStdout(t, func() {
		if err := runReport(reportCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runReport table: %v", err)
		}
	})
	if out != string(stored) {
		t.Errorf("stdout = %q, want stored report bytes %q\n"+
			"(if these differ, runReport→trivy.Convert is not wiring Stdin)",
			out, stored)
	}
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 trivy exec call, got %d", len(rec.calls))
	}
	// Spot-check the call landed on docker with the configured format flag.
	// Detailed argv assertions live in internal/trivy/trivy_test.go.
	if len(rec.calls) > 0 {
		call := rec.calls[0]
		if call.name != "docker" {
			t.Errorf("trivy exec name = %q, want docker", call.name)
		}
		hasFormat := false
		for i := 0; i+1 < len(call.args); i++ {
			if call.args[i] == "--format" && call.args[i+1] == "table" {
				hasFormat = true
				break
			}
		}
		if !hasFormat {
			t.Errorf("args missing --format table\nargs: %v", call.args)
		}
		// Defense-in-depth regression check: the original bug passed "-"
		// to trivy convert as if it would read stdin.  Trivy treats that
		// as a literal file path and fails.  Make sure no orchestration
		// regression silently puts "-" back on the command line.
		for _, a := range call.args {
			if a == "-" {
				t.Errorf("args contain literal '-' input path; trivy convert does not read stdin\nargs: %v", call.args)
				break
			}
		}
	}
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

// scanThenRenderResponses returns the canonical pair of backends used by
// approve tests that exercise the implicit scan: echo'd JSON for trivy.Scan,
// then a fake table line for printScanReport / trivy.Convert.
func scanThenRenderResponses() []execResponse {
	return []execResponse{
		{name: "echo", args: []string{`{"SchemaVersion":2,"Results":[]}`}},
		{name: "echo", args: []string{"fake table"}},
	}
}

func TestRunApprove_answerNO(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.useSequence(t, scanThenRenderResponses()...)
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
	if len(rec.calls) != 2 {
		t.Errorf("expected 2 trivy execs (scan + render), got %d", len(rec.calls))
	}
}

func TestRunApprove_answerYES(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.useSequence(t, scanThenRenderResponses()...)
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
	if len(rec.calls) != 2 {
		t.Errorf("expected 2 trivy execs (scan + render), got %d", len(rec.calls))
	}
}

func TestRunApprove_answerREJECT(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	rec.useSequence(t, scanThenRenderResponses()...)
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
	if len(rec.calls) != 2 {
		t.Errorf("expected 2 trivy execs (scan + render), got %d", len(rec.calls))
	}
}

func TestRunApprove_alreadyScanned(t *testing.T) {
	withConfig(t)
	rec := &trivyExecRecorder{}
	// Pre-scanned image: only the render step shells out (no implicit scan).
	rec.use(t, "echo", "fake table")
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
	if len(rec.calls) != 1 {
		t.Errorf("expected 1 trivy exec (render only, scan is skipped), got %d", len(rec.calls))
	}
}

// ── runApprove --cache ────────────────────────────────────────────────────────

// setApproveCacheFlag sets --cache explicitly so cmd.Flags().Changed("cache")
// returns true inside runApprove, and registers a cleanup that resets both
// the value and the changed bit so sibling tests see a fresh flag state.
func setApproveCacheFlag(t *testing.T, value string) {
	t.Helper()
	if err := approveCmd.Flags().Set("cache", value); err != nil {
		t.Fatalf("set --cache: %v", err)
	}
	t.Cleanup(func() {
		_ = approveCmd.Flags().Set("cache", "")
		approveCmd.Flags().Lookup("cache").Changed = false
		approveCache = ""
	})
}

// approveCacheSetup builds the common fixtures for --cache tests: an
// already-scanned image (skips the implicit trivy scan), a YES stdin answer,
// and a trivy recorder backing the printScanReport render step so the test
// body only has to configure the approveExecRecorder for pushToCache.
func approveCacheSetup(t *testing.T) *mockDB {
	t.Helper()
	withConfig(t)
	tr := &trivyExecRecorder{}
	tr.use(t, "echo", "fake table")
	img := makeImg(1, "linux", "amd64", db.StateScanned)
	img.ScanReport = json.RawMessage(`{"SchemaVersion":2,"Results":[]}`)
	m := &mockDB{images: []*db.Image{img}}
	database = m
	approvePlatform = ""
	t.Cleanup(func() { approvePlatform = "" })
	fakeStdin(t, "YES")
	return m
}

// TestRunApprove_cacheSuccess exercises the full pushToCache sequence —
// pull, tag, push, rmi — and asserts that (a) all four docker calls
// actually ran in the correct order, (b) the image was approved with the
// cache registry recorded, and (c) no SetError path fired.
func TestRunApprove_cacheSuccess(t *testing.T) {
	m := approveCacheSetup(t)
	setApproveCacheFlag(t, "cache.example.com")

	rec := &approveExecRecorder{}
	rec.use(t, "true") // every docker call succeeds

	_ = captureStdout(t, func() {
		if err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"}); err != nil {
			t.Errorf("runApprove YES --cache: %v", err)
		}
	})

	if len(rec.calls) != 4 {
		t.Fatalf("expected 4 docker calls (pull, tag, push, rmi), got %d: %+v", len(rec.calls), rec.calls)
	}
	wantSubcommands := []string{"pull", "tag", "push", "rmi"}
	for i, want := range wantSubcommands {
		call := rec.calls[i]
		if call.name != "docker" {
			t.Errorf("call[%d] name = %q, want docker", i, call.name)
		}
		if len(call.args) == 0 || call.args[0] != want {
			t.Errorf("call[%d] subcommand = %v, want %q", i, call.args, want)
		}
	}
	// The push destination must carry the cache registry prefix.
	pushCall := rec.calls[2]
	if len(pushCall.args) < 2 {
		t.Fatalf("push call missing dest: %v", pushCall.args)
	}
	dest := pushCall.args[1]
	if !strings.HasPrefix(dest, "cache.example.com/") {
		t.Errorf("push dest = %q, want cache.example.com/ prefix", dest)
	}

	// Database state: Approve called once with the cache URL, no SetError.
	if len(m.approveIDs) != 1 || m.approveIDs[0] != 1 {
		t.Errorf("approveIDs = %v, want [1]", m.approveIDs)
	}
	if len(m.approveCaches) != 1 || m.approveCaches[0] != "cache.example.com" {
		t.Errorf("approveCaches = %v, want [cache.example.com]", m.approveCaches)
	}
	if len(m.setErrorIDs) != 0 {
		t.Errorf("setErrorIDs = %v, want empty on success", m.setErrorIDs)
	}
}

// TestRunApprove_cachePullFails verifies the early-exit path: the pull
// step fails, pushToCache returns immediately, runApprove flips the image
// to errored, and no Approve call ever reaches the database.
func TestRunApprove_cachePullFails(t *testing.T) {
	m := approveCacheSetup(t)
	setApproveCacheFlag(t, "cache.example.com")

	rec := &approveExecRecorder{}
	rec.use(t, "false") // every docker call fails — pull is the first to hit

	_ = captureStdout(t, func() {
		err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"})
		if err == nil {
			t.Error("expected error from failing docker pull, got nil")
		}
	})

	if len(rec.calls) != 1 {
		t.Errorf("expected 1 docker call (pull only), got %d: %+v", len(rec.calls), rec.calls)
	}
	if len(rec.calls) > 0 && rec.calls[0].args[0] != "pull" {
		t.Errorf("first call was %v, want pull", rec.calls[0].args)
	}
	if len(m.setErrorIDs) != 1 || m.setErrorIDs[0] != 1 {
		t.Errorf("setErrorIDs = %v, want [1]", m.setErrorIDs)
	}
	if len(m.approveIDs) != 0 {
		t.Errorf("approveIDs = %v, want empty on failure", m.approveIDs)
	}
}

// TestRunApprove_cachePushFails covers the sequenced-failure case the
// single-backend harness cannot express: pull and tag succeed, push
// fails.  runApprove must bail out before rmi and before Approve, and
// it must flip the image to errored.
func TestRunApprove_cachePushFails(t *testing.T) {
	m := approveCacheSetup(t)
	setApproveCacheFlag(t, "cache.example.com")

	rec := &approveExecRecorder{}
	rec.useSequence(t,
		execResponse{name: "true"},  // pull succeeds
		execResponse{name: "true"},  // tag succeeds
		execResponse{name: "false"}, // push fails
		// rmi slot intentionally absent — pushToCache must not reach it.
	)

	_ = captureStdout(t, func() {
		err := runApprove(approveCmd, []string{"registry.example.com/myrepo:v1.0"})
		if err == nil {
			t.Error("expected error from failing docker push, got nil")
		}
	})

	if len(rec.calls) != 3 {
		t.Errorf("expected 3 docker calls (pull, tag, push), got %d: %+v", len(rec.calls), rec.calls)
	}
	if len(rec.calls) >= 3 {
		if rec.calls[2].args[0] != "push" {
			t.Errorf("third call subcommand = %q, want push", rec.calls[2].args[0])
		}
	}
	// rmi must not have run — short-circuit on push error.
	for i, c := range rec.calls {
		if c.args[0] == "rmi" {
			t.Errorf("call[%d] was rmi, but pushToCache must not reach rmi when push fails", i)
		}
	}
	if len(m.setErrorIDs) != 1 || m.setErrorIDs[0] != 1 {
		t.Errorf("setErrorIDs = %v, want [1]", m.setErrorIDs)
	}
	if len(m.approveIDs) != 0 {
		t.Errorf("approveIDs = %v, want empty on failure", m.approveIDs)
	}
}

// ensure bytes is imported for the buffer usage in test helpers
var _ = bytes.NewBuffer
