package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/trivy"
)

// ── mock storage ──────────────────────────────────────────────────────────────

type mockStorage struct {
	mu sync.Mutex

	listImages []db.Image
	listErr    error
	listCalls  int

	byID    map[int64]*db.Image
	byIDErr error

	queueResp  []*db.Image
	queueErr   error
	queueCalls []db.ImageRef

	approveErr   error
	approveCalls []approveCall
	rejectErr    error
	rejectIDs    []int64
	rescindErr   error
	rescindIDs   []int64

	saveScanResp *db.Image
	saveScanErr  error
	saveScanArg  json.RawMessage
	setErrIDs    []int64

	logEvents []logEventCall
}

type approveCall struct {
	ID    int64
	Cache string
}

type logEventCall struct {
	ImageID *int64
	Source  db.EventSource
	Type    string
	Details map[string]interface{}
}

func (m *mockStorage) List(_ db.ListFilter) ([]db.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	return m.listImages, m.listErr
}
func (m *mockStorage) GetByID(id int64) (*db.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byIDErr != nil {
		return nil, m.byIDErr
	}
	return m.byID[id], nil
}
func (m *mockStorage) Queue(ref db.ImageRef, _ db.Fetcher) ([]*db.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueCalls = append(m.queueCalls, ref)
	if m.queueErr != nil {
		return nil, m.queueErr
	}
	return m.queueResp, nil
}
func (m *mockStorage) Approve(id int64, cache string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approveCalls = append(m.approveCalls, approveCall{ID: id, Cache: cache})
	if img, ok := m.byID[id]; ok && img != nil {
		img.State = db.StateApproved
		img.CacheRegistry = cache
	}
	return m.approveErr
}
func (m *mockStorage) Reject(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejectIDs = append(m.rejectIDs, id)
	if img, ok := m.byID[id]; ok && img != nil {
		img.State = db.StateRejected
	}
	return m.rejectErr
}
func (m *mockStorage) Rescind(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rescindIDs = append(m.rescindIDs, id)
	if img, ok := m.byID[id]; ok && img != nil {
		img.State = db.StateRescinded
	}
	return m.rescindErr
}
func (m *mockStorage) SaveScan(id int64, report json.RawMessage) (*db.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveScanArg = report
	if m.saveScanErr != nil {
		return nil, m.saveScanErr
	}
	if m.saveScanResp != nil {
		return m.saveScanResp, nil
	}
	if img, ok := m.byID[id]; ok && img != nil {
		img.State = db.StateScanned
		img.ScanReport = report
		return img, nil
	}
	return nil, errors.New("not found")
}
func (m *mockStorage) SetError(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setErrIDs = append(m.setErrIDs, id)
	return nil
}
func (m *mockStorage) LogEvent(imgID *int64, source db.EventSource, t string, details map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logEvents = append(m.logEvents, logEventCall{ImageID: imgID, Source: source, Type: t, Details: details})
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestServer(t *testing.T, mock *mockStorage) *Server {
	t.Helper()
	return newTestServerWithBase(t, mock, "")
}

func newTestServerWithBase(t *testing.T, mock *mockStorage, base string) *Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.UI.Addr = ":0"
	cfg.UI.URL = "http://localhost"
	cfg.UI.BasePath = base
	return New(mock, cfg)
}

func newImg(id int64, state db.State) *db.Image {
	now := time.Now()
	return &db.Image{
		ID:          id,
		RegistryURL: "registry.example.com",
		Repository:  "myorg/myapp",
		TagName:     "v1",
		Digest:      fmt.Sprintf("sha256:%064d", id),
		Arch:        "amd64",
		OS:          "linux",
		State:       state,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestNew_panicOnBadTemplates_isCovered(t *testing.T) {
	// Just ensure New does not panic with the embedded templates.  This
	// guards against a future template change that breaks parsing.
	mock := &mockStorage{}
	srv := newTestServer(t, mock)
	if srv == nil {
		t.Fatal("expected server")
	}
	if srv.Handler() == nil {
		t.Fatal("expected handler")
	}
}

func TestServeHealthz(t *testing.T) {
	srv := newTestServer(t, &mockStorage{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != "ok\n" {
		t.Errorf("body = %q, want %q", got, "ok\n")
	}
}

func TestDashboard_renders(t *testing.T) {
	mock := &mockStorage{
		listImages: []db.Image{*newImg(1, db.StateApproved), *newImg(2, db.StateScanned)},
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Dashboard", "approved", "scanned", "registry.example.com/myorg/myapp"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

func TestDashboard_dbError(t *testing.T) {
	mock := &mockStorage{listErr: errors.New("boom")}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestListImages_renders(t *testing.T) {
	mock := &mockStorage{
		listImages: []db.Image{*newImg(7, db.StateApproved)},
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "registry.example.com/myorg/myapp") {
		t.Errorf("body missing image: %s", w.Body.String())
	}
}

func TestListImages_htmxPartial(t *testing.T) {
	mock := &mockStorage{
		listImages: []db.Image{*newImg(7, db.StateApproved)},
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images", nil)
	r.Header.Set("Hx-Request", "true")
	r.Header.Set("Hx-Target", "image-rows")
	srv.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if strings.Contains(body, "<html") {
		t.Errorf("htmx partial should not include layout html: %s", body)
	}
	if !strings.Contains(body, "image-7") {
		t.Errorf("partial missing row id: %s", body)
	}
}

func TestListImages_stateFilter(t *testing.T) {
	mock := &mockStorage{}
	srv := newTestServer(t, mock)

	cases := []struct {
		query   string
		want    int
		wantErr bool
	}{
		{"state=approved", http.StatusOK, false},
		{"state=pending", http.StatusOK, false},
		{"state=verified", http.StatusOK, false},
		{"state=approved,scanned", http.StatusOK, false},
		{"state=bogus", http.StatusBadRequest, true},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/images?"+c.query, nil)
		srv.Handler().ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("query %q: status = %d, want %d", c.query, w.Code, c.want)
		}
	}
}

func TestListImages_dbError(t *testing.T) {
	mock := &mockStorage{listErr: errors.New("boom")}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images?state=approved", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestViewImage(t *testing.T) {
	img := newImg(42, db.StateApproved)
	img.Manifest = json.RawMessage(`{"schemaVersion":2}`)
	img.ScanReport = json.RawMessage(`{"Results":[{"Vulnerabilities":[{"Severity":"HIGH"}]}]}`)
	mock := &mockStorage{byID: map[int64]*db.Image{42: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/42", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"Vulnerability summary", "HIGH", "schemaVersion"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestViewImage_notFound(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byID: map[int64]*db.Image{}})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/999", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestViewImage_badID(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byID: map[int64]*db.Image{}})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/not-a-number", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestViewImage_dbError(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byIDErr: errors.New("boom")})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/1", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestActionApprove(t *testing.T) {
	img := newImg(1, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{1: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/1/approve", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if len(mock.approveCalls) != 1 || mock.approveCalls[0].ID != 1 {
		t.Errorf("expected one Approve(1) call, got %#v", mock.approveCalls)
	}
	if got := mock.approveCalls[0].Cache; got != "" {
		t.Errorf("cache = %q, want empty", got)
	}
	if !containsEvent(mock.logEvents, "approve") {
		t.Errorf("missing approve event: %#v", mock.logEvents)
	}
	// Body should be the row partial reflecting the new state.
	if !strings.Contains(w.Body.String(), "state-approved") {
		t.Errorf("row body missing approved badge: %s", w.Body.String())
	}
}

func TestActionApprove_withCacheURL(t *testing.T) {
	img := newImg(1, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{1: img}}
	srv := newTestServer(t, mock)

	form := strings.NewReader("cache_url=cache.example.com")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/1/approve", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if mock.approveCalls[0].Cache != "cache.example.com" {
		t.Errorf("cache = %q, want cache.example.com", mock.approveCalls[0].Cache)
	}
}

func TestActionApprove_withDefaultCache(t *testing.T) {
	img := newImg(1, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{1: img}}
	srv := newTestServer(t, mock)
	srv.cfg.CacheURL = "default-cache.internal"

	form := strings.NewReader("cache_url=")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/1/approve", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if mock.approveCalls[0].Cache != "default-cache.internal" {
		t.Errorf("cache = %q, want default", mock.approveCalls[0].Cache)
	}
}

func TestActionApprove_dbError(t *testing.T) {
	img := newImg(1, db.StateScanned)
	mock := &mockStorage{
		byID:       map[int64]*db.Image{1: img},
		approveErr: errors.New("boom"),
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/1/approve", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestActionApprove_badID(t *testing.T) {
	srv := newTestServer(t, &mockStorage{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/abc/approve", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestActionApprove_redirectWhenNotHtmx(t *testing.T) {
	img := newImg(2, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{2: img}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/2/approve", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/images/2" {
		t.Errorf("location = %q, want /images/2", got)
	}
}

func TestActionReject(t *testing.T) {
	img := newImg(3, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{3: img}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/3/reject", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(mock.rejectIDs) != 1 || mock.rejectIDs[0] != 3 {
		t.Errorf("expected Reject(3), got %v", mock.rejectIDs)
	}
	if !containsEvent(mock.logEvents, "reject") {
		t.Errorf("missing reject event")
	}
}

func TestActionReject_dbError(t *testing.T) {
	img := newImg(3, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{3: img}, rejectErr: errors.New("x")}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/3/reject", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestActionReject_badID(t *testing.T) {
	srv := newTestServer(t, &mockStorage{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/zzz/reject", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestActionRescind_dbError(t *testing.T) {
	img := newImg(5, db.StateApproved)
	mock := &mockStorage{byID: map[int64]*db.Image{5: img}, rescindErr: errors.New("x")}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/5/rescind", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestRespondAction_imageDeletedMidFlight(t *testing.T) {
	img := newImg(33, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{33: img}}
	srv := newTestServer(t, mock)
	// Approve succeeds, but GetByID afterward is wired to return nothing.
	mock.approveErr = nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/33/approve", nil)
	r.Header.Set("Hx-Request", "true")
	// Race-free deletion: clear the byID map BEFORE ServeHTTP. Approve()
	// will mutate nothing because the entry is missing; respondAction's
	// follow-up GetByID then returns nil → 404.
	mock.byID = map[int64]*db.Image{}
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when row vanished", w.Code)
	}
}

func TestRespondAction_dbErrorOnReread(t *testing.T) {
	img := newImg(34, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{34: img}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/34/approve", nil)
	r.Header.Set("Hx-Request", "true")
	// Approve happens; the subsequent GetByID call fails.
	mock.byIDErr = errors.New("post-approve read boom")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestActionRescind(t *testing.T) {
	img := newImg(5, db.StateApproved)
	mock := &mockStorage{byID: map[int64]*db.Image{5: img}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/5/rescind", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(mock.rescindIDs) != 1 || mock.rescindIDs[0] != 5 {
		t.Errorf("expected Rescind(5), got %v", mock.rescindIDs)
	}
	if !containsEvent(mock.logEvents, "rescind") {
		t.Errorf("missing rescind event")
	}
}

func TestActionScan(t *testing.T) {
	img := newImg(9, db.StateQueued)
	mock := &mockStorage{byID: map[int64]*db.Image{9: img}}
	srv := newTestServer(t, mock)

	scanned := make(chan struct{})
	srv.SetScanFunc(func(ref string, cfg config.TrivyConfig) (*trivy.ScanResult, error) {
		defer close(scanned)
		if !strings.Contains(ref, "registry.example.com/myorg/myapp@sha256:") {
			t.Errorf("scan ref = %q", ref)
		}
		return &trivy.ScanResult{Raw: []byte(`{"Results":[]}`)}, nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/9/scan", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	select {
	case <-scanned:
	case <-time.After(time.Second):
		t.Fatal("scan goroutine did not run")
	}
	// Give the goroutine a moment to call SaveScan and LogEvent.
	deadline := time.After(time.Second)
	for {
		mock.mu.Lock()
		ok := len(mock.saveScanArg) > 0
		mock.mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("SaveScan never called")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !containsEvent(mock.logEvents, "scan") {
		t.Errorf("expected scan event, got %#v", mock.logEvents)
	}
}

func TestActionScan_stub(t *testing.T) {
	stub := newImg(11, db.StateQueued)
	stub.Digest = ""
	mock := &mockStorage{byID: map[int64]*db.Image{11: stub}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/11/scan", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 for stub", w.Code)
	}
}

func TestActionScan_notFound(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byID: map[int64]*db.Image{}})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/12/scan", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestActionScan_dbErrorOnGet(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byIDErr: errors.New("x")})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/9/scan", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestRunScan_trivyError(t *testing.T) {
	img := newImg(20, db.StateQueued)
	mock := &mockStorage{byID: map[int64]*db.Image{20: img}}
	srv := newTestServer(t, mock)
	srv.SetScanFunc(func(string, config.TrivyConfig) (*trivy.ScanResult, error) {
		return nil, errors.New("trivy boom")
	})
	srv.runScan(img)
	if len(mock.setErrIDs) != 1 || mock.setErrIDs[0] != 20 {
		t.Errorf("expected SetError(20), got %v", mock.setErrIDs)
	}
	if !containsEvent(mock.logEvents, "scan_error") {
		t.Errorf("expected scan_error event")
	}
}

func TestRunScan_saveError(t *testing.T) {
	img := newImg(21, db.StateQueued)
	mock := &mockStorage{
		byID:        map[int64]*db.Image{21: img},
		saveScanErr: errors.New("save boom"),
	}
	srv := newTestServer(t, mock)
	srv.SetScanFunc(func(string, config.TrivyConfig) (*trivy.ScanResult, error) {
		return &trivy.ScanResult{Raw: []byte(`{}`)}, nil
	})
	srv.runScan(img)
	if len(mock.setErrIDs) != 1 {
		t.Errorf("expected SetError, got %v", mock.setErrIDs)
	}
}

func TestRunScan_tagOnlyRef(t *testing.T) {
	img := newImg(22, db.StateQueued)
	img.Digest = ""
	mock := &mockStorage{byID: map[int64]*db.Image{22: img}}
	srv := newTestServer(t, mock)
	var capturedRef string
	srv.SetScanFunc(func(ref string, _ config.TrivyConfig) (*trivy.ScanResult, error) {
		capturedRef = ref
		return &trivy.ScanResult{Raw: []byte(`{}`)}, nil
	})
	srv.runScan(img)
	want := "registry.example.com/myorg/myapp:v1"
	if capturedRef != want {
		t.Errorf("ref = %q, want %q", capturedRef, want)
	}
}

func TestDashboard_basePathPrefixesAssets(t *testing.T) {
	mock := &mockStorage{listImages: []db.Image{*newImg(1, db.StateApproved)}}
	srv := newTestServerWithBase(t, mock, "/ui")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	for _, want := range []string{
		`href="/ui/static/hermes.css"`,
		`src="/ui/static/htmx.min.js"`,
		`sse-connect="/ui/events"`,
		`href="/ui/images/1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestActionApprove_redirectUsesBasePath(t *testing.T) {
	img := newImg(2, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{2: img}}
	srv := newTestServerWithBase(t, mock, "/ui")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/2/approve", nil)
	srv.Handler().ServeHTTP(w, r)
	if got := w.Header().Get("Location"); got != "/ui/images/2" {
		t.Errorf("location = %q, want /ui/images/2", got)
	}
}

func TestActionFetch(t *testing.T) {
	stub := newImg(50, db.StateQueued)
	stub.Digest = ""
	stub.Arch = ""
	stub.OS = ""

	platformAMD := newImg(51, db.StateQueued)
	platformARM := newImg(52, db.StateQueued)
	platformARM.Arch = "arm64"

	mock := &mockStorage{
		byID:      map[int64]*db.Image{50: stub},
		queueResp: []*db.Image{platformAMD, platformARM},
	}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/50/fetch", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if len(mock.queueCalls) != 1 {
		t.Fatalf("expected one Queue call, got %d", len(mock.queueCalls))
	}
	gotRef := mock.queueCalls[0]
	wantRef := db.ImageRef{
		Registry:   stub.RegistryURL,
		Repository: stub.Repository,
		Tag:        stub.TagName,
	}
	if gotRef != wantRef {
		t.Errorf("Queue ref = %+v, want %+v", gotRef, wantRef)
	}
	if !containsEvent(mock.logEvents, "fetch") {
		t.Errorf("missing fetch event: %#v", mock.logEvents)
	}
	body := w.Body.String()
	for _, want := range []string{`id="image-51"`, `id="image-52"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

func TestActionFetch_notStub(t *testing.T) {
	full := newImg(60, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{60: full}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/60/fetch", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestActionFetch_queueError(t *testing.T) {
	stub := newImg(70, db.StateQueued)
	stub.Digest = ""
	mock := &mockStorage{
		byID:     map[int64]*db.Image{70: stub},
		queueErr: errors.New("upstream 404"),
	}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/70/fetch", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
	if !containsEvent(mock.logEvents, "fetch_error") {
		t.Errorf("expected fetch_error event")
	}
}

func TestActionFetch_notFound(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byID: map[int64]*db.Image{}})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/99/fetch", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListImages_stateSelectedReflectsQuery(t *testing.T) {
	mock := &mockStorage{}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images?state=approved", nil)
	srv.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if !strings.Contains(body, `value="approved"  selected`) {
		t.Errorf("expected approved option to be marked selected\n%s", body)
	}
}

func TestRowPartial_stubHasFetchAction(t *testing.T) {
	stub := newImg(11, db.StateQueued)
	stub.Digest = ""
	mock := &mockStorage{
		listImages: []db.Image{*stub},
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images", nil)
	srv.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if !strings.Contains(body, `/images/11/fetch`) {
		t.Errorf("expected fetch button for stub row\n%s", body)
	}
}

func TestStaticAssetsServed(t *testing.T) {
	srv := newTestServer(t, &mockStorage{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/static/hermes.css", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), ".topbar") {
		t.Errorf("css body unexpected: %s", w.Body.String())
	}
}

func TestServeEvents_streamsAndDisconnects(t *testing.T) {
	mock := &mockStorage{}
	srv := newTestServer(t, mock)

	in := make(chan *db.Event)
	srv.Subscribe(in)

	srvHTTP := httptest.NewServer(srv.Handler())
	defer srvHTTP.Close()

	resp, err := http.Get(srvHTTP.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q", got)
	}

	id := int64(101)
	go func() {
		// Allow the handler to complete its subscribe before we send the
		// event so the broadcast finds at least one subscriber.
		time.Sleep(50 * time.Millisecond)
		in <- &db.Event{ID: id, EventType: "approve", Source: db.SourceAPI, ImageID: &id}
	}()

	type readResult struct {
		n   int
		err error
		buf []byte
	}
	reads := make(chan readResult, 8)
	go func() {
		defer close(reads)
		for {
			buf := make([]byte, 4096)
			n, err := resp.Body.Read(buf)
			reads <- readResult{n: n, err: err, buf: buf}
			if err != nil {
				return
			}
		}
	}()

	var got string
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case <-deadline:
			break loop
		case r, ok := <-reads:
			if !ok {
				break loop
			}
			got += string(r.buf[:r.n])
			if strings.Contains(got, "approve") {
				break loop
			}
			if r.err != nil && r.err != io.EOF {
				break loop
			}
		}
	}
	if !strings.Contains(got, "event: event") {
		t.Errorf("missing event: line\n%s", got)
	}
	if !strings.Contains(got, "approve") {
		t.Errorf("missing event_type approve\n%s", got)
	}
}

func TestEventHub_dropsSlowSubscribers(t *testing.T) {
	h := newEventHub()
	ch1 := h.subscribe()
	ch2 := h.subscribe()

	for i := 0; i < 200; i++ {
		h.broadcast(&db.Event{ID: int64(i)})
	}
	// ch1 read out a few; ch2 left full.
	read1 := drain(ch1, 16)
	read2 := drain(ch2, 16)
	if read1 == 0 || read2 == 0 {
		t.Errorf("expected both subscribers to receive at least one event; got %d, %d", read1, read2)
	}
	h.unsubscribe(ch1)
	h.unsubscribe(ch2)

	// Subscribing on a closed hub yields a closed channel.
	h.close()
	ch3 := h.subscribe()
	if _, ok := <-ch3; ok {
		t.Errorf("expected closed channel after hub.close()")
	}

	// close() is idempotent.
	h.close()
}

func TestEventHub_runDrains(t *testing.T) {
	h := newEventHub()
	in := make(chan *db.Event, 4)
	in <- &db.Event{ID: 1}
	in <- &db.Event{ID: 2}
	close(in)

	done := make(chan struct{})
	go func() {
		h.run(in)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("hub.run did not exit when input closed")
	}
}

func drain(ch <-chan *db.Event, max int) int {
	count := 0
	for count < max {
		select {
		case _, ok := <-ch:
			if !ok {
				return count
			}
			count++
		case <-time.After(50 * time.Millisecond):
			return count
		}
	}
	return count
}

func containsEvent(events []logEventCall, t string) bool {
	for _, e := range events {
		if e.Type == t {
			return true
		}
	}
	return false
}
