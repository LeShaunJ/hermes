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

	listTagSetsResp []db.TagSet
	listTagSetsErr  error
	listTagSetsArgs []listTagSetsArg

	byID    map[int64]*db.Image
	byIDErr error

	queueResp  []*db.Image
	queueErr   error
	queueCalls []db.ImageRef
	queueGate  chan struct{} // when non-nil, Queue blocks on this channel

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

type listTagSetsArg struct {
	Registry string
	Repo     string
	Filter   db.ListFilter
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
func (m *mockStorage) ListTagSets(registry, repository string, f db.ListFilter) ([]db.TagSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listTagSetsArgs = append(m.listTagSetsArgs, listTagSetsArg{Registry: registry, Repo: repository, Filter: f})
	return m.listTagSetsResp, m.listTagSetsErr
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
	gate := m.queueGate
	m.queueCalls = append(m.queueCalls, ref)
	err := m.queueErr
	resp := m.queueResp
	m.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return resp, err
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

func TestImageTree_dedupsAliasedTagsToOneRowPerPlatform(t *testing.T) {
	// `latest` and `3.23.4` both point at sha256:topAA which has 2 platform
	// images.  `tag_image_rows` returns 2 tags × 2 images = 4 rows, but the
	// rendered tree must show one row per platform (id=image-7 once,
	// id=image-8 once) with both aliases preserved on the parent tag-set.
	mk := func(id int64, tag, arch string) db.Image {
		return db.Image{
			ID:          id,
			RegistryURL: "registry.example.com",
			Repository:  "myorg/myapp",
			TagName:     tag,
			TagDigest:   "sha256:topAA",
			Digest:      "sha256:plat" + arch,
			Arch:        arch,
			OS:          "linux",
			State:       db.StateApproved,
			UpdatedAt:   time.Now(),
		}
	}
	mock := &mockStorage{listImages: []db.Image{
		mk(7, "latest", "amd64"),
		mk(8, "latest", "arm64"),
		mk(7, "3.23.4", "amd64"),
		mk(8, "3.23.4", "arm64"),
	}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if got := strings.Count(body, `id="image-7"`); got != 1 {
		t.Errorf("image-7 rows = %d, want 1\n%s", got, body)
	}
	if got := strings.Count(body, `id="image-8"`); got != 1 {
		t.Errorf("image-8 rows = %d, want 1", got)
	}
	for _, tag := range []string{"latest", "3.23.4"} {
		if !strings.Contains(body, `<code class="tag">`+tag+`</code>`) {
			t.Errorf("missing alias %q", tag)
		}
	}
	if !strings.Contains(body, `approved: <strong>2</strong>`) {
		t.Errorf("expected dedup'd approved=2 on level-2 row, body lacked it\n%s", body)
	}
}

func TestViewTagSet_dedupsAliasedRows(t *testing.T) {
	mk := func(id int64, tag, arch string) db.Image {
		return db.Image{
			ID:          id,
			RegistryURL: "docker.io",
			Repository:  "library/alpine",
			TagName:     tag,
			TagDigest:   "sha256:topAA",
			Digest:      "sha256:plat" + arch,
			Arch:        arch,
			OS:          "linux",
			State:       db.StateScanned,
			UpdatedAt:   time.Now(),
		}
	}
	mock := &mockStorage{listImages: []db.Image{
		mk(7, "latest", "amd64"),
		mk(7, "3.23.4", "amd64"),
		mk(8, "latest", "arm64"),
		mk(8, "3.23.4", "arm64"),
	}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos/docker.io/library/alpine/tags/sha256:topAA", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if got := strings.Count(body, `id="image-7"`); got != 1 {
		t.Errorf("image-7 rows = %d, want 1", got)
	}
	if got := strings.Count(body, `id="image-8"`); got != 1 {
		t.Errorf("image-8 rows = %d, want 1", got)
	}
}

func TestViewRepo_dedupsAliasedRows(t *testing.T) {
	mk := func(id int64, tag, arch string) db.Image {
		return db.Image{
			ID:          id,
			RegistryURL: "docker.io",
			Repository:  "library/alpine",
			TagName:     tag,
			TagDigest:   "sha256:topAA",
			Digest:      "sha256:plat" + arch,
			Arch:        arch,
			OS:          "linux",
			State:       db.StateApproved,
			UpdatedAt:   time.Now(),
		}
	}
	mock := &mockStorage{
		listTagSetsResp: []db.TagSet{{
			TagDigest:  "sha256:topAA",
			Tags:       []string{"3.23.4", "latest"},
			ImageCount: 2,
			UpdatedAt:  time.Now(),
			States:     map[string]int{"approved": 2},
		}},
		listImages: []db.Image{
			mk(7, "latest", "amd64"),
			mk(7, "3.23.4", "amd64"),
			mk(8, "latest", "arm64"),
			mk(8, "3.23.4", "arm64"),
		},
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos/docker.io/library/alpine", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if got := strings.Count(body, `id="image-7"`); got != 1 {
		t.Errorf("image-7 rows = %d, want 1", got)
	}
	if got := strings.Count(body, `id="image-8"`); got != 1 {
		t.Errorf("image-8 rows = %d, want 1", got)
	}
}

func TestImageTree_groupsByRepoAndTagDigest(t *testing.T) {
	// Two tags pointing at the same tag_digest collapse to one tag-set
	// containing two per-platform images.  A third stub falls into the
	// empty-digest bucket of the same repo.
	stub := newImg(13, db.StateQueued)
	stub.Digest = ""
	stub.TagDigest = ""
	stub.Arch = ""
	stub.OS = ""
	stub.TagName = "edge"

	a := newImg(7, db.StateApproved)
	a.TagName = "latest"
	a.TagDigest = "sha256:topAA"
	a.Digest = "sha256:platAMD"
	a.Arch = "amd64"

	b := newImg(8, db.StateScanned)
	b.TagName = "v1.2"
	b.TagDigest = "sha256:topAA"
	b.Digest = "sha256:platARM"
	b.Arch = "arm64"

	mock := &mockStorage{listImages: []db.Image{*stub, *a, *b}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`row-repo:registry.example.com|myorg/myapp`,
		`expand (2)`, // two tag-sets in the repo (one resolved, one stub)
		`code class="tag">latest</code>`,
		`code class="tag">v1.2</code>`,
		`unresolved`, // stub bucket label
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
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
	// Wait for the goroutine to finish all the way through LogEvent.
	// Polling on saveScanArg races the LogEvent that follows; wait on
	// the event slice directly so the assertion is deterministic.
	deadline := time.After(time.Second)
	for {
		mock.mu.Lock()
		ok := containsEvent(mock.logEvents, "scan")
		mock.mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("scan event never recorded; logEvents=%#v", mock.logEvents)
		case <-time.After(10 * time.Millisecond):
		}
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
		`src="/ui/static/idiomorph-ext.min.js"`,
		`data-base="/ui"`,
		`hx-ext="morph"`,
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

	// Gate the goroutine so the synchronous response can be rendered
	// (and asserted) before s.fetching is cleared by the goroutine's
	// defer.  Without this the test would race the goroutine — fast
	// mock Queue clears the busy state before respondAction renders.
	gate := make(chan struct{})
	mock := &mockStorage{
		byID:      map[int64]*db.Image{50: stub},
		queueResp: []*db.Image{platformAMD, platformARM},
		queueGate: gate,
	}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/50/fetch", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `class="busy fetching"`) || !strings.Contains(body, "disabled") {
		t.Errorf("expected fetching/disabled button, body=%s", body)
	}

	// Release the goroutine, then wait for the eventual fetch event.
	close(gate)
	deadline := time.After(time.Second)
	for {
		mock.mu.Lock()
		ok := containsEvent(mock.logEvents, "fetch")
		mock.mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("fetch event never recorded; logEvents=%#v", mock.logEvents)
		case <-time.After(10 * time.Millisecond):
		}
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
}

func TestActionFetch_marksRowAsFetching(t *testing.T) {
	stub := newImg(53, db.StateQueued)
	stub.Digest = ""
	stub.Arch = ""
	stub.OS = ""
	mock := &mockStorage{
		byID: map[int64]*db.Image{53: stub},
	}
	srv := newTestServer(t, mock)

	// Block the goroutine inside Queue until the test releases the
	// gate, so the synchronous HTTP response has to come back with
	// the "fetching…" button regardless of how fast Queue would be.
	gate := make(chan struct{})
	mock.queueGate = gate
	mock.queueResp = []*db.Image{newImg(54, db.StateQueued)}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/53/fetch", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `class="busy fetching"`) {
		t.Errorf("expected fetching pseudo-state, body=%s", body)
	}
	if !strings.Contains(body, `aria-busy="true"`) {
		t.Errorf("expected aria-busy on fetching button, body=%s", body)
	}
	close(gate)
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

func TestViewRepo_pathDecoding(t *testing.T) {
	mock := &mockStorage{
		listTagSetsResp: []db.TagSet{{
			TagDigest:  "sha256:topAA",
			Tags:       []string{"3.23.4", "latest"},
			ImageCount: 8,
			UpdatedAt:  time.Now(),
			States:     map[string]int{"queued": 8},
		}},
		listImages: []db.Image{
			{
				ID: 1, RegistryURL: "docker.io", Repository: "library/alpine",
				TagName: "latest", TagDigest: "sha256:topAA",
				Digest: "sha256:platAMD", State: db.StateQueued,
				UpdatedAt: time.Now(),
			},
		},
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos/docker.io/library/alpine", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(mock.listTagSetsArgs) != 1 {
		t.Fatalf("ListTagSets calls = %d, want 1", len(mock.listTagSetsArgs))
	}
	got := mock.listTagSetsArgs[0]
	if got.Registry != "docker.io" || got.Repo != "library/alpine" {
		t.Errorf("ListTagSets args = (%q, %q), want (docker.io, library/alpine)", got.Registry, got.Repo)
	}
	body := w.Body.String()
	if !strings.Contains(body, "code class=\"tag\">latest</code>") {
		t.Errorf("body missing latest tag chip\n%s", body)
	}
}

func TestViewTagSet_digestRoundtrip(t *testing.T) {
	mock := &mockStorage{
		listImages: []db.Image{
			{
				ID: 99, RegistryURL: "docker.io", Repository: "library/alpine",
				TagName: "latest", TagDigest: "sha256:topAA",
				Digest: "sha256:platAMD", Arch: "amd64", OS: "linux",
				State: db.StateScanned, UpdatedAt: time.Now(),
			},
		},
	}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos/docker.io/library/alpine/tags/sha256:topAA", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "image-99") {
		t.Errorf("body missing image-99 row\n%s", body)
	}
	if !strings.Contains(body, "sha256:topAA") {
		t.Errorf("body missing the full top-level digest\n%s", body)
	}
}

func TestViewTagSet_notFound(t *testing.T) {
	srv := newTestServer(t, &mockStorage{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos/docker.io/library/alpine/tags/sha256:none", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestViewImage_rendersCVEAndSBOMTables(t *testing.T) {
	report := json.RawMessage(`{
		"Results": [{
			"Target": "alpine 3.23.4 (alpine 3.23.4)",
			"Type": "alpine",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2024-1234",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1",
				"FixedVersion": "1.1.2",
				"Severity": "HIGH",
				"Title": "Heap buffer overflow"
			}],
			"Packages": [
				{"Name": "musl", "Version": "1.2.5"},
				{"Name": "openssl", "Version": "1.1.1"}
			]
		}]
	}`)
	img := newImg(42, db.StateScanned)
	img.ScanReport = report
	mock := &mockStorage{byID: map[int64]*db.Image{42: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/42", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`Vulnerabilities (1)`,
		`Packages (2)`,
		`CVE-2024-1234`,
		`Heap buffer overflow`,
		`nvd.nist.gov/vuln/detail/CVE-2024-1234`,
		`<code>musl</code>`,
		`<code>openssl</code>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestActionSwap_preservesIndentFromHeader(t *testing.T) {
	img := newImg(11, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{11: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/11/approve", nil)
	r.Header.Set("Hx-Request", "true")
	r.Header.Set("Hx-Indent", "2")
	r.Header.Set("Hx-Group", "tg-ts:registry.example.com|myorg/myapp|sha256:topdigest")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `class="tree-row tree-lvl-3"`) {
		t.Errorf("expected tree-lvl-3 class, body=%s", body)
	}
	if !strings.Contains(body, `data-group="tg-ts:`) {
		t.Errorf("expected data-group attr, body=%s", body)
	}
	if strings.Contains(body, " hidden") {
		t.Errorf("swap response must not be hidden, body=%s", body)
	}
}

func TestActionScan_marksRowAsScanning(t *testing.T) {
	img := newImg(12, db.StateQueued)
	mock := &mockStorage{byID: map[int64]*db.Image{12: img}}
	srv := newTestServer(t, mock)

	// Block the scan goroutine by giving the scan func a long-running
	// closure.  The HTTP response must come back immediately with the
	// row partial in its scanning pseudo-state, regardless of whether
	// the scan has finished.
	gate := make(chan struct{})
	srv.SetScanFunc(func(string, config.TrivyConfig) (*trivy.ScanResult, error) {
		<-gate
		return &trivy.ScanResult{Raw: []byte(`{}`)}, nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/12/scan", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `class="busy scanning"`) || !strings.Contains(body, `disabled`) {
		t.Errorf("expected scanning/disabled button, body=%s", body)
	}
	if !strings.Contains(body, `aria-busy="true"`) {
		t.Errorf("expected aria-busy on scanning button, body=%s", body)
	}
	close(gate)
}

func TestViewImageRow_renders(t *testing.T) {
	img := newImg(13, db.StateApproved)
	mock := &mockStorage{byID: map[int64]*db.Image{13: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/13/row", nil)
	r.Header.Set("Hx-Indent", "1")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `id="image-13"`) {
		t.Errorf("missing row id\n%s", body)
	}
	if !strings.Contains(body, "tree-lvl-2") {
		t.Errorf("expected indent 1 → tree-lvl-2 class\n%s", body)
	}
}

func TestViewImageRow_notFound(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byID: map[int64]*db.Image{}})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/999/row", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestViewImageDetail(t *testing.T) {
	img := newImg(77, db.StateScanned)
	img.Manifest = json.RawMessage(`{"schemaVersion":2}`)
	mock := &mockStorage{byID: map[int64]*db.Image{77: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/77/detail", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "<html") {
		t.Errorf("detail partial must not include <html>, body=%s", body)
	}
	for _, want := range []string{
		`Vulnerability summary`,
		`schemaVersion`,
		`data-clipboard="`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

func TestActionFromDetailPage_returnsDetailPartial(t *testing.T) {
	img := newImg(78, db.StateScanned)
	mock := &mockStorage{byID: map[int64]*db.Image{78: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/78/approve", nil)
	r.Header.Set("Hx-Request", "true")
	r.Header.Set("Hx-Target", "image-detail")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// Detail partial: meta block with state badge, vulnerability summary
	// header, and the action buttons re-rendered for the new state.
	for _, want := range []string{
		`Vulnerability summary`,
		`state-approved`,
		`hx-target="#image-detail"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, `<tr id="image-78"`) {
		t.Errorf("detail-target swap should not include a <tr>, body=%s", body)
	}
}

func TestViewRepoTbody_partial(t *testing.T) {
	mock := &mockStorage{listImages: []db.Image{
		{ID: 1, RegistryURL: "docker.io", Repository: "library/alpine",
			TagName: "latest", TagDigest: "sha256:topAA",
			Digest: "sha256:platAMD", Arch: "amd64", OS: "linux",
			State: db.StateApproved, UpdatedAt: time.Now()},
	}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos/docker.io/library/alpine/tbody", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`<tbody class="repo-tbody"`,
		`id="tbody-repo:docker.io|library/alpine"`,
		`row-repo:docker.io|library/alpine`,
		`approved: <strong>1</strong>`,
		`data-refresh="/repos/docker.io/library/alpine/tbody"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "<html") {
		t.Errorf("partial response must not include layout html")
	}
}

func TestViewTagSetRow_partial(t *testing.T) {
	mock := &mockStorage{listImages: []db.Image{
		{ID: 1, RegistryURL: "docker.io", Repository: "library/alpine",
			TagName: "latest", TagDigest: "sha256:topAA",
			Digest: "sha256:platAMD", Arch: "amd64", OS: "linux",
			State: db.StateApproved, UpdatedAt: time.Now()},
	}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos/docker.io/library/alpine/tags/sha256:topAA/row", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`row-ts:docker.io|library/alpine|sha256:topAA`,
		`approved: <strong>1</strong>`,
		`data-refresh="/repos/docker.io/library/alpine/tags/sha256:topAA/row"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

func TestImageRow_includesCopyDigestButton(t *testing.T) {
	img := newImg(81, db.StateApproved)
	mock := &mockStorage{byID: map[int64]*db.Image{81: img}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/81/row", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	want := `data-clipboard="` + img.Digest + `"`
	if !strings.Contains(body, want) {
		t.Errorf("expected copy button %q, body=%s", want, body)
	}
}

func TestViewImage_stubIdRedirectsToList(t *testing.T) {
	srv := newTestServer(t, &mockStorage{byID: map[int64]*db.Image{}})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/0", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); !strings.Contains(got, "/images?state=queued") {
		t.Errorf("location = %q, want /images?state=queued", got)
	}
}

func TestRow_stubDoesNotLinkToImageZero(t *testing.T) {
	stub := newImg(0, db.StateQueued)
	stub.Digest = ""
	stub.TagDigest = ""
	stub.Arch = ""
	stub.OS = ""
	mock := &mockStorage{listImages: []db.Image{*stub}}
	srv := newTestServer(t, mock)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images", nil)
	srv.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if strings.Contains(body, `href="/images/0"`) {
		t.Errorf("stub row must not link to /images/0\n%s", body)
	}
	if !strings.Contains(body, "(stub)") {
		t.Errorf("stub row must indicate stub\n%s", body)
	}
}

func TestActionFetch_stubIDLogsNullEventID(t *testing.T) {
	stub := newImg(0, db.StateQueued)
	stub.Digest = ""
	stub.TagDigest = ""
	stub.Arch = ""
	stub.OS = ""
	mock := &mockStorage{
		byID:      map[int64]*db.Image{0: stub},
		queueResp: []*db.Image{newImg(101, db.StateQueued)},
	}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/0/fetch", nil)
	r.Header.Set("Hx-Request", "true")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}

	// Wait for the goroutine to log the fetch event.
	deadline := time.After(time.Second)
	for {
		mock.mu.Lock()
		ok := containsEvent(mock.logEvents, "fetch")
		mock.mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("fetch event never recorded")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// The synthetic id=0 must NOT be propagated as image_id, otherwise
	// Postgres' FK constraint rejects the insert (events.image_id has
	// to point at a real images.id row).
	for _, ev := range mock.logEvents {
		if ev.Type == "fetch" && ev.ImageID != nil {
			t.Errorf("fetch event ImageID = %v, want nil for stub", *ev.ImageID)
		}
	}
}

func TestActionsHTML_levelRefreshDoesNotDropScanningSibling(t *testing.T) {
	// Reproduce the race: image #1 has a scan in flight, image #2 fires
	// a state event that triggers a level-2 ancestor refresh.  The
	// refreshed level-2 row must still render image #1 as "scanning…"
	// because s.scanning is consulted via the template func.
	a := newImg(1, db.StateQueued)
	a.TagDigest = "sha256:topAA"
	b := newImg(2, db.StateApproved)
	b.TagDigest = "sha256:topAA"
	mock := &mockStorage{listImages: []db.Image{*a, *b}}
	srv := newTestServer(t, mock)

	// Mark #1 as scanning before we render the level-2 row.
	srv.scanning.Store(int64(1), struct{}{})
	defer srv.scanning.Delete(int64(1))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"/repos/registry.example.com/myorg/myapp/tags/sha256:topAA/row", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `class="busy scanning"`) {
		t.Errorf("expected sibling scanning state preserved, body=%s", body)
	}
}

func TestActionScan_fromDetailPage_returnsDetailPartialWithBusyState(t *testing.T) {
	img := newImg(33, db.StateQueued)
	mock := &mockStorage{byID: map[int64]*db.Image{33: img}}
	srv := newTestServer(t, mock)

	gate := make(chan struct{})
	srv.SetScanFunc(func(string, config.TrivyConfig) (*trivy.ScanResult, error) {
		<-gate
		return &trivy.ScanResult{Raw: []byte(`{}`)}, nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/33/scan", nil)
	r.Header.Set("Hx-Request", "true")
	r.Header.Set("Hx-Target", "image-detail")
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	body := w.Body.String()
	// Detail partial fingerprint:
	if !strings.Contains(body, "Vulnerability summary") {
		t.Errorf("expected detail partial body\n%s", body)
	}
	// Busy state must be reflected in the actions section even though
	// the response goes through the detail-target path.
	if !strings.Contains(body, `class="busy scanning"`) {
		t.Errorf("expected scanning button on detail swap\n%s", body)
	}
	close(gate)
}

func TestActionResponse_includesOOBStateCells(t *testing.T) {
	img := newImg(91, db.StateScanned)
	img.TagDigest = "sha256:topAA"
	mock := &mockStorage{
		byID:       map[int64]*db.Image{91: img},
		listImages: []db.Image{*img},
	}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/91/approve", nil)
	r.Header.Set("Hx-Request", "true")
	r.Header.Set("Hx-Current-URL", "http://localhost/images")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`id="image-91"`, // primary swap
		`id="state-ts:registry.example.com|myorg/myapp|sha256:topAA"`,
		`id="state-repo:registry.example.com|myorg/myapp"`,
		`hx-swap-oob="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

func TestActionResponse_filterMismatchEmitsDeleteOOB(t *testing.T) {
	// Image is currently `queued`; after approve it becomes
	// `approved`, which should disappear from a /images?state=queued
	// view via an OOB delete directive.
	img := newImg(92, db.StateQueued)
	mock := &mockStorage{
		byID:       map[int64]*db.Image{92: img},
		listImages: []db.Image{*img},
	}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/images/92/approve", nil)
	r.Header.Set("Hx-Request", "true")
	r.Header.Set("Hx-Current-URL", "http://localhost/images?state=queued")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `hx-swap-oob="delete:#image-92"`) {
		t.Errorf("expected delete OOB directive\n%s", body)
	}
	// The full row partial must NOT be in the body, since the row
	// shouldn't appear under the queued filter anymore.
	if strings.Contains(body, `<tr id="image-92" class="`) {
		t.Errorf("row should not be rendered when filter rejects it\n%s", body)
	}
}

func TestViewImageRow_filterMismatchReturns410(t *testing.T) {
	img := newImg(93, db.StateApproved)
	mock := &mockStorage{byID: map[int64]*db.Image{93: img}}
	srv := newTestServer(t, mock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/images/93/row", nil)
	r.Header.Set("Hx-Current-URL", "http://localhost/images?state=queued")
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want 410 (current filter excludes the row)", w.Code)
	}
}

func TestReposRouteRemoved(t *testing.T) {
	srv := newTestServer(t, &mockStorage{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/repos", nil)
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("/repos should be 404, got %d", w.Code)
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
