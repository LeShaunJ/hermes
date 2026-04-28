//go:build e2e

// Package uie2e drives the hermes operator console through a real
// headless Chromium so the JS layer (htmx, idiomorph, the SSE client,
// tree-state restoration, action-dedup) is exercised against the
// server-rendered HTML it actually receives.  The unit tests in
// internal/ui can only assert on response bodies; bugs that live in the
// browser (e.g. an htmx.swap call that silently no-ops because the
// morph extension never gets dispatched) slip past them.  These tests
// catch those.
//
// Run with: go test -tags e2e ./test/e2e/ui/...
//
// Browser discovery:
//  1. $HERMES_TEST_CHROME (explicit override)
//  2. Playwright cache under /opt/pw-browsers/* (sandbox + most CI images)
//  3. PATH lookup for google-chrome / chromium / chrome-headless-shell
//
// Tests skip cleanly if none of the above resolves.
package uie2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/trivy"
	"github.com/leshaunj/hermes/internal/ui"
)

// sseHookScript wraps EventSource so tests can wait for the SSE
// channel to be live before pushing events into the hub.  Installed
// via Page.addScriptToEvaluateOnNewDocument so it runs before the
// page's own scripts — guaranteeing every EventSource construction is
// captured.  Reads via window.__hermesSSEReady; total constructions
// via window.__hermesSSECount.
const sseHookScript = `(function () {
	var Native = window.EventSource;
	if (!Native || Native.__hermesHooked) return;
	function Wrapped(url, opts) {
		var es = new Native(url, opts);
		window.__hermesSSECount = (window.__hermesSSECount || 0) + 1;
		es.addEventListener("open", function () { window.__hermesSSEReady = true; });
		return es;
	}
	Wrapped.prototype = Native.prototype;
	Wrapped.__hermesHooked = true;
	Wrapped.CONNECTING = Native.CONNECTING;
	Wrapped.OPEN = Native.OPEN;
	Wrapped.CLOSED = Native.CLOSED;
	window.EventSource = Wrapped;
})()`

// findChrome returns a path to a Chromium-family binary chromedp can
// drive, or skips the test if none is available.
func findChrome(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("HERMES_TEST_CHROME"); v != "" {
		return v
	}
	for _, glob := range []string{
		"/opt/pw-browsers/chromium_headless_shell-*/chrome-linux/headless_shell",
		"/opt/pw-browsers/chromium-*/chrome-linux/chrome",
	} {
		matches, _ := filepath.Glob(glob)
		for _, m := range matches {
			if _, err := os.Stat(m); err == nil {
				return m
			}
		}
	}
	for _, name := range []string{
		"google-chrome", "google-chrome-stable",
		"chromium", "chromium-browser",
		"chrome-headless-shell", "headless_shell",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("no chromium-family binary found; set HERMES_TEST_CHROME or install chromium")
	return ""
}

// browser launches a headless Chromium and returns a chromedp context
// bound to it.  The EventSource probe (sseHookScript) is registered
// before any page script so tests can synchronise on SSE readiness.
// Cleanup is registered against t.
func browser(t *testing.T) context.Context {
	t.Helper()
	bin := findChrome(t)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(cancelAlloc)

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	t.Cleanup(cancelCtx)

	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(sseHookScript).Do(ctx)
			return err
		}),
	); err != nil {
		t.Fatalf("launch chromium: %v", err)
	}
	return ctx
}

// stack bundles a UI server, a backing mock storage, and the SSE event
// channel.  The mock auto-pushes a db.Event onto the channel for every
// LogEvent call — mirroring production where Postgres NOTIFY fires when
// hermes inserts an audit row — so a simulated scan completion travels
// the same path the browser sees from a real scan.
type stack struct {
	t      *testing.T
	srv    *httptest.Server
	store  *mockStore
	uisrv  *ui.Server
	events chan *db.Event
	once   sync.Once
}

func newStack(t *testing.T) *stack {
	t.Helper()

	cfg := &config.Config{}
	cfg.UI.Addr = ":0"
	cfg.UI.URL = "http://localhost"

	events := make(chan *db.Event, 16)
	store := newMockStore(events)

	uisrv := ui.New(store, cfg)
	uisrv.Subscribe(events)

	httpsrv := httptest.NewServer(uisrv.Handler())
	t.Cleanup(httpsrv.Close)

	s := &stack{
		t:      t,
		srv:    httpsrv,
		store:  store,
		uisrv:  uisrv,
		events: events,
	}
	t.Cleanup(func() { s.once.Do(func() { close(events) }) })
	return s
}

// SetScanFunc rewires the trivy scan invocation.  fn receives the image
// ref the production scan path would pass to trivy and returns the raw
// JSON report bytes (or an error).
func (s *stack) SetScanFunc(fn func(ref string) ([]byte, error)) {
	s.t.Helper()
	s.uisrv.SetScanFunc(func(ref string, _ config.TrivyConfig) (*trivy.ScanResult, error) {
		raw, err := fn(ref)
		if err != nil {
			return nil, err
		}
		return &trivy.ScanResult{Raw: raw}, nil
	})
}

// URL is the test server's base URL.
func (s *stack) URL() string { return s.srv.URL }

// Insert adds an image to the in-memory store.
func (s *stack) Insert(img *db.Image) { s.store.Insert(img) }

// ── mock storage ──────────────────────────────────────────────────────

// mockStore is the minimal storage implementation chromedp tests need.
// It keeps a small in-memory image table and forwards every LogEvent
// onto the SSE channel it was constructed with — so the action handler
// inside ui.Server doesn't need to know it's running against a mock.
type mockStore struct {
	mu     sync.Mutex
	images map[int64]*db.Image
	order  []int64

	events chan<- *db.Event
}

func newMockStore(events chan<- *db.Event) *mockStore {
	return &mockStore{images: make(map[int64]*db.Image), events: events}
}

// Insert adds img to the store, preserving FIFO order for List.
func (m *mockStore) Insert(img *db.Image) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if img.CreatedAt.IsZero() {
		img.CreatedAt = time.Now()
	}
	if img.UpdatedAt.IsZero() {
		img.UpdatedAt = img.CreatedAt
	}
	if _, exists := m.images[img.ID]; !exists {
		m.order = append(m.order, img.ID)
	}
	m.images[img.ID] = img
}

func (m *mockStore) snapshot() []db.Image {
	out := make([]db.Image, 0, len(m.order))
	for _, id := range m.order {
		if img := m.images[id]; img != nil {
			out = append(out, *img)
		}
	}
	return out
}

func (m *mockStore) List(_ db.ListFilter) ([]db.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshot(), nil
}

func (m *mockStore) ListTagSets(_, _ string, _ db.ListFilter) ([]db.TagSet, error) {
	// Not exercised by the current tests — return empty so a level-2
	// row refresh renders zero children if it ever fires.
	return nil, nil
}

func (m *mockStore) GetByID(id int64) (*db.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	img, ok := m.images[id]
	if !ok {
		return nil, nil
	}
	cp := *img
	return &cp, nil
}

func (m *mockStore) Queue(_ db.ImageRef, _ db.Fetcher) ([]*db.Image, error) {
	return nil, errors.New("Queue not implemented in ui e2e mock")
}

func (m *mockStore) Approve(id int64, cache string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if img, ok := m.images[id]; ok && img != nil {
		img.State = db.StateApproved
		img.CacheRegistry = cache
		img.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStore) Reject(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if img, ok := m.images[id]; ok && img != nil {
		img.State = db.StateRejected
		img.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStore) Rescind(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if img, ok := m.images[id]; ok && img != nil {
		img.State = db.StateRescinded
		img.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStore) SaveScan(id int64, report json.RawMessage) (*db.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	img, ok := m.images[id]
	if !ok || img == nil {
		return nil, errors.New("not found")
	}
	img.State = db.StateScanned
	img.ScanReport = report
	img.UpdatedAt = time.Now()
	cp := *img
	return &cp, nil
}

func (m *mockStore) SetError(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if img, ok := m.images[id]; ok && img != nil {
		img.State = db.StateErrored
		img.UpdatedAt = time.Now()
	}
	return nil
}

// LogEvent records the audit row and fans it out onto the SSE channel
// the way Postgres NOTIFY does in production.  Non-blocking — if the
// channel is full, drop the notification rather than stalling the
// caller (the eventHub already drops slow subscribers).
func (m *mockStore) LogEvent(imgID *int64, source db.EventSource, t string, details map[string]interface{}) error {
	body, _ := json.Marshal(details)
	ev := &db.Event{
		ImageID:   imgID,
		Source:    source,
		EventType: t,
		Details:   string(body),
		CreatedAt: time.Now(),
	}
	select {
	case m.events <- ev:
	default:
	}
	return nil
}
