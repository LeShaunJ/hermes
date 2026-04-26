/*
Package ui implements the hermes operator web console.

The console is a server-rendered HTML interface that exposes the same
list / view / approve / reject / rescind / scan capabilities as the CLI,
backed by the same db.DB and emitting the same audit events.  It is
served by `hermes ui` on a separate listener so the OCI gateway port
can stay narrow and operators can firewall the console independently.

Routes:

	GET  /                          dashboard (state counts, recent events)
	GET  /images                    image table; htmx-driven filters
	GET  /images/{id}               image detail (manifest, scan report)
	POST /images/{id}/approve       set state -> approved (form: cache_url)
	POST /images/{id}/reject        set state -> rejected
	POST /images/{id}/rescind       set state -> rescinded
	POST /images/{id}/scan          kick a trivy scan in a goroutine
	GET  /events                    SSE stream of db.Event
	GET  /static/...                embedded htmx + CSS
	GET  /healthz                   liveness probe
*/
package ui

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
	"github.com/leshaunj/hermes/internal/trivy"
)

// storage is the subset of db.DB operations used by Server.
// *db.DB satisfies this interface automatically.
type storage interface {
	List(f db.ListFilter) ([]db.Image, error)
	ListRepos(f db.ListFilter) ([]db.RepoSummary, error)
	ListTagSets(registry, repository string, f db.ListFilter) ([]db.TagSet, error)
	GetByID(id int64) (*db.Image, error)
	Queue(ref db.ImageRef, fetcher db.Fetcher) ([]*db.Image, error)
	Approve(imageID int64, cacheRegistry string) error
	Reject(imageID int64) error
	Rescind(imageID int64) error
	SaveScan(imageID int64, scanReport json.RawMessage) (*db.Image, error)
	SetError(imageID int64) error
	LogEvent(imageID *int64, source db.EventSource, eventType string, details map[string]interface{}) error
}

// scanFunc runs a trivy scan; trivy.Scan is the production implementation,
// overridden in tests via SetScanFunc to avoid spawning real containers.
type scanFunc func(imageRef string, cfg config.TrivyConfig) (*trivy.ScanResult, error)

// Server is the hermes operator web console.
type Server struct {
	db      storage
	cfg     *config.Config
	mux     *http.ServeMux
	hub     *eventHub
	tmpl    *templates
	scan    scanFunc
	fetcher db.Fetcher
}

// New creates a Server and registers all routes.  Templates and static
// assets are loaded eagerly from the embedded FS so the constructor fails
// fast if they are malformed.
func New(database storage, cfg *config.Config) *Server {
	tmpl, err := loadTemplates(cfg.UI.BasePath)
	if err != nil {
		// loadTemplates only parses files baked into the binary, so a
		// failure here is a programming error, not a runtime condition.
		panic("ui: parse templates: " + err.Error())
	}

	s := &Server{
		db:      database,
		cfg:     cfg,
		mux:     http.NewServeMux(),
		hub:     newEventHub(),
		tmpl:    tmpl,
		scan:    trivy.Scan,
		fetcher: oci.NewDefaultClient(),
	}

	staticFS, err := fs.Sub(staticAssets, "static")
	if err != nil {
		panic("ui: sub static FS: " + err.Error())
	}

	s.mux.HandleFunc("GET /{$}", s.dashboard)
	s.mux.HandleFunc("GET /images", s.imageTree)
	s.mux.HandleFunc("GET /images/{id}", s.viewImage)
	s.mux.HandleFunc("GET /repos", s.listRepos)
	s.mux.HandleFunc("GET /repos/{registry}/{path...}", s.viewRepoOrTagSet)
	s.mux.HandleFunc("POST /images/{id}/approve", s.actionApprove)
	s.mux.HandleFunc("POST /images/{id}/reject", s.actionReject)
	s.mux.HandleFunc("POST /images/{id}/rescind", s.actionRescind)
	s.mux.HandleFunc("POST /images/{id}/scan", s.actionScan)
	s.mux.HandleFunc("POST /images/{id}/fetch", s.actionFetch)
	s.mux.HandleFunc("GET /events", s.serveEvents)
	s.mux.HandleFunc("GET /healthz", s.serveHealthz)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	slog.Info("hermes ui listening", "addr", s.cfg.UI.Addr)
	return http.ListenAndServe(s.cfg.UI.Addr, s.mux)
}

// Handler returns the server's HTTP handler so callers (e.g. tests) can
// mount the console on their own listener.
func (s *Server) Handler() http.Handler { return s.mux }

// Subscribe wires an external db.Event channel into the SSE hub.  Every
// event received is fanned out to every browser currently connected to
// /events.  The hub stops when the channel is closed.
func (s *Server) Subscribe(events <-chan *db.Event) {
	go s.hub.run(events)
}

// SetScanFunc overrides the trivy.Scan implementation used by the scan
// action handler.  Intended for tests that must not invoke real trivy.
func (s *Server) SetScanFunc(fn scanFunc) { s.scan = fn }

// SetFetcher overrides the OCI client used to fetch manifests when
// promoting a stub image.  Intended for tests that must not hit the
// network.
func (s *Server) SetFetcher(f db.Fetcher) { s.fetcher = f }

func (s *Server) serveHealthz(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok\n"))
}
