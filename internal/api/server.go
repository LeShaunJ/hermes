// Package api implements the hermes HTTP API server.
//
// The server exposes:
//
//	GET /validate/v2/<registry>/<repo>/manifests/<tag>
//	    nginx auth_request target.  Extracts registry, repo, and tag from the
//	    URL path.  Returns 200 + X-HERMES-IMAGE-URI if approved; 401 otherwise.
//	    Queues unknown images so they can be scanned via the CLI later.
//
//	GET /healthz
//	    Liveness probe — returns "ok\n".
package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/leshaunj/hermes/internal/db"
)

// Server is the hermes HTTP API server.
type Server struct {
	db   *db.DB
	addr string
	mux  *http.ServeMux
}

// New creates a Server and registers all routes.
func New(database *db.DB, addr string) *Server {
	s := &Server{
		db:   database,
		addr: addr,
		mux:  http.NewServeMux(),
	}
	// /validate/ catches all paths that start with /validate/
	s.mux.HandleFunc("GET /validate/", s.validate)
	s.mux.HandleFunc("GET /healthz", s.healthz)
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	log.Printf("hermes API listening on %s", s.addr)
	return http.ListenAndServe(s.addr, s.mux)
}

// validate is the nginx auth_request target.
//
// URL format:  GET /validate/v2/<registry>/<repository>/manifests/<tag>
//
// The registry is the first path component after /validate/.
// The remainder is a standard OCI Distribution API path.
//
// Responses:
//   - 200 + X-HERMES-IMAGE-URI   → image is approved
//   - 401                         → image not approved (queued for review if new)
//   - 400                         → malformed path
//   - 500                         → internal error
func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	registry, repo, tag, ok := parseValidatePath(r.URL.Path)
	if !ok {
		http.Error(w, "bad request: expected /validate/v2/<registry>/<repository>/manifests/<tag>", http.StatusBadRequest)
		return
	}

	ref := db.ImageRef{Registry: registry, Repository: repo, Tag: tag}

	// Look up the image.
	img, err := s.db.GetApproved(registry, repo, tag)
	if err != nil {
		log.Printf("ERROR validate db lookup %s/%s:%s — %v", registry, repo, tag, err)
		_ = s.db.LogEvent(nil, db.SourceAPI, "validate_error", map[string]interface{}{
			"registry":   registry,
			"repository": repo,
			"tag":        tag,
			"error":      err.Error(),
			"latency_ms": time.Since(start).Milliseconds(),
		})
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if img != nil {
		// Approved — build the redirect URI.
		// Use the pinned digest if available so nginx proxies the exact layer.
		ref := img.Digest
		if ref == "" {
			ref = tag
		}
		imageURI := fmt.Sprintf("%s/v2/%s/manifests/%s", registry, repo, ref)
		w.Header().Set("X-Hermes-Image-Uri", imageURI)
		w.WriteHeader(http.StatusOK)

		_ = s.db.LogEvent(&img.ID, db.SourceAPI, "validate_approved", map[string]interface{}{
			"registry":   registry,
			"repository": repo,
			"tag":        tag,
			"digest":     img.Digest,
			"image_uri":  imageURI,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		return
	}

	// Not approved — queue the image so it can be reviewed via the CLI.
	queued, qErr := s.db.Queue(ref)
	if qErr != nil {
		log.Printf("WARN validate queue %s/%s:%s — %v", registry, repo, tag, qErr)
	}

	var imageID *int64
	if queued != nil {
		imageID = &queued.ID
	}
	_ = s.db.LogEvent(imageID, db.SourceAPI, "validate_denied", map[string]interface{}{
		"registry":   registry,
		"repository": repo,
		"tag":        tag,
		"queued":     qErr == nil,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	http.Error(w, "not approved", http.StatusUnauthorized)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "ok")
}

// parseValidatePath extracts (registry, repository, tag) from:
//
//	/validate/v2/<registry>/<repository>/manifests/<tag>
//
// The repository may contain slashes (e.g. "org/team/app").
func parseValidatePath(path string) (registry, repo, tag string, ok bool) {
	const prefix = "/validate/"
	if !strings.HasPrefix(path, prefix) {
		return
	}
	rest := path[len(prefix):]

	// Remainder must be v2/<repo>/manifests/<tag>
	const v2prefix = "v2/"
	if !strings.HasPrefix(rest, v2prefix) {
		return
	}
	rest = rest[len(v2prefix):]

	// First component is the registry.
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return
	}
	registry = rest[:slashIdx]
	rest = rest[slashIdx+1:]

	const sep = "/manifests/"
	idx := strings.LastIndex(rest, sep)
	if idx < 0 {
		return
	}
	repo = rest[:idx]
	tag = rest[idx+len(sep):]

	if registry == "" || repo == "" || tag == "" {
		return
	}
	ok = true
	return
}
