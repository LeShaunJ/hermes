// Package api implements the hermes HTTP API server.
//
// The server exposes:
//
//	GET /validate/v2/<registry>/<repo>/manifests/<tag>
//	    nginx auth_request target.  Extracts registry, repo, and reference from
//	    the URL path.  Handles three reference forms:
//	      - <tag>          → authorised if an approved image exists for that tag
//	      - <digest>       → authorised if an approved image with that digest exists
//	      - <tag>@<digest> → authorised if an approved image matches both
//	    Any other /validate/v2/... path is auto-authorised (blobs, tags lists…).
//	    Returns 200 + X-Hermes-Image-Uri if authorised; 401 otherwise.
//	    Queues unknown images so they can be scanned via the CLI later.
//
//	GET /healthz
//	    Liveness probe — returns "ok\n".
package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/leshaunj/hermes/internal/db"
	"github.com/leshaunj/hermes/internal/oci"
)

var logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)

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
	// /validate/v2/ catches all paths that start with /validate/v2/
	s.mux.HandleFunc("GET /validate/v2/", s.validate)
	s.mux.HandleFunc("GET /validate/v2", s.validate)
	s.mux.HandleFunc("GET /healthz", s.healthz)
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	logger.Printf("hermes API listening on %s", s.addr)
	return http.ListenAndServe(s.addr, s.mux)
}

// ── reference kinds ───────────────────────────────────────────────────────────

type refKind int

const (
	refKindTag         refKind = iota // /manifests/<tag>
	refKindDigest                     // /manifests/<digest>  ("sha256:…")
	refKindTagAndDigest               // /manifests/<tag>@<digest>
	refKindOther                      // any other /validate/v2/… path
)

type parsedPath struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Kind       refKind
}

// ── validate ──────────────────────────────────────────────────────────────────

// validate is the nginx auth_request target.
//
// URL format:  GET /validate/v2/<registry>/<repository>/manifests/<reference>
//
// Responses:
//   - 200 + X-Hermes-Image-Uri   → authorised
//   - 401                         → image not approved (queued for review if new)
//   - 400                         → malformed path
//   - 500                         → internal error
func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	p, err := parseValidatePath(r.URL.Path)
	if err != nil {
		msg := fmt.Sprintf("%s (got: %s)", err.Error(), r.URL.Path)
		logger.Printf("ERROR %s", msg)
		w.Header().Set("X-Hermes-Error-Msg", msg)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Non-manifest paths (blobs, tag lists, etc.) are always authorised.
	if p.Kind == refKindOther {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Look up the image.
	var img *db.Image
	switch p.Kind {
	case refKindTag:
		img, err = s.db.GetApproved(p.Registry, p.Repository, p.Tag)
	case refKindDigest:
		img, err = s.db.GetApprovedByDigest(p.Registry, p.Repository, p.Digest)
	case refKindTagAndDigest:
		img, err = s.db.GetApprovedByTagAndDigest(p.Registry, p.Repository, p.Tag, p.Digest)
	}
	if err != nil {
		logger.Printf("ERROR validate db lookup %s/%s ref=%s — %v", p.Registry, p.Repository, r.URL.Path, err)
		_ = s.db.LogEvent(nil, db.SourceAPI, "validate_error", map[string]interface{}{
			"registry":   p.Registry,
			"repository": p.Repository,
			"tag":        p.Tag,
			"digest":     p.Digest,
			"error":      err.Error(),
			"latency_ms": time.Since(start).Milliseconds(),
		})
		w.Header().Set("X-Hermes-Error-Msg", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if img != nil {
		// Authorised — build the canonical image URI.
		imageURI := buildImageURI(p, img)
		w.Header().Set("X-Hermes-Image-Uri", imageURI)
		w.WriteHeader(http.StatusOK)

		_ = s.db.LogEvent(&img.ID, db.SourceAPI, "validate_approved", map[string]interface{}{
			"registry":   p.Registry,
			"repository": p.Repository,
			"tag":        p.Tag,
			"digest":     p.Digest,
			"image_uri":  imageURI,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		return
	}

	// Not approved — queue the image using the client's auth token so hermes
	// can fetch the manifest from the registry on behalf of the caller.
	ref := db.ImageRef{Registry: p.Registry, Repository: p.Repository, Tag: p.Tag}
	var queuedID *int64
	if p.Tag != "" {
		fetcher := oci.NewBearerClient(r.Header.Get("Authorization"))
		queued, qErr := s.db.Queue(ref, fetcher)
		if qErr != nil {
			logger.Printf("WARN validate queue %s/%s:%s — %v", p.Registry, p.Repository, p.Tag, qErr)
			w.Header().Set("X-Hermes-Error-Msg", "not approved")
		} else {
			w.Header().Set("X-Hermes-Error-Msg", "not approved, but queued for approval")
			if len(queued) > 0 {
				queuedID = &queued[0].ID
			}
		}
	} else {
		w.Header().Set("X-Hermes-Error-Msg", "not approved")
	}

	_ = s.db.LogEvent(queuedID, db.SourceAPI, "validate_denied", map[string]interface{}{
		"registry":   p.Registry,
		"repository": p.Repository,
		"tag":        p.Tag,
		"digest":     p.Digest,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	w.WriteHeader(http.StatusUnauthorized)
}

// buildImageURI constructs the X-Hermes-Image-Uri value.
func buildImageURI(p parsedPath, img *db.Image) string {
	ref := img.Digest
	switch {
	case p.Kind == refKindDigest:
		ref = p.Digest
	case p.Kind == refKindTagAndDigest:
		ref = p.Digest
	case ref == "":
		ref = p.Tag
	}
	return fmt.Sprintf("%s/v2/%s/manifests/%s", p.Registry, p.Repository, ref)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "ok")
}

// ── path parsing ──────────────────────────────────────────────────────────────

// parseValidatePath extracts registry, repository, and reference information
// from a /validate/v2/… URL path.
//
// Supported reference forms:
//
//	/validate/v2/<registry>/<repo>/manifests/<tag>
//	/validate/v2/<registry>/<repo>/manifests/<digest>
//	/validate/v2/<registry>/<repo>/manifests/<tag>@<digest>
//
// Any /validate/v2/… path that does not contain "/manifests/" returns
// refKindOther (auto-authorised).
func parseValidatePath(path string) (parsedPath, error) {
	const prefix = "/validate/v2"
	if !strings.HasPrefix(path, prefix) {
		return parsedPath{}, errors.New("bad request: expected /validate/v2 path prefix")
	}

	rest := path[len(prefix):]
	if rest == "" || rest == "/" {
		// Bare /validate/v2 or /validate/v2/ — auto-authorise.
		return parsedPath{Kind: refKindOther}, nil
	}

	// Strip leading slash and split off the registry.
	rest = strings.TrimPrefix(rest, "/")

	const sep = "/manifests/"
	manifIdx := strings.Index(rest, sep)
	if manifIdx < 0 {
		// No /manifests/ component — auto-authorise (blobs, tag lists, etc.)
		return parsedPath{Kind: refKindOther}, nil
	}

	// Everything before /manifests/ is "<registry>/<repo>"
	regRepo := rest[:manifIdx]
	reference := rest[manifIdx+len(sep):]

	slashIdx := strings.Index(regRepo, "/")
	if slashIdx < 0 {
		return parsedPath{}, errors.New("bad request: expected /validate/v2/<registry>/<repo>/manifests/…")
	}
	registry := regRepo[:slashIdx]
	repo := regRepo[slashIdx+1:]

	if registry == "" || repo == "" || reference == "" {
		return parsedPath{}, errors.New("bad request: registry, repository, and reference must be non-empty")
	}

	// Classify the reference.
	p := parsedPath{Registry: registry, Repository: repo}

	if atIdx := strings.Index(reference, "@"); atIdx >= 0 {
		// tag@digest
		p.Tag = reference[:atIdx]
		p.Digest = reference[atIdx+1:]
		p.Kind = refKindTagAndDigest
	} else if strings.HasPrefix(reference, "sha256:") || strings.HasPrefix(reference, "sha512:") {
		// bare digest
		p.Digest = reference
		p.Kind = refKindDigest
	} else {
		// plain tag
		p.Tag = reference
		p.Kind = refKindTag
	}

	return p, nil
}
