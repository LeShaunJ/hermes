// Package api implements the hermes OCI Distribution gateway server.
//
// The server acts as a full reverse-proxy gateway for OCI Distribution
// registries, enforcing image approval policy before forwarding requests.
//
// Routes:
//
//	GET  /v2/
//	    Returns 200 with Docker-Distribution-API-Version to signal a v2-capable
//	    registry.
//
//	*   /v2/<registry>/<repo>/manifests/<ref>
//	    Manifest requests.  Approved images are proxied/redirected to upstream.
//	    Rejected images return 403 DENIED.  Unknown/unapproved images return
//	    401 UNAUTHORIZED with a WWW-Authenticate challenge pointing through the
//	    /ident/ token proxy, and are stub-registered for operator review.
//
//	*   /v2/<registry>/...  (non-manifest paths)
//	    Blobs, tag lists, and other OCI sub-paths are forwarded unconditionally
//	    to the upstream registry (proxy or 307 redirect per cfg.Server.Redirect).
//
//	*   /ident/<registry><path>
//	    Token-acquisition proxy.  Requests are forwarded verbatim to
//	    https://<registry><path> so the Docker client can obtain bearer tokens
//	    through hermes without direct access to the upstream auth endpoint.
//
//	GET /healthz
//	    Liveness probe — returns "ok\n".
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
)

var logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)

// Server is the hermes OCI gateway server.
type Server struct {
	db  *db.DB
	cfg *config.Config
	mux *http.ServeMux
}

// New creates a Server and registers all routes.
func New(database *db.DB, cfg *config.Config) *Server {
	s := &Server{
		db:  database,
		cfg: cfg,
		mux: http.NewServeMux(),
	}
	s.mux.HandleFunc("/v2/", s.serveOCI)
	s.mux.HandleFunc("/v2", s.serveOCI)
	s.mux.HandleFunc("/ident/", s.serveIdent)
	s.mux.HandleFunc("GET /healthz", s.healthz)
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	logger.Printf("hermes gateway listening on %s", s.cfg.Server.Addr)
	return http.ListenAndServe(s.cfg.Server.Addr, s.mux)
}

// ── OCI handler ───────────────────────────────────────────────────────────────

func (s *Server) serveOCI(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := r.URL.Path

	// /v2 or /v2/ root — signal this is a v2-capable registry.
	if path == "/v2" || path == "/v2/" {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}

	p, err := parseV2Path(path)
	if err != nil {
		s.writeOCIError(w, http.StatusBadRequest, "UNSUPPORTED", err.Error())
		return
	}

	// Non-manifest paths (blobs, tag lists, etc.) — proxy/redirect unconditionally.
	if p.Kind == refKindOther {
		// Upstream path: strip "/v2/<registry>" prefix, keep "/v2/..." structure.
		registryPrefix := "/v2/" + p.Registry
		upstreamPath := "/v2" + path[len(registryPrefix):]
		s.proxyOrRedirect(w, r, p.Registry, upstreamPath)
		return
	}

	// Manifest request — check approval status.
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
		logger.Printf("ERROR db lookup %s/%s — %v", p.Registry, p.Repository, err)
		s.writeOCIError(w, http.StatusInternalServerError, "UNKNOWN", "internal error")
		return
	}

	if img != nil {
		// Approved — proxy/redirect to upstream using the pinned digest ref.
		ref := img.Digest
		if ref == "" {
			ref = p.Tag
		}
		_ = s.db.LogEvent(&img.ID, db.SourceAPI, "validate_approved", map[string]interface{}{
			"registry":   p.Registry,
			"repository": p.Repository,
			"tag":        p.Tag,
			"digest":     p.Digest,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		s.proxyOrRedirect(w, r, p.Registry, "/v2/"+p.Repository+"/manifests/"+ref)
		return
	}

	// Check if rejected.
	if p.Tag != "" {
		var rejected *db.Image
		rejected, err = s.db.GetRejected(p.Registry, p.Repository, p.Tag)
		if err != nil {
			logger.Printf("WARN rejected lookup %s/%s:%s — %v", p.Registry, p.Repository, p.Tag, err)
		}
		if rejected != nil {
			_ = s.db.LogEvent(&rejected.ID, db.SourceAPI, "validate_rejected", map[string]interface{}{
				"registry":   p.Registry,
				"repository": p.Repository,
				"tag":        p.Tag,
				"digest":     p.Digest,
				"latency_ms": time.Since(start).Milliseconds(),
			})
			s.writeOCIError(w, http.StatusForbidden, "DENIED", "image has been rejected")
			return
		}
	}

	// Unknown / not yet approved — stub-register the tag and return 401.
	var queuedID *int64
	if p.Tag != "" {
		ref := db.ImageRef{Registry: p.Registry, Repository: p.Repository, Tag: p.Tag}
		if qErr := s.db.QueueStub(ref); qErr != nil {
			logger.Printf("WARN queue stub %s/%s:%s — %v", p.Registry, p.Repository, p.Tag, qErr)
		}
	}

	_ = s.db.LogEvent(queuedID, db.SourceAPI, "validate_denied", map[string]interface{}{
		"registry":   p.Registry,
		"repository": p.Repository,
		"tag":        p.Tag,
		"digest":     p.Digest,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	// Build WWW-Authenticate challenge by probing the upstream registry.
	if wwwAuth := s.upstreamChallenge(p.Registry); wwwAuth != "" {
		w.Header().Set("WWW-Authenticate", s.rewriteRealm(wwwAuth))
	}
	s.writeOCIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}

// upstreamChallenge probes GET https://<registry>/v2/ and returns the
// WWW-Authenticate header from the upstream's 401 response.
// Returns an empty string if the probe fails or returns no challenge.
func (s *Server) upstreamChallenge(registry string) string {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://" + registry + "/v2/")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return resp.Header.Get("WWW-Authenticate")
}

// rewriteRealm replaces realm="https?://host/path" in a WWW-Authenticate
// header so the Docker client routes token requests through /ident/.
var realmRe = regexp.MustCompile(`realm="(https?://[^"]+)"`)

func (s *Server) rewriteRealm(wwwAuth string) string {
	return realmRe.ReplaceAllStringFunc(wwwAuth, func(match string) string {
		sub := realmRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		origURL := sub[1]
		// Strip scheme, build /ident/<host+path> through server URL.
		noScheme := strings.TrimPrefix(strings.TrimPrefix(origURL, "https://"), "http://")
		return fmt.Sprintf(`realm="%s/ident/%s"`, s.cfg.Server.URL, noScheme)
	})
}

// ── identity proxy ────────────────────────────────────────────────────────────

// serveIdent proxies token-acquisition requests to the upstream registry auth
// endpoint.  URL format: /ident/<registry>/<path>?<query>
func (s *Server) serveIdent(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/ident/")
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		http.Error(w, "bad ident path: expected /ident/<registry>/<path>", http.StatusBadRequest)
		return
	}
	registry := rest[:slashIdx]
	upstreamPath := rest[slashIdx:] // starts with /

	target, err := url.Parse("https://" + registry)
	if err != nil {
		http.Error(w, "bad registry in ident path: "+err.Error(), http.StatusBadRequest)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = registry
		req.URL.Path = upstreamPath
		req.Host = registry
	}
	proxy.ServeHTTP(w, r)
}

// ── proxy / redirect ──────────────────────────────────────────────────────────

// proxyOrRedirect either reverse-proxies the request to the upstream registry
// or sends an HTTP 307 redirect, depending on cfg.Server.Redirect.
// WWW-Authenticate realm headers in proxied responses are rewritten through /ident/.
func (s *Server) proxyOrRedirect(w http.ResponseWriter, r *http.Request, registry, upstreamPath string) {
	if s.cfg.Server.Redirect {
		dest := "https://" + registry + upstreamPath
		if r.URL.RawQuery != "" {
			dest += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, dest, http.StatusTemporaryRedirect)
		return
	}

	target, _ := url.Parse("https://" + registry)
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.URL.Path = upstreamPath
		req.Host = registry
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
			resp.Header.Set("WWW-Authenticate", s.rewriteRealm(wwwAuth))
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

// ── OCI error response ────────────────────────────────────────────────────────

type ociError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ociErrorResponse struct {
	Errors []ociError `json:"errors"`
}

func (s *Server) writeOCIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ociErrorResponse{
		Errors: []ociError{{Code: code, Message: message}},
	})
}

// ── health ────────────────────────────────────────────────────────────────────

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "ok")
}

// ── path parsing ──────────────────────────────────────────────────────────────

type refKind int

const (
	refKindTag         refKind = iota // /manifests/<tag>
	refKindDigest                     // /manifests/<digest>  ("sha256:…")
	refKindTagAndDigest               // /manifests/<tag>@<digest>
	refKindOther                      // any other /v2/… path
)

type parsedPath struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Kind       refKind
}

// parseV2Path extracts registry, repository, and reference information from a
// /v2/<registry>/<repo>/manifests/<ref> URL path.
//
// Paths without a /manifests/ component return refKindOther with Registry set.
func parseV2Path(path string) (parsedPath, error) {
	const prefix = "/v2/"
	if !strings.HasPrefix(path, prefix) {
		return parsedPath{}, errors.New("expected /v2/ path prefix")
	}

	rest := path[len(prefix):] // "<registry>/<repo>/manifests/<ref>" or other

	// Extract registry (first path segment).
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return parsedPath{Kind: refKindOther, Registry: rest}, nil
	}
	registry := rest[:slashIdx]

	const sep = "/manifests/"
	manifIdx := strings.Index(rest, sep)
	if manifIdx < 0 {
		// No /manifests/ component — non-manifest path.
		return parsedPath{Kind: refKindOther, Registry: registry}, nil
	}

	// Everything before /manifests/ is "<registry>/<repo>"
	regRepo := rest[:manifIdx]
	reference := rest[manifIdx+len(sep):]

	repoSlashIdx := strings.Index(regRepo, "/")
	if repoSlashIdx < 0 {
		return parsedPath{}, errors.New("expected /v2/<registry>/<repo>/manifests/…")
	}
	repo := regRepo[repoSlashIdx+1:]

	if registry == "" || repo == "" || reference == "" {
		return parsedPath{}, errors.New("registry, repository, and reference must be non-empty")
	}

	p := parsedPath{Registry: registry, Repository: repo}

	if atIdx := strings.Index(reference, "@"); atIdx >= 0 {
		p.Tag = reference[:atIdx]
		p.Digest = reference[atIdx+1:]
		p.Kind = refKindTagAndDigest
	} else if strings.HasPrefix(reference, "sha256:") || strings.HasPrefix(reference, "sha512:") {
		p.Digest = reference
		p.Kind = refKindDigest
	} else {
		p.Tag = reference
		p.Kind = refKindTag
	}

	return p, nil
}
