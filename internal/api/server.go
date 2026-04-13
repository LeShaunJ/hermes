/*
Package api implements the hermes OCI Distribution gateway server.

The server acts as a full reverse-proxy gateway for OCI Distribution
registries, enforcing image approval policy before forwarding requests.

Routes:

	GET  /v2/
		Returns 200 with Docker-Distribution-API-Version to signal a v2-capable
		registry.

	*   /v2/<registry>/<repo>/manifests/<ref>
		Manifest requests.  Approved images are proxied/redirected to upstream.
		Rejected images return 403 DENIED.  Unknown/unapproved images return
		401 UNAUTHORIZED with a WWW-Authenticate challenge pointing through the
		/ident/ token proxy, and are stub-registered for operator review.

	*   /v2/<registry>/...  (non-manifest paths)
		Blobs, tag lists, and other OCI sub-paths are forwarded unconditionally
		to the upstream registry (proxy or 307 redirect per cfg.Server.Redirect).

	*   /ident/<registry><path>
		Token-acquisition proxy.  Requests are forwarded verbatim to
		https://<registry><path> so the Docker client can obtain bearer tokens
		through hermes without direct access to the upstream auth endpoint.

	GET /healthz
		Liveness probe — returns "ok\n".
*/
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/leshaunj/hermes/internal/config"
	"github.com/leshaunj/hermes/internal/db"
)

// storage is the subset of db.DB operations used by Server.
// *db.DB satisfies this interface automatically.
type storage interface {
	GetApproved(registry, repository, tag string) (*db.Image, error)
	GetApprovedByDigest(registry, repository, digest string) (*db.Image, error)
	GetApprovedByTagAndDigest(registry, repository, tag, digest string) (*db.Image, error)
	GetRejected(registry, repository, tag string) (*db.Image, error)
	QueueStub(ref db.ImageRef) error
	AdoptTagByDigest(ref db.ImageRef, digest string) (bool, error)
	BlobAuthorized(registry, repository, digest string) (bool, error)
	LogEvent(imageID *int64, source db.EventSource, eventType string, details map[string]interface{}) error
}

// Server is the hermes OCI gateway server.
type Server struct {
	db  storage
	cfg *config.Config
	mux *http.ServeMux

	// challengeRetrieveFn overrides challengeRetrieve in tests to avoid
	// outbound HTTPS calls.
	challengeRetrieveFn func(registry, path string) string

	// transport overrides the HTTP transport used by the ident and
	// manifest/blob proxies in tests.  When non-nil, proxyOrRedirect uses
	// "http://" instead of "https://" for upstream URLs so tests can point
	// at an httptest backend.
	transport http.RoundTripper
}

// New creates a Server and registers all routes.
func New(database storage, cfg *config.Config) *Server {
	s := &Server{
		db:  database,
		cfg: cfg,
		mux: http.NewServeMux(),
	}
	s.mux.HandleFunc("/v2/", s.serveOCI)
	s.mux.HandleFunc("/v2", s.serveOCI)
	s.mux.HandleFunc("/ident/", s.serveIdent)
	s.mux.HandleFunc("/ident", s.serveIdent)
	s.mux.HandleFunc("GET /healthz", s.serveHealthz)
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	slog.Info("hermes gateway listening", "addr", s.cfg.Server.Addr)
	return http.ListenAndServe(s.cfg.Server.Addr, s.mux)
}

// ── OCI handler ───────────────────────────────────────────────────────────────

func (s *Server) serveOCI(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := r.URL.Path

	// /v2 or /v2/ root — signal this is a v2-capable registry.
	if path == "/v2" || path == "/v2/" {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s/ident\"", s.cfg.Server.URL))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	p, err := parseV2Path(path)
	if err != nil {
		s.writeOCIError(w, http.StatusBadRequest, "UNSUPPORTED", err.Error())
		return
	}

	// Non-manifest, non-blob paths (tag lists, uploads, catalog, etc.) — proxy/
	// redirect unconditionally.
	if p.Kind == refKindOther {
		// Upstream path: strip "/v2/<registry>" prefix, keep "/v2/..." structure.
		registryPrefix := "/v2/" + p.Registry
		upstreamPath := "/v2" + path[len(registryPrefix):]
		s.proxyOrRedirect(w, r, p.Registry, upstreamPath)
		return
	}

	// Blob downloads — only forward if the digest belongs to the config or one
	// of the layers of an approved image in the same repository.  This stops
	// clients from pulling arbitrary blobs through the gateway.
	if p.Kind == refKindBlob {
		s.serveBlob(w, r, p, start)
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
		slog.Error("db lookup", "registry", p.Registry, "repository", p.Repository, "err", err)
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
			slog.Warn("rejected lookup", "registry", p.Registry, "repository", p.Repository, "tag", p.Tag, "err", err)
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

	// Tag manifest miss — proxy the client's request to the upstream and
	// intercept the response.  The hook reads the upstream-returned
	// Docker-Content-Digest and either adopts the tag (alternate-tag case,
	// existing approved image at the same digest) or stub-registers it and
	// rewrites the response to 401 UNAUTHORIZED.  This reuses the client's
	// own bearer token so no server-side re-auth is required.
	if p.Kind == refKindTag {
		ref := db.ImageRef{Registry: p.Registry, Repository: p.Repository, Tag: p.Tag}
		hook := s.adoptTagResponseHook(ref, start)
		s.proxyOrRedirect(w, r, p.Registry, "/v2/"+p.Repository+"/manifests/"+p.Tag, hook)
		return
	}

	// Digest or tag+digest miss — no adoption path; stub-register if possible
	// and deny.
	var queuedID *int64
	if p.Tag != "" {
		ref := db.ImageRef{Registry: p.Registry, Repository: p.Repository, Tag: p.Tag}
		if qErr := s.db.QueueStub(ref); qErr != nil {
			slog.Warn("queue stub", "registry", p.Registry, "repository", p.Repository, "tag", p.Tag, "err", qErr)
		}
	}

	_ = s.db.LogEvent(queuedID, db.SourceAPI, "validate_denied", map[string]interface{}{
		"registry":   p.Registry,
		"repository": p.Repository,
		"tag":        p.Tag,
		"digest":     p.Digest,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	s.writeOCIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "approval required")
}

// adoptTagResponseHook returns a responseHook that inspects a manifest
// response returned by the upstream registry and either:
//
//   - adopts the tag when the upstream Docker-Content-Digest matches an
//     existing approved image in the same repository (alternate-tag case),
//     letting the response pass through unchanged; or
//   - stub-registers the tag and rewrites the response to a CNCF-format
//     401 UNAUTHORIZED error so the client never sees the raw manifest.
//
// Upstream non-success responses are also rewritten to 401 so hermes does
// not leak upstream errors (e.g. auth retries, redirects) to the client.
func (s *Server) adoptTagResponseHook(ref db.ImageRef, start time.Time) responseHook {
	return func(resp *http.Response) error {
		if resp.StatusCode == http.StatusOK {
			digest := resp.Header.Get("Docker-Content-Digest")
			if digest != "" {
				adopted, err := s.db.AdoptTagByDigest(ref, digest)
				if err != nil {
					slog.Warn("adopt tag", "registry", ref.Registry, "repository", ref.Repository, "tag", ref.Tag, "err", err)
				}
				if adopted {
					_ = s.db.LogEvent(nil, db.SourceAPI, "validate_adopted", map[string]interface{}{
						"registry":   ref.Registry,
						"repository": ref.Repository,
						"tag":        ref.Tag,
						"digest":     digest,
						"latency_ms": time.Since(start).Milliseconds(),
					})
					return nil
				}
			}
		}

		// Not adopted — stub-register and replace the response body with a
		// hermes-owned 401 so the approval workflow kicks in.
		if qErr := s.db.QueueStub(ref); qErr != nil {
			slog.Warn("queue stub", "registry", ref.Registry, "repository", ref.Repository, "tag", ref.Tag, "err", qErr)
		}
		_ = s.db.LogEvent(nil, db.SourceAPI, "validate_denied", map[string]interface{}{
			"registry":      ref.Registry,
			"repository":    ref.Repository,
			"tag":           ref.Tag,
			"upstream_code": resp.StatusCode,
			"latency_ms":    time.Since(start).Milliseconds(),
		})
		return rewriteResponseOCIError(resp, http.StatusUnauthorized, "UNAUTHORIZED", "approval required")
	}
}

// rewriteResponseOCIError replaces a proxied response body with a CNCF OCI
// error document and sets the appropriate headers.  Used by responseHooks
// that need to turn upstream content into a hermes-owned error.
func rewriteResponseOCIError(resp *http.Response, status int, code, message string) error {
	body, err := json.Marshal(ociErrorResponse{
		Errors: []ociError{{Code: code, Message: message}},
	})
	if err != nil {
		return err
	}
	// Drop upstream payload headers that no longer describe the body.
	resp.Header.Del("Docker-Content-Digest")
	resp.Header.Del("Etag")
	resp.Header.Del("Last-Modified")
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Docker-Distribution-API-Version", "registry/2.0")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.StatusCode = status
	resp.Status = http.StatusText(status)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// serveBlob authorizes a /v2/<registry>/<repo>/blobs/<digest> download against
// the database and either forwards it to the upstream registry or denies it.
func (s *Server) serveBlob(w http.ResponseWriter, r *http.Request, p parsedPath, start time.Time) {
	ok, err := s.db.BlobAuthorized(p.Registry, p.Repository, p.Digest)
	if err != nil {
		slog.Error("blob authz", "registry", p.Registry, "repository", p.Repository, "digest", p.Digest, "err", err)
		s.writeOCIError(w, http.StatusInternalServerError, "UNKNOWN", "internal error")
		return
	}
	if !ok {
		_ = s.db.LogEvent(nil, db.SourceAPI, "blob_denied", map[string]interface{}{
			"registry":   p.Registry,
			"repository": p.Repository,
			"digest":     p.Digest,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		s.writeOCIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "blob not part of an approved image")
		return
	}
	_ = s.db.LogEvent(nil, db.SourceAPI, "blob_approved", map[string]interface{}{
		"registry":   p.Registry,
		"repository": p.Repository,
		"digest":     p.Digest,
		"latency_ms": time.Since(start).Milliseconds(),
	})
	s.proxyOrRedirect(w, r, p.Registry, "/v2/"+p.Repository+"/blobs/"+p.Digest)
}

// challengeRetrieve probes GET https://<registry>/v2/<path> and returns the
// WWW-Authenticate header from the upstream's 401 response.
// Returns an empty string if the probe fails or returns no challenge.
func (s *Server) challengeRetrieve(registry string, path string) string {
	if s.challengeRetrieveFn != nil {
		return s.challengeRetrieveFn(registry, path)
	}
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://" + registry + "/v2/" + path)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("WWW-Authenticate")
}

// ── identity proxy ────────────────────────────────────────────────────────────

var scopeRe = regexp.MustCompile(`^repository:([^/]+)/(.+):pull$`)
var wwwAuthRe = regexp.MustCompile(`\b(\w+)="([^"]+)"`)

func challengeParse(header string, account string) string {
	matches := wwwAuthRe.FindAllStringSubmatch(header, -1)
	realm := ""
	query := ""
	delim := "?"

	if account != "" {
		query += delim + "account=" + account
		delim = "&"
	}

	for _, match := range matches {
		if len(match) > 2 {
			if match[1] == "realm" {
				realm = match[2]
			} else {
				query += delim + match[1] + "=" + match[2]
				delim = "&"
			}
		}
	}

	if realm == "" {
		return ""
	}

	return realm + query
}

// serveIdent proxies token-acquisition requests to the upstream registry auth
// endpoint.  URL format: /ident/<registry>/<path>?<query>
func (s *Server) serveIdent(w http.ResponseWriter, r *http.Request) {
	var sessionID *int64
	start := time.Now()
	query := r.URL.Query()

	scope, ok := query["scope"]
	if !ok {
		s.writeOCIError(w, http.StatusBadRequest, "UNSUPPORTED", "missing `scope=` paramter")
		return
	}

	account, ok := query["account"]
	if !ok {
		account = []string{""}
	}

	match := scopeRe.FindStringSubmatch(scope[0])
	if match == nil {
		s.writeOCIError(w, http.StatusBadRequest, "UNSUPPORTED", "malformed `scope=` paramter")
		return
	}
	slog.Debug("ident scope match", "match", match)

	wwwAuth := s.challengeRetrieve(match[1], match[2]+"/tags/list")
	slog.Debug("ident challenge retrieved", "www_authenticate", wwwAuth)

	challenge := challengeParse(wwwAuth, account[0])
	if challenge == "" {
		s.writeOCIError(w, http.StatusFailedDependency, "UNSUPPORTED", "could not retrieve auth challenge")
		return
	}
	slog.Debug("ident challenge parsed", "challenge", challenge)

	target, err := url.Parse(challenge)
	if err != nil {
		s.writeOCIError(w, http.StatusFailedDependency, "UNSUPPORTED", "bad registry in ident path: "+err.Error())
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	if s.transport != nil {
		proxy.Transport = s.transport
	}
	proxy.Director = func(req *http.Request) {
		if s.transport == nil {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = target.Scheme
		}
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		req.URL.RawQuery = target.RawQuery
		req.Host = target.Host
		req.Header.Set("X-Forwarded-Proto", "https")

		_ = s.db.LogEvent(sessionID, db.SourceAPI, "token_proxied", map[string]interface{}{
			"downstream": r.URL.String(),
			"upstream":   req.URL.String(),
			"latency_ms": time.Since(start).Milliseconds(),
		})
	}
	proxy.ModifyResponse = func(res *http.Response) error {
		res.Header.Set("Docker-Distribution-API-Version", "registry/2.0")
		return nil
	}
	proxy.ServeHTTP(w, r)
}

// ── proxy / redirect ──────────────────────────────────────────────────────────

// responseHook is invoked from httputil.ReverseProxy.ModifyResponse, in order,
// so callers can inspect or rewrite the upstream response before it reaches
// the client.  Returning an error aborts the proxy write with a 502.
type responseHook func(resp *http.Response) error

// proxyOrRedirect either reverse-proxies the request to the upstream registry
// or sends an HTTP 307 redirect, depending on cfg.Server.Redirect.  If any
// responseHook is supplied the redirect fast-path is skipped — hooks can only
// run when hermes actually sees the upstream response, so proxy mode is forced.
// Hooks run after the default Docker-Distribution-API-Version header is set.
func (s *Server) proxyOrRedirect(w http.ResponseWriter, r *http.Request, registry, path string, hooks ...responseHook) {
	var sessionID *int64
	start := time.Now()

	if s.cfg.Server.Redirect && len(hooks) == 0 {
		dest := "https://" + registry + path
		if r.URL.RawQuery != "" {
			dest += "?" + r.URL.RawQuery
		}
		_ = s.db.LogEvent(sessionID, db.SourceAPI, "content_redirected", map[string]interface{}{
			"downstream": r.URL.String(),
			"upstream":   dest,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		http.Redirect(w, r, dest, http.StatusTemporaryRedirect)
		return
	}

	scheme := "https"
	if s.transport != nil {
		// Tests inject an HTTP transport pointing at an httptest backend.
		scheme = "http"
	}
	target, _ := url.Parse(scheme + "://" + registry)
	proxy := httputil.NewSingleHostReverseProxy(target)
	if s.transport != nil {
		proxy.Transport = s.transport
	}
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.URL.Path = path
		req.Host = registry
		req.Header.Set("X-Forwarded-Proto", "https")

		_ = s.db.LogEvent(sessionID, db.SourceAPI, "content_proxied", map[string]interface{}{
			"downstream": r.URL.String(),
			"upstream":   req.URL.String(),
			"latency_ms": time.Since(start).Milliseconds(),
		})
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Docker-Distribution-API-Version", "registry/2.0")
		for _, h := range hooks {
			if err := h(resp); err != nil {
				return err
			}
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

func (s *Server) serveHealthz(w http.ResponseWriter, _ *http.Request) {
	_, _ = fmt.Fprintln(w, "ok")
}

// ── path parsing ──────────────────────────────────────────────────────────────

type refKind int

const (
	refKindTag          refKind = iota // /manifests/<tag>
	refKindDigest                      // /manifests/<digest>  ("sha256:…")
	refKindTagAndDigest                // /manifests/<tag>@<digest>
	refKindBlob                        // /blobs/<digest> (downloads, not uploads)
	refKindOther                       // any other /v2/… path
)

type parsedPath struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Kind       refKind
}

// parseV2Path extracts registry, repository, and reference information from a
// /v2/<registry>/<repo>/manifests/<ref> or /v2/<registry>/<repo>/blobs/<digest>
// URL path.
//
// Paths without a /manifests/ or /blobs/<digest> component return refKindOther
// with Registry set.  Blob upload paths (/blobs/uploads/...) are also reported
// as refKindOther so they pass through unconditionally.
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

	// Recognise blob downloads — /blobs/sha256:… or /blobs/sha512:… — and
	// extract the digest so the gateway can gatekeep them.  Upload paths
	// (/blobs/uploads/…) and any other shape pass through as refKindOther.
	const blobSep = "/blobs/"
	if blobIdx := strings.Index(rest, blobSep); blobIdx >= 0 {
		regRepo := rest[:blobIdx]
		reference := rest[blobIdx+len(blobSep):]
		repoSlashIdx := strings.Index(regRepo, "/")
		if repoSlashIdx >= 0 && (strings.HasPrefix(reference, "sha256:") || strings.HasPrefix(reference, "sha512:")) {
			repo := regRepo[repoSlashIdx+1:]
			if repo != "" {
				return parsedPath{
					Kind:       refKindBlob,
					Registry:   registry,
					Repository: repo,
					Digest:     reference,
				}, nil
			}
		}
	}

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
