package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/leshaunj/hermes/internal/db"
)

// Server is the HTTP API server.
type Server struct {
	db   *db.DB
	addr string
	mux  *http.ServeMux
}

// New creates a new Server and registers all routes.
func New(database *db.DB, addr string) *Server {
	s := &Server{
		db:   database,
		addr: addr,
		mux:  http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /validate_image", s.validateImage)
	s.mux.HandleFunc("GET /healthz", s.healthz)
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	log.Printf("hermes API listening on %s", s.addr)
	return http.ListenAndServe(s.addr, s.mux)
}

// validateImage is the nginx auth_request target.
//
// It accepts the image coordinates in two ways:
//  1. Query params: ?repo=<repository>&tag=<tag>
//  2. X-Original-URI header: /v2/<repository>/manifests/<tag>
//
// Response:
//   - 200 + X-Approved-Digest + X-Registry-Domain  →  image is approved
//   - 401                                           →  image is not approved / not found
//   - 400                                           →  repo or tag could not be determined
func (s *Server) validateImage(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	tag := r.URL.Query().Get("tag")

	if repo == "" || tag == "" {
		repo, tag = parseOriginalURI(r.Header.Get("X-Original-URI"))
	}

	if repo == "" || tag == "" {
		http.Error(w, "missing repo and tag", http.StatusBadRequest)
		return
	}

	img, err := s.db.GetApproved(repo, tag)
	if err != nil {
		log.Printf("ERROR validate_image db lookup %s:%s — %v", repo, tag, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if img == nil {
		http.Error(w, "not approved", http.StatusUnauthorized)
		return
	}

	w.Header().Set("X-Approved-Digest", img.Digest)
	w.Header().Set("X-Registry-Domain", img.Registry)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}

// parseOriginalURI extracts repository and tag from a Distribution API path.
//
//	/v2/{repository}/manifests/{tag}
//
// The repository may contain slashes (e.g. "myorg/myapp/myimage").
// Splitting on "/manifests/" (limit 2) handles this correctly.
func parseOriginalURI(uri string) (repo, tag string) {
	// Strip query string.
	if i := strings.Index(uri, "?"); i >= 0 {
		uri = uri[:i]
	}

	const prefix = "/v2/"
	const sep = "/manifests/"

	if !strings.HasPrefix(uri, prefix) {
		return "", ""
	}
	rest := uri[len(prefix):]

	// Use the LAST occurrence of "/manifests/" to handle repos that happen to
	// contain "manifests" as a path component.
	idx := strings.LastIndex(rest, sep)
	if idx < 0 {
		return "", ""
	}
	return rest[:idx], rest[idx+len(sep):]
}
