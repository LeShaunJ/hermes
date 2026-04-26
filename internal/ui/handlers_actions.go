package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/leshaunj/hermes/internal/db"
)

// actionApprove handles POST /images/{id}/approve.  Form fields:
//
//	cache_url  optional registry URL to push the image to upon approval.
//	           When empty (and the field was sent at all) the configured
//	           cfg.CacheURL is used.  When the field is omitted entirely,
//	           no caching happens.
//
// The image is NOT pushed to a cache from the UI in v1 — operators wanting
// cache behaviour should use `hermes approve --cache` from the CLI.  The
// form field is still honoured (recorded against the manifest) so the
// gateway forwards future requests to the cache registry.
func (s *Server) actionApprove(w http.ResponseWriter, r *http.Request) {
	id, ok := s.actionPrep(w, r)
	if !ok {
		return
	}
	cacheURL := strings.TrimSpace(r.FormValue("cache_url"))
	if r.Form.Has("cache_url") && cacheURL == "" {
		cacheURL = s.cfg.CacheURL
	}
	if err := s.db.Approve(id, cacheURL); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.db.LogEvent(&id, db.SourceAPI, "approve", map[string]interface{}{
		"source":    "ui",
		"cache_url": cacheURL,
	})
	s.respondAction(w, r, id)
}

// actionReject handles POST /images/{id}/reject.
func (s *Server) actionReject(w http.ResponseWriter, r *http.Request) {
	id, ok := s.actionPrep(w, r)
	if !ok {
		return
	}
	if err := s.db.Reject(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.db.LogEvent(&id, db.SourceAPI, "reject", map[string]interface{}{"source": "ui"})
	s.respondAction(w, r, id)
}

// actionRescind handles POST /images/{id}/rescind.
func (s *Server) actionRescind(w http.ResponseWriter, r *http.Request) {
	id, ok := s.actionPrep(w, r)
	if !ok {
		return
	}
	if err := s.db.Rescind(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.db.LogEvent(&id, db.SourceAPI, "rescind", map[string]interface{}{"source": "ui"})
	s.respondAction(w, r, id)
}

// actionScan handles POST /images/{id}/scan.  The trivy invocation is
// long-running, so it is dispatched on a background goroutine; this
// handler returns immediately with the row partial in its "scanning…"
// state.  The /events SSE feed will deliver the eventual scan / scan_error
// event to the browser, which swaps the row into its terminal state.
func (s *Server) actionScan(w http.ResponseWriter, r *http.Request) {
	id, ok := s.actionPrep(w, r)
	if !ok {
		return
	}
	img, err := s.db.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if img == nil {
		http.NotFound(w, r)
		return
	}
	if isStub(*img) {
		http.Error(w, "image is a stub — gateway has not seen its manifest yet", http.StatusConflict)
		return
	}

	go s.runScan(img)

	w.WriteHeader(http.StatusAccepted)
	s.respondAction(w, r, id)
}

// runScan invokes trivy and persists the result.  Errors are logged to
// the events table so the SSE feed surfaces them; they are not returned
// because the original HTTP request has already been answered.
func (s *Server) runScan(img *db.Image) {
	scanRef := fmt.Sprintf("%s/%s:%s", img.RegistryURL, img.Repository, img.TagName)
	if img.Digest != "" {
		scanRef = fmt.Sprintf("%s/%s@%s", img.RegistryURL, img.Repository, img.Digest)
	}

	result, err := s.scan(scanRef, s.cfg.Trivy)
	if err != nil {
		_ = s.db.SetError(img.ID)
		_ = s.db.LogEvent(&img.ID, db.SourceAPI, "scan_error", map[string]interface{}{
			"source": "ui",
			"error":  err.Error(),
		})
		slog.Warn("ui scan error", "image_id", img.ID, "err", err)
		return
	}
	if _, err := s.db.SaveScan(img.ID, json.RawMessage(result.Raw)); err != nil {
		_ = s.db.SetError(img.ID)
		_ = s.db.LogEvent(&img.ID, db.SourceAPI, "scan_error", map[string]interface{}{
			"source": "ui",
			"error":  err.Error(),
		})
		slog.Warn("ui scan save error", "image_id", img.ID, "err", err)
		return
	}
	_ = s.db.LogEvent(&img.ID, db.SourceAPI, "scan", map[string]interface{}{
		"source": "ui",
		"digest": img.Digest,
	})
}

// actionPrep parses the path id and form body.  Returns false (and writes
// the error response itself) on any failure so handlers can early-return.
func (s *Server) actionPrep(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad image id", http.StatusBadRequest)
		return 0, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// respondAction writes the row partial for htmx so the table swaps the
// affected row into its new state in place.  Non-htmx requests are
// redirected to the image detail page.
func (s *Server) respondAction(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Header.Get("Hx-Request") != "true" {
		http.Redirect(w, r, fmt.Sprintf("%s/images/%d", s.cfg.UI.BasePath, id), http.StatusSeeOther)
		return
	}
	img, err := s.db.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if img == nil {
		http.NotFound(w, r)
		return
	}
	s.tmpl.render(w, "_row.html", *img)
}
