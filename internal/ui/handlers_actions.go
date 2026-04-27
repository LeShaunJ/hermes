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

// actionFetch handles POST /images/{id}/fetch.  Stub rows have no
// manifest yet — the gateway saw the tag but the operator never ran
// `hermes scan` to populate it.  This action runs db.Queue (the same
// path the CLI uses) on a background goroutine so a slow registry
// does not stall the HTTP response.  The handler returns immediately
// with the row partial in its "fetching…" state; the eventual `fetch`
// / `fetch_error` event lets the SSE shim refresh the level-1 row,
// which by then contains the resolved per-platform rows.
func (s *Server) actionFetch(w http.ResponseWriter, r *http.Request) {
	id, ok := s.actionPrep(w, r)
	if !ok {
		return
	}
	stub, err := s.db.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if stub == nil {
		http.NotFound(w, r)
		return
	}
	if !isStub(*stub) {
		http.Error(w, "image is already fetched; use scan to refresh", http.StatusConflict)
		return
	}

	// Non-htmx (no JS) path keeps the original synchronous shape so a
	// curl/wget caller still gets the resolved row set.  The interactive
	// htmx flow goes through the async path with the spinner.
	if r.Header.Get("Hx-Request") != "true" {
		s.runFetchSync(w, r, stub, id)
		return
	}

	s.fetching.Store(id, struct{}{})
	go s.runFetch(stub, id)

	w.WriteHeader(http.StatusAccepted)
	s.respondAction(w, r, id)
}

// runFetch is the goroutine body for actionFetch.  Errors and successes
// both clear the in-flight tracker and emit an event the SSE shim uses
// to refresh the affected ancestors.
func (s *Server) runFetch(stub *db.Image, id int64) {
	defer s.fetching.Delete(id)

	ref := db.ImageRef{
		Registry:   stub.RegistryURL,
		Repository: stub.Repository,
		Tag:        stub.TagName,
	}
	imgs, err := s.db.Queue(ref, s.fetcher)
	if err != nil {
		_ = s.db.LogEvent(&id, db.SourceAPI, "fetch_error", map[string]interface{}{
			"source": "ui",
			"error":  err.Error(),
		})
		slog.Warn("ui fetch error", "image_id", id, "err", err)
		return
	}
	_ = s.db.LogEvent(&id, db.SourceAPI, "fetch", map[string]interface{}{
		"source":   "ui",
		"registry": stub.RegistryURL,
		"repo":     stub.Repository,
		"tag":      stub.TagName,
		"count":    len(imgs),
	})
}

// runFetchSync preserves the pre-async fallback for non-htmx callers
// (curl, redirected browsers without JS).  It blocks the request until
// Queue returns and renders the resolved row set or a 502.
func (s *Server) runFetchSync(w http.ResponseWriter, r *http.Request, stub *db.Image, id int64) {
	ref := db.ImageRef{
		Registry:   stub.RegistryURL,
		Repository: stub.Repository,
		Tag:        stub.TagName,
	}
	imgs, err := s.db.Queue(ref, s.fetcher)
	if err != nil {
		_ = s.db.LogEvent(&id, db.SourceAPI, "fetch_error", map[string]interface{}{
			"source": "ui",
			"error":  err.Error(),
		})
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = s.db.LogEvent(&id, db.SourceAPI, "fetch", map[string]interface{}{
		"source":   "ui",
		"registry": stub.RegistryURL,
		"repo":     stub.Repository,
		"tag":      stub.TagName,
		"count":    len(imgs),
	})
	http.Redirect(w, r, fmt.Sprintf("%s/images?ref=%s/%s:%s",
		s.cfg.UI.BasePath, stub.RegistryURL, stub.Repository, stub.TagName),
		http.StatusSeeOther)
}

// actionScan handles POST /images/{id}/scan.  The trivy invocation is
// long-running, so it is dispatched on a background goroutine; this
// handler returns immediately with the row partial in its "scanning…"
// state (button disabled, spinner visible).  The /events SSE feed
// delivers the eventual scan / scan_error event, the shim's SSE
// listener fetches `/images/{id}/row` and swaps the row into its
// terminal state.
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

	// Stamp the in-flight tracker before spawning the goroutine so the
	// row partial we render below picks up the scanning pseudo-state.
	// The deferred Delete in runScan clears it once the scan finishes.
	s.scanning.Store(id, struct{}{})
	go s.runScan(img)

	w.WriteHeader(http.StatusAccepted)
	s.respondAction(w, r, id)
}

// runScan invokes trivy and persists the result.  Errors are logged to
// the events table so the SSE feed surfaces them; they are not returned
// because the original HTTP request has already been answered.
func (s *Server) runScan(img *db.Image) {
	defer s.scanning.Delete(img.ID)

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

// respondAction writes the right partial for the source page: a row
// partial when the action came from a tree row (Hx-Target=image-{id}),
// or the image-detail partial when the action came from the detail
// page (Hx-Target=image-detail).  Non-htmx requests redirect to the
// image detail page.
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
	if r.Header.Get("Hx-Target") == "image-detail" {
		s.tmpl.render(w, "_image_detail.html", *img)
		return
	}
	s.renderRow(w, r, img)
}
