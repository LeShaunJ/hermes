package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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
// to refresh the affected ancestors.  Stub rows synthesize id=0 in
// `tag_image_rows` and have no real image row to FK against, so the
// event is logged with image_id=NULL when id is zero — Postgres
// rejects an `events.image_id` that does not exist in `images`.
func (s *Server) runFetch(stub *db.Image, id int64) {
	defer s.fetching.Delete(id)

	ref := db.ImageRef{
		Registry:   stub.RegistryURL,
		Repository: stub.Repository,
		Tag:        stub.TagName,
	}
	imgs, err := s.db.Queue(ref, s.fetcher)
	eventID := eventIDFor(id)
	if err != nil {
		_ = s.db.LogEvent(eventID, db.SourceAPI, "fetch_error", map[string]interface{}{
			"source":   "ui",
			"error":    err.Error(),
			"registry": stub.RegistryURL,
			"repo":     stub.Repository,
			"tag":      stub.TagName,
		})
		slog.Warn("ui fetch error", "image_id", id, "err", err)
		return
	}
	_ = s.db.LogEvent(eventID, db.SourceAPI, "fetch", map[string]interface{}{
		"source":   "ui",
		"registry": stub.RegistryURL,
		"repo":     stub.Repository,
		"tag":      stub.TagName,
		"count":    len(imgs),
	})
}

// eventIDFor returns id wrapped in *int64, or nil when id is the
// synthetic zero used for stub rows.  events.image_id is FK-checked
// against images.id, so passing zero would 23503 — and there is no
// "the stub" row to point at anyway.
func eventIDFor(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
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
	eventID := eventIDFor(id)
	if err != nil {
		_ = s.db.LogEvent(eventID, db.SourceAPI, "fetch_error", map[string]interface{}{
			"source":   "ui",
			"error":    err.Error(),
			"registry": stub.RegistryURL,
			"repo":     stub.Repository,
			"tag":      stub.TagName,
		})
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = s.db.LogEvent(eventID, db.SourceAPI, "fetch", map[string]interface{}{
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

// respondAction writes the right response shape for the source page:
//
//   - Detail page (Hx-Target=image-detail) → re-render the detail
//     partial inline so the section swaps in place.
//   - Tree row (anything else) → emit a multi-swap response: the
//     updated row in its target slot, plus OOB swaps for the parent
//     tag-set and repo state-summary cells.  When the current view's
//     state filter no longer admits the new state, the row is replaced
//     with an `hx-swap-oob="delete"` directive so it disappears.
//
// Non-htmx requests redirect to the image detail page.
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
	s.renderActionResponse(w, r, img)
}

// renderActionResponse writes the multi-swap row response for an
// action triggered from a tree page.  See respondAction.
func (s *Server) renderActionResponse(w http.ResponseWriter, r *http.Request, img *db.Image) {
	indent := 0
	if v := r.Header.Get("Hx-Indent"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 2 {
			indent = n
		}
	}
	tsKey := tagSetKey(img.RegistryURL, img.Repository, img.TagDigest)
	repoKey := fmt.Sprintf("repo:%s|%s", img.RegistryURL, img.Repository)

	repoStates, tsStates, err := s.computeAncestorStates(img)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.tmpl.render(w, "_action_response.html", map[string]interface{}{
		"Image":      *img,
		"Group":      r.Header.Get("Hx-Group"),
		"Indent":     indent,
		"RemoveRow":  !s.imageMatchesCurrentFilter(r, img),
		"TSKey":      tsKey,
		"RepoKey":    repoKey,
		"TSStates":   tsStates,
		"RepoStates": repoStates,
	})
}

// computeAncestorStates totals state counts across the image's
// repository (level 1) and the tag-set within that repository it
// shares a top-level digest with (level 2).  Used to populate OOB
// state-summary chips on action responses without recomputing the
// whole tree.
func (s *Server) computeAncestorStates(img *db.Image) (repoStates, tsStates map[string]int, err error) {
	imgs, err := s.db.List(db.ListFilter{Refs: []string{img.RegistryURL + "/" + img.Repository}})
	if err != nil {
		return nil, nil, err
	}
	imgs = dedupImages(imgs)
	repoStates = map[string]int{}
	tsStates = map[string]int{}
	for _, m := range imgs {
		repoStates[string(m.State)]++
		if m.TagDigest == img.TagDigest {
			tsStates[string(m.State)]++
		}
	}
	return repoStates, tsStates, nil
}

// imageMatchesCurrentFilter inspects the operator's current page URL
// (sent as Hx-Current-URL by the shim, with Referer as a fallback) and
// reports whether img would still appear under the page's `state`
// filter.  Returns true when the filter is empty or absent so action
// responses default to a normal swap.
func (s *Server) imageMatchesCurrentFilter(r *http.Request, img *db.Image) bool {
	cur := r.Header.Get("Hx-Current-URL")
	if cur == "" {
		cur = r.Header.Get("Referer")
	}
	if cur == "" {
		return true
	}
	u, err := url.Parse(cur)
	if err != nil {
		return true
	}
	states := u.Query()["state"]
	if len(states) == 0 {
		return true
	}
	var allowed []db.State
	for _, raw := range states {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if list, lerr := db.ParseStateOrGroup(item); lerr == nil {
				allowed = append(allowed, list...)
			}
		}
	}
	if len(allowed) == 0 {
		return true
	}
	for _, st := range allowed {
		if st == img.State {
			return true
		}
	}
	return false
}

// tagSetKey returns the rowID-style identifier for a tag-set, matching
// the keys emitted by the tree templates (`ts:reg|path|digest` or
// `ts:reg|path|stub` for the unresolved bucket).
func tagSetKey(registry, repository, digest string) string {
	d := digest
	if d == "" {
		d = "stub"
	}
	return fmt.Sprintf("ts:%s|%s|%s", registry, repository, d)
}
