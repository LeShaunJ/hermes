package ui

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/leshaunj/hermes/internal/db"
)

// dashboard renders the / page — state counts plus a live event feed root.
func (s *Server) dashboard(w http.ResponseWriter, _ *http.Request) {
	all, err := s.db.List(db.ListFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := map[db.State]int{}
	for _, img := range all {
		counts[img.State]++
	}

	// Display the canonical state set in a stable order so the dashboard
	// numbers don't jump around when new entries appear.
	order := []db.State{
		db.StateQueued,
		db.StateScanned,
		db.StateRescinded,
		db.StateVoided,
		db.StateApproved,
		db.StateRejected,
		db.StateErrored,
	}
	tiles := make([]stateTile, 0, len(order))
	for _, st := range order {
		tiles = append(tiles, stateTile{State: st, Count: counts[st]})
	}

	// Show the most recent ten images so an operator landing on the
	// dashboard sees fresh activity without a separate click.
	recent := all
	if len(recent) > 10 {
		recent = recent[:10]
	}

	s.tmpl.render(w, "index.html", pageData{
		Title:  "Hermes",
		Tiles:  tiles,
		Recent: recent,
		Total:  len(all),
	})
}

// imageTree renders the unified three-level tree view of tracked images.
// All rows are emitted server-side; level 2 / 3 rows start `hidden` and
// the htmx shim flips visibility on click + persists state in
// localStorage.  Query params match the previous flat listing
// (`state`, `os`, `arch`, `ref`) so deep-links keep working.
func (s *Server) imageTree(w http.ResponseWriter, r *http.Request) {
	filter, stateTokens, err := s.parseListFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	imgs, err := s.db.List(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := pageData{
		Title:       "Images",
		Tree:        groupTree(imgs),
		Filter:      filter,
		StateTokens: stateTokens,
		RefFilter:   strings.Join(filter.Refs, " "),
		Query:       r.URL.Query().Encode(),
	}
	s.tmpl.render(w, "images.html", data)
}

// viewImageRow re-renders a single level-3 row.  The htmx shim hits
// this from its SSE handler so the row updates in place when a scan
// (or any other state-changing action) finishes asynchronously — no
// full-page reload required.  The nesting context is supplied via
// `Hx-Indent` and `Hx-Group` headers (set by the shim from the source
// row's CSS class and `data-group` attribute) so the swap preserves
// indent and parent-collapse linkage.
func (s *Server) viewImageRow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad image id", http.StatusBadRequest)
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
	s.renderRow(w, r, img)
}

// renderRow writes the level-3 row partial for img, picking up indent
// and group context from request headers so action swaps and SSE
// refreshes both keep the row visually consistent with where it lived
// before.  Busy state (scanning / fetching) is read straight from the
// server's in-flight maps via the `isScanning` / `isFetching`
// template funcs — no need to thread booleans through every dict.
func (s *Server) renderRow(w http.ResponseWriter, r *http.Request, img *db.Image) {
	indent := 0
	if v := r.Header.Get("Hx-Indent"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 2 {
			indent = n
		}
	}
	s.tmpl.render(w, "_row.html", map[string]interface{}{
		"Image":  *img,
		"Group":  r.Header.Get("Hx-Group"),
		"Indent": indent,
		"Hidden": false,
	})
}

// viewImageDetail returns the inner partial of the image detail page.
// The shim's SSE handler hits this endpoint when an event for the
// image currently shown on /images/{id} arrives, and detail-page
// action buttons target #image-detail so the swap stays in place.
func (s *Server) viewImageDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad image id", http.StatusBadRequest)
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
	s.tmpl.render(w, "_image_detail.html", *img)
}

// viewRepoOrTagSet dispatches every `/repos/{registry}/{path...}` URL.
// Go's stdlib mux requires `{path...}` to be the last segment, so the
// handler parses the trailing form itself:
//
//	/repos/{reg}/{path}                          → repo detail page
//	/repos/{reg}/{path}/row                      → level-1 row partial
//	/repos/{reg}/{path}/tags/{digest}            → tag-set detail page
//	/repos/{reg}/{path}/tags/{digest}/row        → level-2 row partial
func (s *Server) viewRepoOrTagSet(w http.ResponseWriter, r *http.Request) {
	registry := r.PathValue("registry")
	rest := r.PathValue("path")

	// Strip a trailing /row marker first so we can route partial
	// requests independently of detail-page requests.
	wantRow := false
	if strings.HasSuffix(rest, "/row") {
		wantRow = true
		rest = strings.TrimSuffix(rest, "/row")
	}

	repoPath := rest
	digest := ""
	if i := strings.Index(rest, "/tags/"); i >= 0 {
		repoPath = rest[:i]
		raw := rest[i+len("/tags/"):]
		if d, err := url.PathUnescape(raw); err == nil {
			digest = d
		} else {
			digest = raw
		}
	}
	if registry == "" || repoPath == "" {
		http.Error(w, "missing registry or repository", http.StatusBadRequest)
		return
	}

	switch {
	case wantRow && digest != "":
		s.viewTagSetRow(w, r, registry, repoPath, digest)
	case wantRow:
		s.viewRepoRow(w, r, registry, repoPath)
	case digest != "":
		s.viewTagSet(w, r, registry, repoPath, digest)
	default:
		s.viewRepo(w, r, registry, repoPath)
	}
}

// viewRepoRow re-renders the level-1 (repo) tree row in isolation.
// Used by the shim when an SSE event fires for a child image whose
// repo row state-summary chips need to refresh.
func (s *Server) viewRepoRow(w http.ResponseWriter, r *http.Request, registry, repoPath string) {
	imgs, err := s.db.List(db.ListFilter{Refs: []string{registry + "/" + repoPath}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tree := groupTree(imgs)
	for _, repo := range tree {
		if repo.RegistryURL == registry && repo.Repository == repoPath {
			s.tmpl.render(w, "_repo_row.html", repo)
			return
		}
	}
	http.NotFound(w, r)
}

// viewTagSetRow re-renders the level-2 (tag-set) tree row in isolation.
func (s *Server) viewTagSetRow(w http.ResponseWriter, r *http.Request, registry, repoPath, digest string) {
	imgs, err := s.db.List(db.ListFilter{
		Refs:      []string{registry + "/" + repoPath},
		TagDigest: digest,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(imgs) == 0 {
		http.NotFound(w, r)
		return
	}
	imgs = dedupImages(imgs)

	ts := TagSetNode{TagDigest: digest, States: map[string]int{}, UpdatedAt: imgs[0].UpdatedAt}
	tagSeen := map[string]struct{}{}
	for _, img := range imgs {
		if _, ok := tagSeen[img.TagName]; !ok {
			ts.Tags = append(ts.Tags, img.TagName)
			tagSeen[img.TagName] = struct{}{}
		}
		ts.States[string(img.State)]++
		ts.Images = append(ts.Images, img)
		if img.UpdatedAt.After(ts.UpdatedAt) {
			ts.UpdatedAt = img.UpdatedAt
		}
	}
	sort.Strings(ts.Tags)

	parentRowID := fmt.Sprintf("repo:%s|%s", registry, repoPath)
	parentGroup := "tg-" + parentRowID
	s.tmpl.render(w, "_tagset_row.html", map[string]interface{}{
		"Repo":   registry,
		"Path":   repoPath,
		"TagSet": ts,
		"Group":  parentGroup,
	})
}

func (s *Server) viewRepo(w http.ResponseWriter, r *http.Request, registry, repoPath string) {
	tagSets, err := s.db.ListTagSets(registry, repoPath, db.ListFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	imgs, err := s.db.List(db.ListFilter{
		Refs: []string{registry + "/" + repoPath},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Same alias-fanout as in groupTree — collapse duplicates so the
	// per-platform list under a tag-set has one row per real image.
	imgs = dedupImages(imgs)
	summary := summarizeImages(imgs)
	images := groupByTagDigest(imgs)

	s.tmpl.render(w, "repo.html", pageData{
		Title:        registry + "/" + repoPath,
		RegistryURL:  registry,
		RepoPath:     repoPath,
		TagSets:      tagSets,
		ImagesByTag:  images,
		StateSummary: summary,
	})
}

func (s *Server) viewTagSet(w http.ResponseWriter, r *http.Request, registry, repoPath, digest string) {
	imgs, err := s.db.List(db.ListFilter{
		Refs:      []string{registry + "/" + repoPath},
		TagDigest: digest,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(imgs) == 0 {
		http.NotFound(w, r)
		return
	}

	tagSet := db.TagSet{TagDigest: digest, States: map[string]int{}, UpdatedAt: imgs[0].UpdatedAt}
	tagsSeen := map[string]struct{}{}
	imgSeen := map[string]struct{}{}
	deduped := make([]db.Image, 0, len(imgs))
	for _, img := range imgs {
		if _, ok := tagsSeen[img.TagName]; !ok {
			tagSet.Tags = append(tagSet.Tags, img.TagName)
			tagsSeen[img.TagName] = struct{}{}
		}
		key := imageDedupKey(img)
		if _, dup := imgSeen[key]; dup {
			continue
		}
		imgSeen[key] = struct{}{}
		deduped = append(deduped, img)
		if img.ID != 0 {
			tagSet.ImageCount++
		}
		tagSet.States[string(img.State)]++
		if img.UpdatedAt.After(tagSet.UpdatedAt) {
			tagSet.UpdatedAt = img.UpdatedAt
		}
	}
	sort.Strings(tagSet.Tags)

	s.tmpl.render(w, "tagset.html", pageData{
		Title:        registry + "/" + repoPath + " · " + shortDigest(digest),
		RegistryURL:  registry,
		RepoPath:     repoPath,
		TagSet:       &tagSet,
		Images:       deduped,
		StateSummary: summarizeImages(deduped),
	})
}

// parseListFilter pulls state / os / arch / ref query params out of r and
// returns the corresponding ListFilter and the raw state-token slice
// (for re-rendering the form).
func (s *Server) parseListFilter(r *http.Request) (db.ListFilter, []string, error) {
	q := r.URL.Query()
	filter := db.ListFilter{
		OS:   q.Get("os"),
		Arch: q.Get("arch"),
	}
	if refs := q["ref"]; len(refs) > 0 {
		filter.Refs = refs
	}
	var stateTokens []string
	for _, raw := range q["state"] {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			states, err := db.ParseStateOrGroup(item)
			if err != nil {
				return db.ListFilter{}, nil, err
			}
			filter.States = append(filter.States, states...)
			stateTokens = append(stateTokens, item)
		}
	}
	return filter, stateTokens, nil
}

// viewImage renders the detail page for one image.
func (s *Server) viewImage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad image id", http.StatusBadRequest)
		return
	}
	// Synthetic id=0 covers every stub in `tag_image_rows`, so a
	// detail page at /images/0 cannot identify a specific row.
	// Bounce the operator back to the list, which links each stub
	// only by its (registry, repository, tag) tuple.
	if id == 0 {
		http.Redirect(w, r, s.cfg.UI.BasePath+"/images?state=queued", http.StatusSeeOther)
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
	s.tmpl.render(w, "image.html", pageData{
		Title: "Image",
		Image: img,
	})
}

// pageData is the unified template input.  Templates touch only the fields
// they need; unset fields render as empty.
type pageData struct {
	Title       string
	Tiles       []stateTile
	Recent      []db.Image
	Images      []db.Image
	Filter      db.ListFilter
	StateTokens []string // raw state/group tokens from the query, for re-rendering the form
	RefFilter   string   // joined `ref` query values, for re-populating the input
	Query       string
	Image       *db.Image
	Total       int
	FlashMsg    string

	// Tree view (/images): ordered list of repo nodes with nested tag-sets
	// and per-platform image rows.
	Tree []RepoNode

	// /repos: flat list of repo summaries.
	Repos []db.RepoSummary

	// /repos/{registry}/{path...}: focused on one repo.
	RegistryURL string
	RepoPath    string
	TagSets     []db.TagSet
	ImagesByTag map[string][]db.Image // key = tag_digest; "" bucket = stub

	// /repos/{registry}/{path...}/tags/{digest}: focused on one tag-set.
	TagSet *db.TagSet

	// State-summary chip data shared by repo / tag-set pages.
	StateSummary []stateTile
}

type stateTile struct {
	State db.State
	Count int
}

// RepoNode is the level-1 tree entry feeding `templates/images.html`.
type RepoNode struct {
	RegistryURL string
	Repository  string
	UpdatedAt   time.Time
	States      map[string]int
	TagSets     []TagSetNode
}

// TagSetNode is the level-2 tree entry — a single top-level manifest
// digest and the tag(s)/per-platform images it carries.
type TagSetNode struct {
	TagDigest string
	Tags      []string
	UpdatedAt time.Time
	States    map[string]int
	Images    []db.Image
}

// groupTree assembles imgs into the (repo → tag-set → image) tree the
// images.html template iterates.  Repos are ordered by most-recent
// activity; tag-sets within a repo similarly; tag names within a
// tag-set are sorted lexicographically.  Stub images (empty TagDigest)
// share the "" bucket so the unresolved-tags pile is visible at a
// glance.
//
// `tag_image_rows` produces one row per (tag, platform) — when several
// tags point at the same top-level digest (e.g. `latest` + `3.23.4`)
// each platform image appears once per aliasing tag.  We dedup by
// image id within a tag-set so the rendered tree shows one row per
// platform, with the aliases collected on the parent tag-set row.
func groupTree(imgs []db.Image) []RepoNode {
	type repoKey struct{ Reg, Path string }
	type tsKey struct {
		Reg, Path, Digest string
	}

	repoIdx := map[repoKey]int{}
	tsIdx := map[tsKey]int{}
	tagSeen := map[tsKey]map[string]struct{}{}
	imgSeen := map[tsKey]map[string]struct{}{}

	var repos []RepoNode

	for _, img := range imgs {
		rk := repoKey{img.RegistryURL, img.Repository}
		ri, ok := repoIdx[rk]
		if !ok {
			ri = len(repos)
			repoIdx[rk] = ri
			repos = append(repos, RepoNode{
				RegistryURL: img.RegistryURL,
				Repository:  img.Repository,
				UpdatedAt:   img.UpdatedAt,
				States:      map[string]int{},
			})
		}
		repo := &repos[ri]
		if img.UpdatedAt.After(repo.UpdatedAt) {
			repo.UpdatedAt = img.UpdatedAt
		}

		tk := tsKey{img.RegistryURL, img.Repository, img.TagDigest}
		ti, ok := tsIdx[tk]
		if !ok {
			ti = len(repo.TagSets)
			tsIdx[tk] = ti
			repo.TagSets = append(repo.TagSets, TagSetNode{
				TagDigest: img.TagDigest,
				UpdatedAt: img.UpdatedAt,
				States:    map[string]int{},
			})
			tagSeen[tk] = map[string]struct{}{}
			imgSeen[tk] = map[string]struct{}{}
		}
		ts := &repo.TagSets[ti]
		if img.UpdatedAt.After(ts.UpdatedAt) {
			ts.UpdatedAt = img.UpdatedAt
		}
		if _, seen := tagSeen[tk][img.TagName]; !seen {
			ts.Tags = append(ts.Tags, img.TagName)
			tagSeen[tk][img.TagName] = struct{}{}
		}

		// Skip duplicate platform-image rows produced by alias tags
		// pointing at the same digest.  Stubs (ID == 0) have no image
		// row to dedup against, so key on tag name instead so each
		// distinct stub tag still appears.
		key := imageDedupKey(img)
		if _, dup := imgSeen[tk][key]; dup {
			continue
		}
		imgSeen[tk][key] = struct{}{}

		repo.States[string(img.State)]++
		ts.States[string(img.State)]++
		ts.Images = append(ts.Images, img)
	}

	// Order tag-sets within each repo by most-recent first; sort tag
	// names alphabetically; sort repos by most-recent first.
	for ri := range repos {
		ts := repos[ri].TagSets
		sort.SliceStable(ts, func(i, j int) bool {
			if ts[i].UpdatedAt.Equal(ts[j].UpdatedAt) {
				return ts[i].TagDigest < ts[j].TagDigest
			}
			return ts[i].UpdatedAt.After(ts[j].UpdatedAt)
		})
		for ti := range ts {
			sort.Strings(ts[ti].Tags)
		}
	}
	sort.SliceStable(repos, func(i, j int) bool {
		if repos[i].UpdatedAt.Equal(repos[j].UpdatedAt) {
			if repos[i].RegistryURL == repos[j].RegistryURL {
				return repos[i].Repository < repos[j].Repository
			}
			return repos[i].RegistryURL < repos[j].RegistryURL
		}
		return repos[i].UpdatedAt.After(repos[j].UpdatedAt)
	})
	return repos
}

// imageDedupKey returns a stable identifier for one platform-image row
// suitable for collapsing duplicates from `tag_image_rows` when several
// tags alias the same digest.  Real image rows (ID != 0) key on the
// integer id; stub rows (ID == 0) key on the tag name so distinct
// unresolved tags survive deduplication.
func imageDedupKey(img db.Image) string {
	if img.ID != 0 {
		return strconv.FormatInt(img.ID, 10)
	}
	return "stub:" + img.TagName
}

// dedupImages collapses duplicate platform-image rows produced by the
// (tag × image) JOIN when multiple aliasing tags point at the same
// digest.  See imageDedupKey for the bucketing rule.
func dedupImages(imgs []db.Image) []db.Image {
	seen := make(map[string]struct{}, len(imgs))
	out := make([]db.Image, 0, len(imgs))
	for _, img := range imgs {
		key := imageDedupKey(img)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, img)
	}
	return out
}

// groupByTagDigest buckets imgs by their top-level (`tag_digest`).
// Stubs share the empty-digest bucket.  Used by the repo detail page so
// the level-2 rows mirror the level-1 expanded view from `/images`.
func groupByTagDigest(imgs []db.Image) map[string][]db.Image {
	out := map[string][]db.Image{}
	for _, img := range imgs {
		out[img.TagDigest] = append(out[img.TagDigest], img)
	}
	return out
}

// summarizeImages returns ordered state-tile chips (non-zero counts only)
// for a flat slice — used as the header summary on the repo and
// tag-set pages.
func summarizeImages(imgs []db.Image) []stateTile {
	counts := map[db.State]int{}
	for _, img := range imgs {
		counts[img.State]++
	}
	order := []db.State{
		db.StateQueued,
		db.StateScanned,
		db.StateRescinded,
		db.StateVoided,
		db.StateApproved,
		db.StateRejected,
		db.StateErrored,
	}
	out := make([]stateTile, 0, len(order))
	for _, st := range order {
		if c := counts[st]; c > 0 {
			out = append(out, stateTile{State: st, Count: c})
		}
	}
	return out
}
