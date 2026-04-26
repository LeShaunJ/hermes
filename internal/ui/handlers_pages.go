package ui

import (
	"net/http"
	"strconv"
	"strings"

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

// listImages renders the table of tracked images.  Query params:
//
//	state  one or more (comma-separated or repeated) states/groups
//	ref    filter pattern, "[<registry>/][<namespace>/]<name>[:<tag>]"
//	os     exact OS match
//	arch   exact arch match
//
// htmx GETs targeting the table body include `Hx-Request: true`, in which
// case only the rows partial is returned so the swap is in-place.
func (s *Server) listImages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := db.ListFilter{
		OS:   q.Get("os"),
		Arch: q.Get("arch"),
	}

	if refs := q["ref"]; len(refs) > 0 {
		filter.Refs = refs
	}

	for _, raw := range q["state"] {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			states, err := db.ParseStateOrGroup(item)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			filter.States = append(filter.States, states...)
		}
	}

	imgs, err := s.db.List(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := pageData{
		Title:  "Images",
		Images: imgs,
		Filter: filter,
		Query:  q.Encode(),
	}

	if r.Header.Get("Hx-Request") == "true" && r.Header.Get("Hx-Target") == "image-rows" {
		s.tmpl.render(w, "_rows.html", data)
		return
	}
	s.tmpl.render(w, "images.html", data)
}

// viewImage renders the detail page for one image.
func (s *Server) viewImage(w http.ResponseWriter, r *http.Request) {
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
	s.tmpl.render(w, "image.html", pageData{
		Title: "Image",
		Image: img,
	})
}

// pageData is the unified template input.  Templates touch only the fields
// they need; unset fields render as empty.
type pageData struct {
	Title    string
	Tiles    []stateTile
	Recent   []db.Image
	Images   []db.Image
	Filter   db.ListFilter
	Query    string
	Image    *db.Image
	Total    int
	FlashMsg string
}

type stateTile struct {
	State db.State
	Count int
}
