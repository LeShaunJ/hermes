package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/leshaunj/hermes/internal/db"
)

//go:embed templates/*.html templates/partials/*.html
var templateFS embed.FS

//go:embed static/*
var staticAssets embed.FS

// templates bundles every parsed HTML template.  Pages are parsed
// individually (each with a fresh copy of layout.html and the partials)
// because every page defines its own "content" block and Go's
// html/template namespace is global per *Template.  Partials parse once
// into a shared bundle for direct rendering by htmx swap handlers.
type templates struct {
	pages    map[string]*template.Template
	partials *template.Template
}

// pageNames lists every full-page template file under templates/.  Adding
// a new page requires appending its filename here.
var pageNames = []string{"index.html", "images.html", "image.html"}

func loadTemplates(basePath string) (*templates, error) {
	partialFiles, err := fs.Glob(templateFS, "templates/partials/*.html")
	if err != nil {
		return nil, err
	}
	funcs := buildFuncMap(basePath)

	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t := template.New(name).Funcs(funcs)
		files := append([]string{"templates/layout.html", "templates/" + name}, partialFiles...)
		if _, err := t.ParseFS(templateFS, files...); err != nil {
			return nil, err
		}
		pages[name] = t
	}

	p := template.New("partials").Funcs(funcs)
	if _, err := p.ParseFS(templateFS, partialFiles...); err != nil {
		return nil, err
	}

	return &templates{pages: pages, partials: p}, nil
}

// render executes the named template and writes its output to w.  Pages
// (entries in pageNames) render layout.html, which pulls in the page's
// "content" definition; everything else is treated as a partial name like
// "_row.html" and rendered directly.
//
// Output is buffered so a render failure can be reported as a 500 rather
// than truncating a half-written response.
func (t *templates) render(w http.ResponseWriter, name string, data interface{}) {
	var buf bytes.Buffer
	var err error
	if page, ok := t.pages[name]; ok {
		err = page.ExecuteTemplate(&buf, "layout", data)
	} else {
		err = t.partials.ExecuteTemplate(&buf, name, data)
	}
	if err != nil {
		http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// buildFuncMap returns the template helper map with `base` closed over the
// configured mount prefix.  Templates emit URLs as `{{base}}/...` so the
// console works whether it is served at the listener's root or behind a
// reverse-proxy path like `/ui`.
func buildFuncMap(basePath string) template.FuncMap {
	return template.FuncMap{
		"base":           func() string { return basePath },
		"stateClass":     stateClass,
		"shortDigest":    shortDigest,
		"formatTime":     formatTime,
		"formatRelative": formatRelative,
		"vulnSummary":    vulnSummary,
		"prettyJSON":     prettyJSON,
		"isStub":         isStub,
		"join":           strings.Join,
		"add":            func(a, b int) int { return a + b },
	}
}

// stateClass maps a db.State to a CSS class for badge styling.
func stateClass(s db.State) string {
	switch s {
	case db.StateApproved:
		return "state state-approved"
	case db.StateRejected:
		return "state state-rejected"
	case db.StateQueued, db.StateScanned, db.StateRescinded, db.StateVoided:
		return "state state-pending"
	case db.StateErrored:
		return "state state-errored"
	}
	return "state"
}

// shortDigest returns the first 12 hex chars after `sha256:`, like docker.
func shortDigest(d string) string {
	if d == "" {
		return ""
	}
	if i := strings.Index(d, ":"); i >= 0 && i+13 <= len(d) {
		return d[:i+13]
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// formatRelative renders a coarse "5m ago" / "2h ago" / "3d ago" string.
func formatRelative(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// isStub reports whether the image row has not yet had its manifest fetched.
func isStub(img db.Image) bool {
	return img.Digest == ""
}

// vulnSummary extracts severity counts from a trivy JSON report, returning
// a slice of {Severity, Count} pairs in canonical (CRITICAL→UNKNOWN) order.
// Empty / missing reports yield an empty slice without error.
func vulnSummary(report json.RawMessage) []SeverityCount {
	if len(report) == 0 || string(report) == "null" {
		return nil
	}
	var doc struct {
		Results []struct {
			Vulnerabilities []struct {
				Severity string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil
	}
	counts := map[string]int{}
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			counts[strings.ToUpper(v.Severity)]++
		}
	}
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	out := make([]SeverityCount, 0, len(order))
	for _, sev := range order {
		if c := counts[sev]; c > 0 {
			out = append(out, SeverityCount{Severity: sev, Count: c})
		}
	}
	// Drain any non-canonical severities (e.g. NEGLIGIBLE) so the summary
	// is complete.  Sort them after the canonical block for stability.
	leftovers := make([]SeverityCount, 0)
	for sev, c := range counts {
		known := false
		for _, k := range order {
			if k == sev {
				known = true
				break
			}
		}
		if !known {
			leftovers = append(leftovers, SeverityCount{Severity: sev, Count: c})
		}
	}
	sort.Slice(leftovers, func(i, j int) bool { return leftovers[i].Severity < leftovers[j].Severity })
	return append(out, leftovers...)
}

// SeverityCount is one row of vulnSummary's output.
type SeverityCount struct {
	Severity string
	Count    int
}

// prettyJSON re-indents raw JSON with 2-space indent for display.
// Returns the original bytes on parse failure so the user still sees something.
func prettyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
