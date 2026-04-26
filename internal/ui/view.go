package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
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
var pageNames = []string{
	"index.html",
	"images.html",
	"image.html",
	"repos.html",
	"repo.html",
	"tagset.html",
}

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
		"vulnList":       vulnList,
		"packageList":    packageList,
		"cveURL":         cveURL,
		"prettyJSON":     prettyJSON,
		"isStub":         isStub,
		"pathEscape":     url.PathEscape,
		"join":           strings.Join,
		"add":            func(a, b int) int { return a + b },
		"dict":           dict,
	}
}

// dict returns a map[string]any built from alternating key/value pairs.
// Lets templates pass labelled arguments to sub-templates without
// declaring a struct for every shape.  Panics on misuse so a typo'd
// template breaks loudly rather than silently producing nil values.
func dict(pairs ...interface{}) map[string]interface{} {
	if len(pairs)%2 != 0 {
		panic("dict: odd argument count")
	}
	out := make(map[string]interface{}, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			panic(fmt.Sprintf("dict: key %d is not a string", i))
		}
		out[key] = pairs[i+1]
	}
	return out
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

// CVE is one row in the vulnerability table on the image detail page.
// Mirrors the trivy `Results[].Vulnerabilities[]` shape, flattened with
// the parent Result's Target so a multi-OS scan still distinguishes
// where the finding came from.
type CVE struct {
	ID               string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Title            string
	Target           string
}

// Package is one row in the SBOM table on the image detail page.
// Sourced from `Results[].Packages[]` when present (trivy emits it for
// SBOM-formatted outputs); falls back to deduped vulnerability rows.
type Package struct {
	Name    string
	Version string
	Type    string
	Source  string
	Target  string
}

// severityRank orders trivy severities so the CVE table can be sorted
// worst-first.  Unknown / non-canonical severities sink below LOW.
var severityRank = map[string]int{
	"CRITICAL": 0,
	"HIGH":     1,
	"MEDIUM":   2,
	"LOW":      3,
	"UNKNOWN":  4,
}

// vulnList flattens every Result.Vulnerabilities[] into a sorted slice
// (worst severity first, then alphabetical CVE id).  Missing or
// malformed reports return nil.
func vulnList(report json.RawMessage) []CVE {
	if len(report) == 0 || string(report) == "null" {
		return nil
	}
	var doc struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil
	}
	var out []CVE
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			out = append(out, CVE{
				ID:               v.VulnerabilityID,
				PkgName:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         strings.ToUpper(v.Severity),
				Title:            v.Title,
				Target:           r.Target,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank[out[i].Severity], severityRank[out[j].Severity]
		if ri == 0 && out[i].Severity != "CRITICAL" {
			ri = 99
		}
		if rj == 0 && out[j].Severity != "CRITICAL" {
			rj = 99
		}
		if ri != rj {
			return ri < rj
		}
		if out[i].PkgName != out[j].PkgName {
			return out[i].PkgName < out[j].PkgName
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// packageList flattens every Result.Packages[] into a sorted slice for
// the SBOM table.  When the report has no Packages array (typical for
// vulnerability-only scans), falls back to the distinct
// (PkgName, InstalledVersion, Target) tuples observed in
// Vulnerabilities so operators always see something useful.
func packageList(report json.RawMessage) []Package {
	if len(report) == 0 || string(report) == "null" {
		return nil
	}
	var doc struct {
		Results []struct {
			Target   string `json:"Target"`
			Type     string `json:"Type"`
			Class    string `json:"Class"`
			Packages []struct {
				Name    string `json:"Name"`
				Version string `json:"Version"`
				SrcName string `json:"SrcName"`
				Layer   struct {
					Digest string `json:"Digest"`
				} `json:"Layer"`
			} `json:"Packages"`
			Vulnerabilities []struct {
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil
	}

	var out []Package
	seen := map[string]struct{}{}
	for _, r := range doc.Results {
		if len(r.Packages) > 0 {
			for _, p := range r.Packages {
				key := p.Name + "@" + p.Version + "|" + r.Target
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, Package{
					Name:    p.Name,
					Version: p.Version,
					Type:    r.Type,
					Source:  p.SrcName,
					Target:  r.Target,
				})
			}
		}
	}
	if len(out) == 0 {
		// Fall back to distinct (pkg, version, target) from vulns.
		for _, r := range doc.Results {
			for _, v := range r.Vulnerabilities {
				key := v.PkgName + "@" + v.InstalledVersion + "|" + r.Target
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, Package{
					Name:    v.PkgName,
					Version: v.InstalledVersion,
					Type:    r.Type,
					Target:  r.Target,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// cveURL builds a stable lookup link for a vulnerability identifier.
// CVE ids resolve to NVD; everything else (Alpine ALAS, GHSA, etc.)
// falls back to a Google search so operators can still click through.
func cveURL(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return ""
	}
	if strings.HasPrefix(id, "CVE-") {
		return "https://nvd.nist.gov/vuln/detail/" + id
	}
	if strings.HasPrefix(id, "GHSA-") {
		return "https://github.com/advisories/" + id
	}
	return "https://www.google.com/search?q=" + url.QueryEscape(id)
}
