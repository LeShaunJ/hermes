// Package db manages the hermes PostgreSQL schema and all image/event persistence.
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// ── state / group ─────────────────────────────────────────────────────────────

// State is the approval-pipeline state of a platform image.
type State string

const (
	StateQueued    State = "queued"
	StateScanned   State = "scanned"
	StateApproved  State = "approved"
	StateRescinded State = "rescinded"
	StateRejected  State = "rejected"
	StateError     State = "error"
)

// Group categorises states into coarser buckets for filtering.
type Group string

const (
	GroupPending  Group = "pending"
	GroupVerified Group = "verified"
)

// GroupOf returns the Group for the given State, or "" for StateError.
func GroupOf(s State) Group {
	switch s {
	case StateQueued, StateScanned, StateRescinded:
		return GroupPending
	case StateApproved, StateRejected:
		return GroupVerified
	default:
		return ""
	}
}

// ParseStateOrGroup converts a string to a State or Group.
// Returns the matched states (multiple for a group), or an error.
func ParseStateOrGroup(s string) ([]State, error) {
	switch State(s) {
	case StateQueued, StateScanned, StateApproved, StateRescinded, StateRejected, StateError:
		return []State{State(s)}, nil
	}
	switch Group(s) {
	case GroupPending:
		return []State{StateQueued, StateScanned, StateRescinded}, nil
	case GroupVerified:
		return []State{StateApproved, StateRejected}, nil
	}
	return nil, fmt.Errorf("unknown state or group %q", s)
}

// ── image ─────────────────────────────────────────────────────────────────────

// ImageRef is the decomposed lookup key for an image tag reference.
type ImageRef struct {
	Registry   string
	Repository string
	Tag        string
}

// Image represents one tracked OCI platform image.
// Fields are populated by JOIN across registries, tags, and images tables.
type Image struct {
	ID            int64
	TagID         int64
	RegistryURL   string          // from registries.url
	Repository    string          // from tags.repository
	TagName       string          // from tags.name
	CacheRegistry string          // URL from registries join; empty if null
	Digest        string          // platform-specific manifest digest
	Arch          string
	OS            string
	Manifest      json.RawMessage // jsonb column
	ScanReport    json.RawMessage // jsonb column
	State         State
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ── event ─────────────────────────────────────────────────────────────────────

// EventSource identifies whether an event originated from the CLI or API.
type EventSource string

const (
	SourceCLI EventSource = "cli"
	SourceAPI EventSource = "api"
)

// Event records an action taken on an image (or the system in general).
type Event struct {
	ID        int64
	ImageID   *int64
	Source    EventSource
	EventType string
	Details   map[string]interface{}
	CreatedAt time.Time
}

// ── Fetcher ───────────────────────────────────────────────────────────────────

// Fetcher is implemented by oci.Client (duck-typed — the oci package does not
// import db, avoiding a circular dependency).
type Fetcher interface {
	// FetchManifest retrieves the manifest for registry/repository:reference.
	// reference may be a tag or a digest.
	// Returns content-digest, content-type (media-type), and raw JSON body.
	FetchManifest(registry, repository, reference string) (digest, mediaType string, manifest []byte, err error)

	// FetchConfig retrieves the config blob and returns architecture and OS.
	FetchConfig(registry, repository, configDigest string) (arch, os string, err error)
}

// ── manifest media types ──────────────────────────────────────────────────────

const (
	mediaTypeOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex     = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerV2     = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerList   = "application/vnd.docker.distribution.manifest.list.v2+json"
)

func isImageManifest(mt string) bool {
	return mt == mediaTypeOCIManifest || mt == mediaTypeDockerV2
}

func isImageIndex(mt string) bool {
	return mt == mediaTypeOCIIndex || mt == mediaTypeDockerList
}

// ── DB ────────────────────────────────────────────────────────────────────────

// DB wraps the connection pool and exposes all persistence operations.
type DB struct {
	db *sql.DB
}

// Open connects to PostgreSQL, runs schema migrations, and returns a DB.
func Open(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	sqlDB.SetMaxOpenConns(10)

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("db: migrate: %w", err)
	}
	return d, nil
}

// Close shuts down the connection pool.
func (d *DB) Close() {
	d.db.Close()
}

// migrate creates tables if they don't already exist.
func (d *DB) migrate() error {
	stmts := []string{
		// Drop v1 schema tables (incompatible column layout).
		`DROP TABLE IF EXISTS events CASCADE`,
		`DROP TABLE IF EXISTS images CASCADE`,

		// registries — unique registry base URLs
		`CREATE TABLE IF NOT EXISTS registries (
			id         BIGSERIAL PRIMARY KEY,
			url        TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (url)
		)`,

		// state enum (PostgreSQL 16 supports IF NOT EXISTS on CREATE TYPE)
		`DO $$ BEGIN
			CREATE TYPE state AS ENUM
				('queued','scanned','approved','rescinded','rejected','error');
		EXCEPTION WHEN duplicate_object THEN NULL;
		END $$`,

		// tags — one row per (registry, repository, name) triple
		`CREATE TABLE IF NOT EXISTS tags (
			id         BIGSERIAL PRIMARY KEY,
			registry   BIGINT NOT NULL REFERENCES registries(id),
			repository TEXT NOT NULL,
			name       TEXT NOT NULL,
			digest     TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (registry, repository, name)
		)`,

		// images — one row per platform image
		`CREATE TABLE IF NOT EXISTS images (
			id              BIGSERIAL PRIMARY KEY,
			cache_registry  BIGINT REFERENCES registries(id),
			tag             BIGINT NOT NULL REFERENCES tags(id),
			digest          TEXT,
			arch            TEXT,
			os              TEXT,
			manifest        jsonb,
			scan_report     jsonb,
			state           state NOT NULL DEFAULT 'queued',
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (tag, digest)
		)`,

		// events — audit log
		`CREATE TABLE IF NOT EXISTS events (
			id          BIGSERIAL PRIMARY KEY,
			image_id    BIGINT REFERENCES images(id) ON DELETE SET NULL,
			source      TEXT NOT NULL,
			event_type  TEXT NOT NULL,
			details     TEXT,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		// indexes
		`CREATE INDEX IF NOT EXISTS idx_tags_registry       ON tags(registry)`,
		`CREATE INDEX IF NOT EXISTS idx_tags_digest         ON tags(digest)`,
		`CREATE INDEX IF NOT EXISTS idx_images_tag          ON images(tag)`,
		`CREATE INDEX IF NOT EXISTS idx_images_state        ON images(state)`,
		`CREATE INDEX IF NOT EXISTS idx_images_digest       ON images(digest)`,
		`CREATE INDEX IF NOT EXISTS idx_images_manifest_gin ON images USING gin(manifest)`,
		`CREATE INDEX IF NOT EXISTS idx_images_scanrpt_gin  ON images USING gin(scan_report)`,
		`CREATE INDEX IF NOT EXISTS idx_events_image_id     ON events(image_id)`,
	}
	for _, s := range stmts {
		if _, err := d.db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

// upsertRegistry inserts a registry URL if absent and returns its id.
func (d *DB) upsertRegistry(url string) (int64, error) {
	var id int64
	err := d.db.QueryRow(`
		INSERT INTO registries (url)
		VALUES ($1)
		ON CONFLICT (url) DO UPDATE SET updated_at = NOW()
		RETURNING id`,
		url,
	).Scan(&id)
	return id, err
}

// getTagID returns the id of an existing tag, or 0 if absent.
func (d *DB) getTagID(registryID int64, repository, tagName string) (int64, error) {
	var id int64
	err := d.db.QueryRow(`
		SELECT id FROM tags
		WHERE registry = $1 AND repository = $2 AND name = $3`,
		registryID, repository, tagName,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// insertTag creates a tag row and returns its id.
func (d *DB) insertTag(registryID int64, repository, tagName, digest string) (int64, error) {
	var id int64
	var dgst interface{}
	if digest != "" {
		dgst = digest
	}
	err := d.db.QueryRow(`
		INSERT INTO tags (registry, repository, name, digest)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (registry, repository, name) DO UPDATE
			SET digest = EXCLUDED.digest, updated_at = NOW()
		RETURNING id`,
		registryID, repository, tagName, dgst,
	).Scan(&id)
	return id, err
}

// insertImage inserts a platform image row; skips silently on conflict.
func (d *DB) insertImage(tagID int64, digest, arch, os string, manifest []byte) error {
	_, err := d.db.Exec(`
		INSERT INTO images (tag, digest, arch, os, manifest, state)
		VALUES ($1, $2, $3, $4, $5, 'queued')
		ON CONFLICT (tag, digest) DO NOTHING`,
		tagID, digest, arch, os, manifest,
	)
	return err
}

// imagesByTagID returns all image rows for a tag, with joined registry URL.
func (d *DB) imagesByTagID(tagID int64) ([]*Image, error) {
	rows, err := d.db.Query(`
		SELECT `+imageColumns+`
		FROM images i
		JOIN tags    t  ON t.id  = i.tag
		JOIN registries r ON r.id = t.registry
		LEFT JOIN registries cr ON cr.id = i.cache_registry
		WHERE i.tag = $1
		ORDER BY i.id`,
		tagID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanImageRows(rows)
}

// ── Queue ─────────────────────────────────────────────────────────────────────

// Queue ensures the registry, tag, and per-platform image rows exist in the DB.
// If the tag is new it fetches the manifest (and per-platform manifests for an
// image index) via fetcher, then inserts one image row per known platform.
// Returns all image rows for the tag.
func (d *DB) Queue(ref ImageRef, fetcher Fetcher) ([]*Image, error) {
	// 1. Upsert registry.
	registryID, err := d.upsertRegistry(ref.Registry)
	if err != nil {
		return nil, fmt.Errorf("upsert registry: %w", err)
	}

	// 2. If tag already exists, return its images without fetching.
	tagID, err := d.getTagID(registryID, ref.Repository, ref.Tag)
	if err != nil {
		return nil, fmt.Errorf("get tag: %w", err)
	}
	if tagID != 0 {
		return d.imagesByTagID(tagID)
	}

	// 3. Fetch the top-level manifest.
	digest, mediaType, manifest, err := fetcher.FetchManifest(ref.Registry, ref.Repository, ref.Tag)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest for %s/%s:%s: %w", ref.Registry, ref.Repository, ref.Tag, err)
	}

	// 4. Insert tag row (with the top-level digest).
	tagID, err = d.insertTag(registryID, ref.Repository, ref.Tag, digest)
	if err != nil {
		return nil, fmt.Errorf("insert tag: %w", err)
	}

	switch {
	case isImageManifest(mediaType):
		// Single-platform image.
		if err := d.queueSingleImage(tagID, digest, ref.Registry, ref.Repository, manifest, fetcher); err != nil {
			return nil, err
		}

	case isImageIndex(mediaType):
		// Multi-platform image index.
		if err := d.queueIndexImages(tagID, ref.Registry, ref.Repository, manifest, fetcher); err != nil {
			return nil, err
		}

	default:
		// Unknown media type — insert a placeholder row so the tag is tracked.
		if err := d.insertImage(tagID, digest, "", "", manifest); err != nil {
			return nil, fmt.Errorf("insert image (unknown media type): %w", err)
		}
	}

	return d.imagesByTagID(tagID)
}

// queueSingleImage fetches the config for a single-platform manifest and inserts
// an image row.
func (d *DB) queueSingleImage(tagID int64, digest, registry, repository string, manifest []byte, fetcher Fetcher) error {
	configDigest, err := extractConfigDigest(manifest)
	if err != nil {
		// Insert without arch/os if config extraction fails.
		return d.insertImage(tagID, digest, "", "", manifest)
	}
	arch, os, err := fetcher.FetchConfig(registry, repository, configDigest)
	if err != nil {
		return d.insertImage(tagID, digest, "", "", manifest)
	}
	return d.insertImage(tagID, digest, arch, os, manifest)
}

// queueIndexImages iterates the manifests in an image index, fetches each
// known platform's manifest + config, and inserts image rows.
func (d *DB) queueIndexImages(tagID int64, registry, repository string, indexManifest []byte, fetcher Fetcher) error {
	var idx struct {
		Manifests []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Platform  *struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexManifest, &idx); err != nil {
		return fmt.Errorf("parse image index: %w", err)
	}

	for _, entry := range idx.Manifests {
		// Skip unknown/attestation entries.
		if entry.Platform == nil {
			continue
		}
		if entry.Platform.OS == "unknown" || entry.Platform.Architecture == "unknown" {
			continue
		}

		// Fetch the platform-specific manifest.
		mDigest, _, mBody, err := fetcher.FetchManifest(registry, repository, entry.Digest)
		if err != nil {
			// Log and skip this platform rather than aborting the whole queue.
			continue
		}
		if mDigest == "" {
			mDigest = entry.Digest
		}

		// Fetch config for arch/os (best-effort).
		arch := entry.Platform.Architecture
		os := entry.Platform.OS
		if configDigest, err := extractConfigDigest(mBody); err == nil {
			if a, o, err := fetcher.FetchConfig(registry, repository, configDigest); err == nil {
				arch, os = a, o
			}
		}

		if err := d.insertImage(tagID, mDigest, arch, os, mBody); err != nil {
			return fmt.Errorf("insert image %s: %w", mDigest, err)
		}
	}
	return nil
}

// extractConfigDigest returns the digest from the manifest's config descriptor.
func extractConfigDigest(manifest []byte) (string, error) {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return "", err
	}
	if m.Config.Digest == "" {
		return "", fmt.Errorf("no config digest in manifest")
	}
	return m.Config.Digest, nil
}

// ── image scan ────────────────────────────────────────────────────────────────

// SaveScan stores the trivy scan report for an image and sets its state to scanned.
func (d *DB) SaveScan(imageID int64, scanReport json.RawMessage) (*Image, error) {
	_, err := d.db.Exec(`
		UPDATE images SET
			scan_report = $1,
			state       = 'scanned',
			updated_at  = NOW()
		WHERE id = $2`,
		[]byte(scanReport), imageID,
	)
	if err != nil {
		return nil, err
	}
	return d.GetByID(imageID)
}

// ── state transitions ─────────────────────────────────────────────────────────

// Approve sets a platform image's state to approved and optionally records the
// cache registry URL.
func (d *DB) Approve(imageID int64, cacheRegistry string) error {
	var cacheRegID interface{}
	if cacheRegistry != "" {
		id, err := d.upsertRegistry(cacheRegistry)
		if err != nil {
			return fmt.Errorf("upsert cache registry: %w", err)
		}
		cacheRegID = id
	}
	_, err := d.db.Exec(`
		UPDATE images SET
			state          = 'approved',
			cache_registry = $1,
			updated_at     = NOW()
		WHERE id = $2`,
		cacheRegID, imageID,
	)
	return err
}

// Rescind sets a platform image's state to rescinded.
func (d *DB) Rescind(imageID int64) error {
	return d.setImageState(imageID, StateRescinded)
}

// Reject sets a platform image's state to rejected.
func (d *DB) Reject(imageID int64) error {
	return d.setImageState(imageID, StateRejected)
}

// SetError sets a platform image's state to error.
func (d *DB) SetError(imageID int64) error {
	return d.setImageState(imageID, StateError)
}

func (d *DB) setImageState(imageID int64, state State) error {
	_, err := d.db.Exec(`
		UPDATE images SET state = $1, updated_at = NOW()
		WHERE id = $2`,
		string(state), imageID,
	)
	return err
}

// ── image queries ─────────────────────────────────────────────────────────────

// imageColumns is the SELECT column list for all image queries (requires joins
// with aliases i, t, r, cr).
const imageColumns = `
	i.id, i.tag, r.url, t.repository, t.name,
	COALESCE(cr.url, ''),
	COALESCE(i.digest, ''), COALESCE(i.arch, ''), COALESCE(i.os, ''),
	COALESCE(i.manifest::text, 'null'), COALESCE(i.scan_report::text, 'null'),
	i.state::text, i.created_at, i.updated_at`

func scanImageRow(row *sql.Row) (*Image, error) {
	img := &Image{}
	var manifestStr, scanReportStr, stateStr string
	err := row.Scan(
		&img.ID, &img.TagID, &img.RegistryURL, &img.Repository, &img.TagName,
		&img.CacheRegistry,
		&img.Digest, &img.Arch, &img.OS,
		&manifestStr, &scanReportStr,
		&stateStr, &img.CreatedAt, &img.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	img.State = State(stateStr)
	img.Manifest = json.RawMessage(manifestStr)
	img.ScanReport = json.RawMessage(scanReportStr)
	return img, nil
}

func scanImageRows(rows *sql.Rows) ([]*Image, error) {
	var out []*Image
	for rows.Next() {
		img := &Image{}
		var manifestStr, scanReportStr, stateStr string
		if err := rows.Scan(
			&img.ID, &img.TagID, &img.RegistryURL, &img.Repository, &img.TagName,
			&img.CacheRegistry,
			&img.Digest, &img.Arch, &img.OS,
			&manifestStr, &scanReportStr,
			&stateStr, &img.CreatedAt, &img.UpdatedAt,
		); err != nil {
			return nil, err
		}
		img.State = State(stateStr)
		img.Manifest = json.RawMessage(manifestStr)
		img.ScanReport = json.RawMessage(scanReportStr)
		out = append(out, img)
	}
	return out, rows.Err()
}

// GetByID returns the Image with the given id, or nil if not found.
func (d *DB) GetByID(id int64) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageColumns+`
		FROM images i
		JOIN tags    t  ON t.id  = i.tag
		JOIN registries r ON r.id = t.registry
		LEFT JOIN registries cr ON cr.id = i.cache_registry
		WHERE i.id = $1`,
		id,
	)
	return scanImageRow(row)
}

// GetByRef returns all platform images for the given tag reference.
func (d *DB) GetByRef(ref ImageRef) ([]*Image, error) {
	rows, err := d.db.Query(`
		SELECT `+imageColumns+`
		FROM images i
		JOIN tags    t  ON t.id  = i.tag
		JOIN registries r ON r.id = t.registry
		LEFT JOIN registries cr ON cr.id = i.cache_registry
		WHERE r.url = $1 AND t.repository = $2 AND t.name = $3
		ORDER BY i.id`,
		ref.Registry, ref.Repository, ref.Tag,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanImageRows(rows)
}

// GetApproved returns the first approved platform image for the given tag, or nil.
func (d *DB) GetApproved(registry, repository, tag string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageColumns+`
		FROM images i
		JOIN tags    t  ON t.id  = i.tag
		JOIN registries r ON r.id = t.registry
		LEFT JOIN registries cr ON cr.id = i.cache_registry
		WHERE r.url = $1 AND t.repository = $2 AND t.name = $3
		  AND i.state = 'approved'
		ORDER BY i.id
		LIMIT 1`,
		registry, repository, tag,
	)
	return scanImageRow(row)
}

// GetApprovedByDigest returns an approved image matching the given digest, or nil.
func (d *DB) GetApprovedByDigest(registry, repository, digest string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageColumns+`
		FROM images i
		JOIN tags    t  ON t.id  = i.tag
		JOIN registries r ON r.id = t.registry
		LEFT JOIN registries cr ON cr.id = i.cache_registry
		WHERE r.url = $1 AND t.repository = $2
		  AND i.digest = $3
		  AND i.state = 'approved'
		LIMIT 1`,
		registry, repository, digest,
	)
	return scanImageRow(row)
}

// GetApprovedByTagAndDigest returns an approved image matching digest whose tag
// name also equals tag, or nil.
func (d *DB) GetApprovedByTagAndDigest(registry, repository, tag, digest string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageColumns+`
		FROM images i
		JOIN tags    t  ON t.id  = i.tag
		JOIN registries r ON r.id = t.registry
		LEFT JOIN registries cr ON cr.id = i.cache_registry
		WHERE r.url = $1 AND t.repository = $2 AND t.name = $3
		  AND i.digest = $4
		  AND i.state = 'approved'
		LIMIT 1`,
		registry, repository, tag, digest,
	)
	return scanImageRow(row)
}

// ── list ──────────────────────────────────────────────────────────────────────

// ListFilter specifies optional filters for List.
type ListFilter struct {
	States []State  // empty = all
	Refs   []string // "namespace/name[:tag]" patterns; empty = all
}

// List returns images ordered by updated_at DESC, with optional filtering.
func (d *DB) List(f ListFilter) ([]Image, error) {
	var (
		conditions []string
		args       []interface{}
		argIdx     = 1
	)

	if len(f.States) > 0 {
		stateStrs := make([]string, len(f.States))
		for i, s := range f.States {
			stateStrs[i] = string(s)
		}
		conditions = append(conditions, fmt.Sprintf("i.state::text = ANY($%d)", argIdx))
		args = append(args, pq.Array(stateStrs))
		argIdx++
	}

	if len(f.Refs) > 0 {
		var refConds []string
		for _, r := range f.Refs {
			tag := ""
			if idx := strings.LastIndex(r, ":"); idx > 0 {
				tag = r[idx+1:]
				r = r[:idx]
			}
			if tag != "" {
				refConds = append(refConds, fmt.Sprintf(
					"(t.repository = $%d AND t.name = $%d)",
					argIdx, argIdx+1,
				))
				args = append(args, r, tag)
				argIdx += 2
			} else {
				refConds = append(refConds, fmt.Sprintf("t.repository = $%d", argIdx))
				args = append(args, r)
				argIdx++
			}
		}
		conditions = append(conditions, "("+strings.Join(refConds, " OR ")+")")
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT `+imageColumns+`
		FROM images i
		JOIN tags    t  ON t.id  = i.tag
		JOIN registries r ON r.id = t.registry
		LEFT JOIN registries cr ON cr.id = i.cache_registry
		%s
		ORDER BY i.updated_at DESC`, where)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ptrs, err := scanImageRows(rows)
	if err != nil {
		return nil, err
	}
	out := make([]Image, len(ptrs))
	for i, p := range ptrs {
		out[i] = *p
	}
	return out, nil
}

// ── event logging ─────────────────────────────────────────────────────────────

// LogEvent records an event. imageID may be nil for non-image events.
func (d *DB) LogEvent(imageID *int64, source EventSource, eventType string, details map[string]interface{}) error {
	var detailsJSON interface{}
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err == nil {
			detailsJSON = string(b)
		}
	}
	_, err := d.db.Exec(`
		INSERT INTO events (image_id, source, event_type, details)
		VALUES ($1, $2, $3, $4)`,
		imageID, string(source), eventType, detailsJSON,
	)
	return err
}
