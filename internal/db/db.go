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

// State is the approval-pipeline state of an image tag.
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

// ParseState converts a string to a State or Group.
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

// ImageRef is the decomposed lookup key for an image reference.
type ImageRef struct {
	Registry   string
	Repository string
	Tag        string
}

// Image represents one tracked OCI image tag.
type Image struct {
	ID            int64
	Registry      string
	Repository    string
	Tag           string
	Digest        string // may be empty for queued images
	Manifest      string // raw JSON, may be empty
	ScanReport    string // raw JSON trivy report, may be empty
	State         State
	CacheRegistry string // set after successful cache push
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
		`CREATE TABLE IF NOT EXISTS images (
			id              BIGSERIAL PRIMARY KEY,
			registry        TEXT NOT NULL,
			repository      TEXT NOT NULL,
			tag             TEXT NOT NULL,
			digest          TEXT,
			manifest        TEXT,
			scan_report     TEXT,
			state           TEXT NOT NULL DEFAULT 'queued',
			cache_registry  TEXT,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (registry, repository, tag)
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id          BIGSERIAL PRIMARY KEY,
			image_id    BIGINT REFERENCES images(id) ON DELETE SET NULL,
			source      TEXT NOT NULL,
			event_type  TEXT NOT NULL,
			details     TEXT,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_images_state      ON images(state)`,
		`CREATE INDEX IF NOT EXISTS idx_images_repo_tag   ON images(repository, tag)`,
		`CREATE INDEX IF NOT EXISTS idx_events_image_id   ON events(image_id)`,
	}
	for _, s := range stmts {
		if _, err := d.db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// ── image operations ──────────────────────────────────────────────────────────

// Queue inserts a new image record with state=queued, or returns the existing
// record unchanged.  Returns the (possibly pre-existing) image.
func (d *DB) Queue(ref ImageRef) (*Image, error) {
	_, err := d.db.Exec(`
		INSERT INTO images (registry, repository, tag, state)
		VALUES ($1, $2, $3, 'queued')
		ON CONFLICT (registry, repository, tag) DO NOTHING`,
		ref.Registry, ref.Repository, ref.Tag,
	)
	if err != nil {
		return nil, err
	}
	return d.GetByRef(ref)
}

// SaveScan stores the digest, manifest, and scan report for an image and sets
// its state to scanned.
func (d *DB) SaveScan(ref ImageRef, digest, manifest, scanReport string) (*Image, error) {
	_, err := d.db.Exec(`
		INSERT INTO images (registry, repository, tag, digest, manifest, scan_report, state, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'scanned', NOW())
		ON CONFLICT (registry, repository, tag) DO UPDATE SET
			digest      = EXCLUDED.digest,
			manifest    = EXCLUDED.manifest,
			scan_report = EXCLUDED.scan_report,
			state       = 'scanned',
			updated_at  = NOW()`,
		ref.Registry, ref.Repository, ref.Tag, digest, manifest, scanReport,
	)
	if err != nil {
		return nil, err
	}
	return d.GetByRef(ref)
}

// Approve sets an image's state to approved and optionally records the cache registry.
func (d *DB) Approve(ref ImageRef, cacheRegistry string) error {
	var cr interface{}
	if cacheRegistry != "" {
		cr = cacheRegistry
	}
	_, err := d.db.Exec(`
		UPDATE images SET
			state          = 'approved',
			cache_registry = $1,
			updated_at     = NOW()
		WHERE registry = $2 AND repository = $3 AND tag = $4`,
		cr, ref.Registry, ref.Repository, ref.Tag,
	)
	return err
}

// Rescind sets state to rescinded.
func (d *DB) Rescind(ref ImageRef) error {
	return d.setState(ref, StateRescinded)
}

// Reject sets state to rejected.
func (d *DB) Reject(ref ImageRef) error {
	return d.setState(ref, StateRejected)
}

// SetError sets state to error with a reason stored in a new event.
func (d *DB) SetError(ref ImageRef) error {
	return d.setState(ref, StateError)
}

func (d *DB) setState(ref ImageRef, state State) error {
	_, err := d.db.Exec(`
		UPDATE images SET state = $1, updated_at = NOW()
		WHERE registry = $2 AND repository = $3 AND tag = $4`,
		string(state), ref.Registry, ref.Repository, ref.Tag,
	)
	return err
}

// imageColumns is the SELECT column list used by all image queries.
const imageColumns = `id, registry, repository, tag,
	COALESCE(digest,''), COALESCE(manifest,''), COALESCE(scan_report,''),
	state, COALESCE(cache_registry,''),
	created_at, updated_at`

func scanImageRow(row *sql.Row) (*Image, error) {
	img := &Image{}
	err := row.Scan(
		&img.ID, &img.Registry, &img.Repository, &img.Tag,
		&img.Digest, &img.Manifest, &img.ScanReport,
		(*string)(&img.State), &img.CacheRegistry,
		&img.CreatedAt, &img.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return img, err
}

// GetByRef returns the Image for ref, or nil if not found.
func (d *DB) GetByRef(ref ImageRef) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageColumns+`
		FROM images
		WHERE registry = $1 AND repository = $2 AND tag = $3
		LIMIT 1`,
		ref.Registry, ref.Repository, ref.Tag,
	)
	return scanImageRow(row)
}

// GetApproved returns an approved image matching registry+repository+tag, or nil.
func (d *DB) GetApproved(registry, repository, tag string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageColumns+`
		FROM images
		WHERE registry = $1 AND repository = $2 AND tag = $3
		  AND state = 'approved'
		LIMIT 1`,
		registry, repository, tag,
	)
	return scanImageRow(row)
}

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
		conditions = append(conditions, fmt.Sprintf("state = ANY($%d)", argIdx))
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
					"(repository = $%d AND tag = $%d)",
					argIdx, argIdx+1,
				))
				args = append(args, r, tag)
				argIdx += 2
			} else {
				refConds = append(refConds, fmt.Sprintf("repository = $%d", argIdx))
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
		FROM images
		%s
		ORDER BY updated_at DESC`, where)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Image
	for rows.Next() {
		var img Image
		if err := rows.Scan(
			&img.ID, &img.Registry, &img.Repository, &img.Tag,
			&img.Digest, &img.Manifest, &img.ScanReport,
			(*string)(&img.State), &img.CacheRegistry,
			&img.CreatedAt, &img.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, img)
	}
	return out, rows.Err()
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
