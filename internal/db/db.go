// Package db manages the hermes PostgreSQL schema and all image/event persistence.
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
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
	StateVoided    State = "voided"
	StateRejected  State = "rejected"
	StateErrored   State = "errored"
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
	case StateQueued, StateScanned, StateRescinded, StateVoided:
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
	case StateQueued, StateScanned, StateApproved, StateRescinded, StateVoided, StateRejected, StateErrored:
		return []State{State(s)}, nil
	}
	switch Group(s) {
	case GroupPending:
		return []State{StateQueued, StateScanned, StateRescinded, StateVoided}, nil
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
	RegistryURL   string // from registries.url
	Repository    string // from tags.repository
	TagName       string // from tags.name
	CacheRegistry string // URL from registries join; empty if null
	Digest        string // platform-specific manifest digest
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
	mediaTypeOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex    = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerV2    = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerList  = "application/vnd.docker.distribution.manifest.list.v2+json"
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
		_ = sqlDB.Close()
		return nil, fmt.Errorf("db: migrate: %w", err)
	}
	return d, nil
}

// Close shuts down the connection pool.
func (d *DB) Close() {
	_ = d.db.Close()
}

// migrate creates tables if they don't already exist.
func (d *DB) migrate() error {
	stmts := []string{
		// registries — unique registry base URLs
		`CREATE TABLE IF NOT EXISTS registries (
			id         BIGSERIAL PRIMARY KEY,
			mask       BIGINT REFERENCES registries(id),
			url        TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (url)
		)`,

		// seed docker.io mask
		`INSERT INTO registries (url)
			VALUES ('docker.io')
			ON CONFLICT (url) DO NOTHING
		`,
		// seed and mask Docker registries
		`INSERT INTO registries (url, mask)
			SELECT new_data.url, r.id
			FROM (
				VALUES ('index.docker.io'), ('registry-1.docker.io')
			) AS new_data(url)
			CROSS JOIN registries r
			WHERE r.url = 'docker.io'
			ON CONFLICT (url) DO NOTHING
		`,

		// state enum (PostgreSQL 16 supports IF NOT EXISTS on CREATE TYPE)
		`DO $$ BEGIN
			CREATE TYPE state AS ENUM
				('queued','scanned','approved','rescinded','voided','rejected','errored');
		EXCEPTION WHEN duplicate_object THEN NULL;
		END $$`,

		// tags — one row per (registry, repository, name) triple.
		// digest holds the top-level (manifest or index) digest the tag resolved to.
		`CREATE TABLE IF NOT EXISTS tags (
			id         BIGSERIAL PRIMARY KEY,
			registry   BIGINT NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
			repository TEXT NOT NULL,
			name       TEXT NOT NULL,
			digest     TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (registry, repository, name)
		)`,

		// images — one row per platform image, identified independently of any
		// tag.  Multiple tags may reference the same image via tag_images.
		`CREATE TABLE IF NOT EXISTS images (
			id              BIGSERIAL PRIMARY KEY,
			registry        BIGINT NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
			repository      TEXT NOT NULL,
			cache_registry  BIGINT REFERENCES registries(id) ON DELETE SET NULL,
			digest          TEXT NOT NULL,
			arch            TEXT,
			os              TEXT,
			manifest        jsonb,
			scan_report     jsonb,
			state           state NOT NULL DEFAULT 'queued',
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (registry, repository, digest)
		)`,

		// tag_images — many-to-many link between tags and images.
		// A tag with no rows in this table is a "stub" (seen but not yet populated).
		`CREATE TABLE IF NOT EXISTS tag_images (
			tag        BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
			image      BIGINT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (tag, image)
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
		`CREATE INDEX IF NOT EXISTS idx_tags_digest         ON tags(registry, repository, digest)`,
		`CREATE INDEX IF NOT EXISTS idx_images_state        ON images(state)`,
		`CREATE INDEX IF NOT EXISTS idx_images_lookup       ON images(registry, repository, digest)`,
		`CREATE INDEX IF NOT EXISTS idx_images_manifest_gin ON images USING gin(manifest)`,
		`CREATE INDEX IF NOT EXISTS idx_images_scanrpt_gin  ON images USING gin(scan_report)`,
		`CREATE INDEX IF NOT EXISTS idx_tag_images_image    ON tag_images(image)`,
		`CREATE INDEX IF NOT EXISTS idx_events_image_id     ON events(image_id)`,

		// tag_image_rows — canonical SELECT shape for every image query.
		// A LEFT JOIN through tag_images lets stub tags (no linked image)
		// appear as synthesised rows with image_id = 0 and state = 'queued',
		// so callers do not need to duplicate the COALESCE column list.
		// Both image_digest (platform-specific) and tag_digest (top-level
		// manifest or index digest) are exposed so approval queries can
		// select whichever is appropriate for upstream forwarding.
		`CREATE OR REPLACE VIEW tag_image_rows AS
			SELECT
				COALESCE(i.id, 0)                     AS image_id,
				t.id                                  AS tag_id,
				r.url                                 AS registry_url,
				t.repository                          AS repository,
				t.name                                AS tag_name,
				COALESCE(cr.url, '')                  AS cache_registry_url,
				COALESCE(i.digest, '')                AS image_digest,
				COALESCE(t.digest, '')                AS tag_digest,
				COALESCE(i.arch, '')                  AS arch,
				COALESCE(i.os, '')                    AS os,
				COALESCE(i.manifest::text, 'null')    AS manifest,
				COALESCE(i.scan_report::text, 'null') AS scan_report,
				COALESCE(i.state::text, 'queued')     AS state,
				COALESCE(i.created_at, t.created_at)  AS created_at,
				COALESCE(i.updated_at, t.updated_at)  AS updated_at
			FROM tags t
			JOIN registries r       ON r.id  = t.registry
			LEFT JOIN tag_images ti ON ti.tag = t.id
			LEFT JOIN images i      ON i.id  = ti.image
			LEFT JOIN registries cr ON cr.id = i.cache_registry`,
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

// insertImage inserts a platform image row keyed on (registry, repository,
// digest) and returns its id.  Empty arch/os values are stored as NULL so an
// upsert never overwrites better data with blanks.  Existing rows are left
// unchanged (state, scan_report, etc. are preserved) and their id is returned.
func (d *DB) insertImage(registryID int64, repository, digest, arch, os string, manifest []byte) (int64, error) {
	var id int64
	err := d.db.QueryRow(`
		INSERT INTO images (registry, repository, digest, arch, os, manifest)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6)
		ON CONFLICT (registry, repository, digest) DO UPDATE
			SET updated_at = NOW()
		RETURNING id`,
		registryID, repository, digest, arch, os, manifest,
	).Scan(&id)
	return id, err
}

// linkTagImage adds a (tag, image) pair to tag_images.  Idempotent.
func (d *DB) linkTagImage(tagID, imageID int64) error {
	_, err := d.db.Exec(`
		INSERT INTO tag_images (tag, image)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`,
		tagID, imageID,
	)
	return err
}

// imagesByTagID returns all real image rows linked to the given tag.  Returns
// an empty slice for stub tags (no tag_images entries).
func (d *DB) imagesByTagID(tagID int64) ([]*Image, error) {
	rows, err := d.db.Query(`
		SELECT `+imageCols+`
		FROM tag_image_rows
		WHERE tag_id = $1 AND image_id <> 0
		ORDER BY image_id`,
		tagID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanImageRows(rows)
}

// ── Queue ─────────────────────────────────────────────────────────────────────

// QueueStub ensures the registry and tag rows exist without making any
// outbound registry calls.  It is used by the API server to register a
// first-seen tag so operators can see it in 'hermes list'.  A stub tag has no
// linked image rows; manifest fetching and image insertion happen lazily the
// first time the operator runs scan/approve (or when the API later adopts the
// tag via AdoptTagByDigest).
func (d *DB) QueueStub(ref ImageRef) error {
	registryID, err := d.upsertRegistry(ref.Registry)
	if err != nil {
		return fmt.Errorf("upsert registry: %w", err)
	}
	tagID, err := d.getTagID(registryID, ref.Repository, ref.Tag)
	if err != nil {
		return fmt.Errorf("get tag: %w", err)
	}
	if tagID == 0 {
		if _, err := d.insertTag(registryID, ref.Repository, ref.Tag, ""); err != nil {
			return fmt.Errorf("insert stub tag: %w", err)
		}
	}
	return nil
}

// Queue ensures the registry, tag, and per-platform image rows exist in the DB.
// If the tag has no linked image rows yet (including when stub-registered by
// the API) it fetches the manifest via fetcher and either:
//   - adopts existing image rows when another tag in the same repository
//     already references the upstream-returned digest (alternate-tag case), or
//   - inserts new image rows per platform.
//
// Returns all image rows linked to the tag.
func (d *DB) Queue(ref ImageRef, fetcher Fetcher) ([]*Image, error) {
	// 1. Upsert registry.
	registryID, err := d.upsertRegistry(ref.Registry)
	if err != nil {
		return nil, fmt.Errorf("upsert registry: %w", err)
	}

	// 2. Check whether the tag already exists and is fully populated.
	tagID, err := d.getTagID(registryID, ref.Repository, ref.Tag)
	if err != nil {
		return nil, fmt.Errorf("get tag: %w", err)
	}
	if tagID != 0 {
		imgs, err := d.imagesByTagID(tagID)
		if err != nil {
			return nil, fmt.Errorf("get images: %w", err)
		}
		if len(imgs) > 0 {
			return imgs, nil
		}
		// Stub tag (no linked images) — fall through to populate.
	}

	// 3. Fetch the top-level manifest.
	digest, mediaType, manifest, err := fetcher.FetchManifest(ref.Registry, ref.Repository, ref.Tag)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest for %s/%s:%s: %w", ref.Registry, ref.Repository, ref.Tag, err)
	}

	// 4. Look for existing images already known at this digest (alt-tag case).
	existingIDs, err := d.findImageIDsByTagDigest(registryID, ref.Repository, digest)
	if err != nil {
		return nil, fmt.Errorf("find images by digest: %w", err)
	}

	// 5. Upsert the tag row with the resolved digest.
	tagID, err = d.insertTag(registryID, ref.Repository, ref.Tag, digest)
	if err != nil {
		return nil, fmt.Errorf("insert tag: %w", err)
	}

	if len(existingIDs) > 0 {
		// Adopt — link existing images to the new tag and skip refetching.
		for _, imgID := range existingIDs {
			if err := d.linkTagImage(tagID, imgID); err != nil {
				return nil, fmt.Errorf("link tag→image: %w", err)
			}
		}
		return d.imagesByTagID(tagID)
	}

	// 6. No alt-tag match — populate normally.
	switch {
	case isImageManifest(mediaType):
		if err := d.queueSingleImage(tagID, registryID, ref.Registry, ref.Repository, digest, manifest, fetcher); err != nil {
			return nil, err
		}
	case isImageIndex(mediaType):
		if err := d.queueIndexImages(tagID, registryID, ref.Registry, ref.Repository, manifest, fetcher); err != nil {
			return nil, err
		}
	default:
		// Unknown media type — insert a minimal image row so the tag is tracked.
		imgID, err := d.insertImage(registryID, ref.Repository, digest, "", "", manifest)
		if err != nil {
			return nil, fmt.Errorf("insert image (unknown media type): %w", err)
		}
		if err := d.linkTagImage(tagID, imgID); err != nil {
			return nil, fmt.Errorf("link image: %w", err)
		}
	}

	return d.imagesByTagID(tagID)
}

// findImageIDsByTagDigest returns the distinct ids of all images currently
// linked to any tag in (registryID, repository) whose digest equals the given
// value.  This drives the alternate-tag adoption path.
func (d *DB) findImageIDsByTagDigest(registryID int64, repository, digest string) ([]int64, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT ti.image
		FROM tags t
		JOIN tag_images ti ON ti.tag = t.id
		WHERE t.registry = $1 AND t.repository = $2 AND t.digest = $3`,
		registryID, repository, digest,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// queueSingleImage inserts a row for a single-platform manifest, best-effort
// resolving arch/os from the image config, then links it to the tag.
func (d *DB) queueSingleImage(tagID, registryID int64, registry, repository, digest string, manifest []byte, fetcher Fetcher) error {
	var arch, os string
	if configDigest, err := extractConfigDigest(manifest); err == nil {
		if a, o, err := fetcher.FetchConfig(registry, repository, configDigest); err == nil {
			arch, os = a, o
		}
	}
	imgID, err := d.insertImage(registryID, repository, digest, arch, os, manifest)
	if err != nil {
		return fmt.Errorf("insert image: %w", err)
	}
	return d.linkTagImage(tagID, imgID)
}

// queueIndexImages iterates the manifests in an image index, fetches each
// known platform's manifest + config, inserts image rows, and links them to
// the tag.
func (d *DB) queueIndexImages(tagID, registryID int64, registry, repository string, indexManifest []byte, fetcher Fetcher) error {
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

		imgID, err := d.insertImage(registryID, repository, mDigest, arch, os, mBody)
		if err != nil {
			return fmt.Errorf("insert image %s: %w", mDigest, err)
		}
		if err := d.linkTagImage(tagID, imgID); err != nil {
			return fmt.Errorf("link image %s: %w", mDigest, err)
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

// Void sets a platform image's state to voided — its digest no longer
// exists upstream and the image was not cached, so it cannot be served.
func (d *DB) Void(imageID int64) error {
	return d.setImageState(imageID, StateVoided)
}

// VoidByBlob flips every approved, uncached image in (registry, repository)
// whose manifest references digest (as the config or one of the layers) to
// the voided state.  Cached images are left alone — they remain servable
// from the cache registry regardless of upstream state.  Returns the IDs of
// the images that were voided so the caller can log them in an audit event.
func (d *DB) VoidByBlob(registry, repository, digest string) ([]int64, error) {
	configContains, err := json.Marshal(map[string]any{
		"config": map[string]string{"digest": digest},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal config containment: %w", err)
	}
	layersContains, err := json.Marshal(map[string]any{
		"layers": []map[string]string{{"digest": digest}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal layers containment: %w", err)
	}

	rows, err := d.db.Query(`
		UPDATE images
		SET state = 'voided', updated_at = NOW()
		WHERE id IN (
			SELECT i.id
			FROM images i
			JOIN registries r ON r.id = i.registry
			WHERE r.url = $1 AND i.repository = $2
			  AND i.state = 'approved'
			  AND i.cache_registry IS NULL
			  AND (i.manifest @> $3::jsonb OR i.manifest @> $4::jsonb)
		)
		RETURNING id`,
		registry, repository, string(configContains), string(layersContains),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Reject sets a platform image's state to rejected.
func (d *DB) Reject(imageID int64) error {
	return d.setImageState(imageID, StateRejected)
}

// SetError sets a platform image's state to error.
func (d *DB) SetError(imageID int64) error {
	return d.setImageState(imageID, StateErrored)
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

// imageCols is the default SELECT column list for queries against the
// tag_image_rows view.  It returns the platform image digest (image_digest)
// as the .Digest field, which is what callers want for digest-addressed
// lookups and general listing.
const imageCols = `
	image_id, tag_id, registry_url, repository, tag_name,
	cache_registry_url, image_digest, arch, os,
	manifest, scan_report, state, created_at, updated_at`

// imageColsTagDigest is the column list for queries that want the tag's
// top-level (manifest or index) digest as the .Digest field — used by
// GetApproved so the gateway forwards tag requests pinned to the resolved
// upstream digest.
const imageColsTagDigest = `
	image_id, tag_id, registry_url, repository, tag_name,
	cache_registry_url, tag_digest, arch, os,
	manifest, scan_report, state, created_at, updated_at`

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

// GetByID returns the Image with the given id, or nil if not found.  When the
// image is linked to multiple tags the row from the lowest-id tag is returned.
func (d *DB) GetByID(id int64) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageCols+`
		FROM tag_image_rows
		WHERE image_id = $1
		ORDER BY tag_id
		LIMIT 1`,
		id,
	)
	return scanImageRow(row)
}

// GetByRef returns all platform images linked to the given tag reference.
// Stub tags (no linked images) yield a single synthesised row with empty
// digest/arch/os and state 'queued', so callers can still discover the tag.
func (d *DB) GetByRef(ref ImageRef) ([]*Image, error) {
	rows, err := d.db.Query(`
		SELECT `+imageCols+`
		FROM tag_image_rows
		WHERE registry_url = $1 AND repository = $2 AND tag_name = $3
		ORDER BY image_id`,
		ref.Registry, ref.Repository, ref.Tag,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanImageRows(rows)
}

// GetApproved returns the first approved platform image linked to the given
// tag, or nil.  The returned image's Digest is the tag's top-level digest
// (manifest or index) so callers can pin the upstream request.
func (d *DB) GetApproved(registry, repository, tag string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageColsTagDigest+`
		FROM tag_image_rows
		WHERE registry_url = $1 AND repository = $2 AND tag_name = $3
		  AND state = 'approved'
		ORDER BY image_id
		LIMIT 1`,
		registry, repository, tag,
	)
	return scanImageRow(row)
}

// GetApprovedByDigest returns an approved image matching the given digest, or
// nil.  The lookup matches both platform-manifest digests (images.digest) and
// top-level/index digests (tags.digest with at least one approved linked
// image).  The returned image's Digest field echoes the requested digest so
// callers may forward the request unchanged.
func (d *DB) GetApprovedByDigest(registry, repository, digest string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT
			image_id, tag_id, registry_url, repository, tag_name,
			cache_registry_url, $3::text, arch, os,
			manifest, scan_report, state, created_at, updated_at
		FROM tag_image_rows
		WHERE registry_url = $1 AND repository = $2
		  AND (image_digest = $3 OR tag_digest = $3)
		  AND state = 'approved'
		ORDER BY CASE WHEN image_digest = $3 THEN 0 ELSE 1 END, image_id
		LIMIT 1`,
		registry, repository, digest,
	)
	return scanImageRow(row)
}

// GetApprovedByTagAndDigest returns an approved image matching the given
// digest whose tag name also equals tag, or nil.  Like GetApprovedByDigest the
// lookup considers both platform and top-level digests.
func (d *DB) GetApprovedByTagAndDigest(registry, repository, tag, digest string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT
			image_id, tag_id, registry_url, repository, tag_name,
			cache_registry_url, $4::text, arch, os,
			manifest, scan_report, state, created_at, updated_at
		FROM tag_image_rows
		WHERE registry_url = $1 AND repository = $2 AND tag_name = $3
		  AND (image_digest = $4 OR tag_digest = $4)
		  AND state = 'approved'
		ORDER BY CASE WHEN image_digest = $4 THEN 0 ELSE 1 END, image_id
		LIMIT 1`,
		registry, repository, tag, digest,
	)
	return scanImageRow(row)
}

// GetRejected returns the first rejected platform image linked to the given
// tag, or nil.
func (d *DB) GetRejected(registry, repository, tag string) (*Image, error) {
	row := d.db.QueryRow(`
		SELECT `+imageCols+`
		FROM tag_image_rows
		WHERE registry_url = $1 AND repository = $2 AND tag_name = $3
		  AND state = 'rejected'
		ORDER BY image_id
		LIMIT 1`,
		registry, repository, tag,
	)
	return scanImageRow(row)
}

// ── list ──────────────────────────────────────────────────────────────────────

// ListFilter specifies optional filters for List.
type ListFilter struct {
	States []State  // empty = all
	Refs   []string // "namespace/name[:tag]" patterns; empty = all
	OS     string   // exact match, "" = any
	Arch   string   // exact match, "" = any
}

// List returns images ordered by updated_at DESC, with optional filtering.
// Stub tags (no linked images) are included as synthesised rows with state
// 'queued' and empty digest/arch/os fields.
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

	if f.OS != "" {
		conditions = append(conditions, fmt.Sprintf("os = $%d", argIdx))
		args = append(args, f.OS)
		argIdx++
	}
	if f.Arch != "" {
		conditions = append(conditions, fmt.Sprintf("arch = $%d", argIdx))
		args = append(args, f.Arch)
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
					"(repository = $%d AND tag_name = $%d)",
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
		SELECT `+imageCols+`
		FROM tag_image_rows
		%s
		ORDER BY updated_at DESC`, where)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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

// ── blob authorization ────────────────────────────────────────────────────────

// BlobAuthorized reports whether the given blob digest belongs to an approved
// image in (registry, repository).  A blob is authorized when it appears as
// either the config digest or one of the layer digests of an approved image's
// manifest.  The check uses jsonb containment so the GIN index on images.manifest
// can answer it without scanning rows.
//
// The second return is the cache registry URL to forward the blob request to:
// when at least one owning image has cache_registry set hermes serves the blob
// from cache (protecting against upstream removal), preferring cached owners
// over uncached ones and breaking ties by the smallest image id.  An empty
// string means "forward to origin".
func (d *DB) BlobAuthorized(registry, repository, digest string) (bool, string, error) {
	configContains, err := json.Marshal(map[string]any{
		"config": map[string]string{"digest": digest},
	})
	if err != nil {
		return false, "", fmt.Errorf("marshal config containment: %w", err)
	}
	layersContains, err := json.Marshal(map[string]any{
		"layers": []map[string]string{{"digest": digest}},
	})
	if err != nil {
		return false, "", fmt.Errorf("marshal layers containment: %w", err)
	}

	var cacheURL sql.NullString
	err = d.db.QueryRow(`
		SELECT COALESCE(cr.url, '')
		FROM images i
		JOIN registries r        ON r.id  = i.registry
		LEFT JOIN registries cr  ON cr.id = i.cache_registry
		WHERE r.url = $1 AND i.repository = $2
		  AND i.state = 'approved'
		  AND (i.manifest @> $3::jsonb OR i.manifest @> $4::jsonb)
		ORDER BY (i.cache_registry IS NULL), i.id
		LIMIT 1`,
		registry, repository, string(configContains), string(layersContains),
	).Scan(&cacheURL)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, cacheURL.String, nil
}

// ── alternate-tag adoption ────────────────────────────────────────────────────

// AdoptTagByDigest looks for image rows already linked to any tag in
// (registry, repository) whose digest equals the given value, and links them
// to a (newly created if needed) tag with the supplied name.  It returns true
// when at least one of the adopted images is in the approved state, signalling
// to the caller that the new tag may be served immediately.
//
// This is the alternate-tag detection helper used by the API server: when an
// unknown tag is requested but the upstream returns a manifest digest that is
// already known and approved in the DB, the new tag inherits the existing
// approval state without re-fetching or re-scanning.
func (d *DB) AdoptTagByDigest(ref ImageRef, digest string) (bool, error) {
	registryID, err := d.upsertRegistry(ref.Registry)
	if err != nil {
		return false, fmt.Errorf("upsert registry: %w", err)
	}

	rows, err := d.db.Query(`
		SELECT DISTINCT ti.image, i.state::text
		FROM tags t
		JOIN tag_images ti ON ti.tag = t.id
		JOIN images i      ON i.id  = ti.image
		WHERE t.registry = $1 AND t.repository = $2 AND t.digest = $3`,
		registryID, ref.Repository, digest,
	)
	if err != nil {
		return false, fmt.Errorf("lookup digest: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var imageIDs []int64
	hasApproved := false
	for rows.Next() {
		var id int64
		var state string
		if err := rows.Scan(&id, &state); err != nil {
			return false, err
		}
		imageIDs = append(imageIDs, id)
		if state == string(StateApproved) {
			hasApproved = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	if len(imageIDs) == 0 {
		return false, nil
	}

	tagID, err := d.insertTag(registryID, ref.Repository, ref.Tag, digest)
	if err != nil {
		return false, fmt.Errorf("insert tag: %w", err)
	}
	for _, imgID := range imageIDs {
		if err := d.linkTagImage(tagID, imgID); err != nil {
			return false, fmt.Errorf("link tag→image: %w", err)
		}
	}
	return hasApproved, nil
}

// ── event logging ─────────────────────────────────────────────────────────────

// LogEvent records an event. imageID may be nil for non-image events.
//
// In addition to the events-table insert, the same payload is mirrored to
// slog.Default() so operators can tail audit activity through the global
// hermes logger (journald, Loki, etc.).
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

	attrs := []any{
		slog.String("source", string(source)),
		slog.String("event_type", eventType),
	}
	if imageID != nil {
		attrs = append(attrs, slog.Int64("image_id", *imageID))
	}
	if len(details) > 0 {
		detailAttrs := make([]any, 0, len(details))
		for k, v := range details {
			detailAttrs = append(detailAttrs, slog.Any(k, v))
		}
		attrs = append(attrs, slog.Group("details", detailAttrs...))
	}
	if err != nil {
		attrs = append(attrs, slog.String("persist_err", err.Error()))
		slog.Warn("event", attrs...)
	} else {
		slog.Info("event", attrs...)
	}
	return err
}
