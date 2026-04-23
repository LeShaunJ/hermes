// Package db manages the hermes PostgreSQL schema and all image/event persistence.
package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
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

// manifest_blobs.role values.
const (
	roleConfig = "config"
	roleLayer  = "layer"
)

// blobDescriptor is a lightweight view of a manifest config/layer descriptor.
type blobDescriptor struct {
	Digest    string
	Size      int64
	MediaType string
}

func isImageManifest(mt string) bool {
	return mt == mediaTypeOCIManifest || mt == mediaTypeDockerV2
}

func isImageIndex(mt string) bool {
	return mt == mediaTypeOCIIndex || mt == mediaTypeDockerList
}

// ── DB ────────────────────────────────────────────────────────────────────────

// DB wraps the connection pool and exposes all persistence operations.
// dsn is retained so Listen can open a dedicated LISTEN connection via
// pq.NewListener, which requires its own socket outside the query pool.
type DB struct {
	db  *sql.DB
	dsn string
}

// Open connects to PostgreSQL, runs schema migrations, and returns a DB.
func Open(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	sqlDB.SetMaxOpenConns(10)

	d := &DB{db: sqlDB, dsn: dsn}
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

		// repositories — normalized repository path scoped to a registry.
		`CREATE TABLE IF NOT EXISTS repositories (
			id         BIGSERIAL PRIMARY KEY,
			registry   BIGINT NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
			path       TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (registry, path)
		)`,

		// manifests — content-addressed store.  Carries the raw body for
		// verbatim forwarding, platform hints, scan report, approval state,
		// and optional cache registry.  All of these are determined by the
		// manifest content, so the same digest observed at multiple
		// (registry, repository) locations shares one row.
		`CREATE TABLE IF NOT EXISTS manifests (
			id             BIGSERIAL PRIMARY KEY,
			digest         TEXT NOT NULL UNIQUE,
			media_type     TEXT NOT NULL,
			body           JSONB NOT NULL,
			arch           TEXT,
			os             TEXT,
			scan_report    JSONB,
			scanned_at     TIMESTAMPTZ,
			cache_registry BIGINT REFERENCES registries(id) ON DELETE SET NULL,
			state          state NOT NULL DEFAULT 'queued',
			created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		// blobs — content-addressed catalog of every config/layer digest
		// referenced by any manifest.  Gatekeeps blob forwarding at the
		// gateway without requiring JSONB containment.
		`CREATE TABLE IF NOT EXISTS blobs (
			id         BIGSERIAL PRIMARY KEY,
			digest     TEXT NOT NULL UNIQUE,
			size       BIGINT,
			media_type TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		// manifest_blobs — M2M link from manifests to their config/layer blobs.
		// `role` distinguishes the config blob from the layer blobs; `ordinal`
		// preserves layer order (NULL for config).
		`CREATE TABLE IF NOT EXISTS manifest_blobs (
			manifest BIGINT NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
			blob     BIGINT NOT NULL REFERENCES blobs(id)     ON DELETE CASCADE,
			role     TEXT   NOT NULL CHECK (role IN ('config','layer')),
			ordinal  INT,
			PRIMARY KEY (manifest, blob, role)
		)`,

		// tags — one row per (repository, name).  `manifest` is the top-level
		// (image manifest or index) reference the tag last resolved to.  NULL
		// means the tag is a "stub" that has been seen at the gateway but not
		// yet populated.
		`CREATE TABLE IF NOT EXISTS tags (
			id         BIGSERIAL PRIMARY KEY,
			repository BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
			name       TEXT   NOT NULL,
			manifest   BIGINT REFERENCES manifests(id),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (repository, name)
		)`,

		// images — pure provenance row: "this manifest was observed at this
		// repository".  State/scan/cache live on the manifest; an images row
		// simply records the (repository → manifest) observation, and is what
		// events.image_id audits against.
		`CREATE TABLE IF NOT EXISTS images (
			id         BIGSERIAL PRIMARY KEY,
			repository BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
			manifest   BIGINT NOT NULL REFERENCES manifests(id),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (repository, manifest)
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
		`CREATE INDEX IF NOT EXISTS idx_repositories_registry ON repositories(registry)`,
		`CREATE INDEX IF NOT EXISTS idx_tags_repository       ON tags(repository)`,
		`CREATE INDEX IF NOT EXISTS idx_tags_manifest         ON tags(manifest)`,
		`CREATE INDEX IF NOT EXISTS idx_manifests_state       ON manifests(state)`,
		`CREATE INDEX IF NOT EXISTS idx_images_manifest       ON images(manifest)`,
		`CREATE INDEX IF NOT EXISTS idx_manifest_blobs_blob   ON manifest_blobs(blob)`,
		`CREATE INDEX IF NOT EXISTS idx_tag_images_image      ON tag_images(image)`,
		`CREATE INDEX IF NOT EXISTS idx_events_image_id       ON events(image_id)`,

		// tag_image_rows — canonical SELECT shape for every image query.
		// A LEFT JOIN through tag_images lets stub tags (no linked image)
		// appear as synthesised rows with image_id = 0 and state = 'queued',
		// so callers do not need to duplicate the COALESCE column list.
		// Both image_digest (platform-specific, from the linked manifest) and
		// tag_digest (top-level manifest or index digest, via tags.manifest)
		// are exposed so approval queries can select whichever is appropriate
		// for upstream forwarding.
		`CREATE OR REPLACE VIEW tag_image_rows AS
			SELECT
				COALESCE(i.id, 0)                      AS image_id,
				t.id                                   AS tag_id,
				r.url                                  AS registry_url,
				p.path                                 AS repository,
				t.name                                 AS tag_name,
				COALESCE(cr.url, '')                   AS cache_registry_url,
				COALESCE(im.digest, '')                AS image_digest,
				COALESCE(tm.digest, '')                AS tag_digest,
				COALESCE(im.arch, '')                  AS arch,
				COALESCE(im.os, '')                    AS os,
				COALESCE(im.body::text, 'null')        AS manifest,
				COALESCE(im.scan_report::text, 'null') AS scan_report,
				COALESCE(im.state::text, 'queued')     AS state,
				COALESCE(i.created_at, t.created_at)   AS created_at,
				COALESCE(i.updated_at, t.updated_at)   AS updated_at
			FROM tags t
			JOIN repositories p       ON p.id  = t.repository
			JOIN registries r         ON r.id  = p.registry
			LEFT JOIN manifests tm    ON tm.id = t.manifest
			LEFT JOIN tag_images ti   ON ti.tag = t.id
			LEFT JOIN images i        ON i.id  = ti.image
			LEFT JOIN manifests im    ON im.id = i.manifest
			LEFT JOIN registries cr   ON cr.id = im.cache_registry`,
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

// upsertRepository inserts a (registry, path) pair if absent and returns its id.
func (d *DB) upsertRepository(registryID int64, path string) (int64, error) {
	var id int64
	err := d.db.QueryRow(`
		INSERT INTO repositories (registry, path)
		VALUES ($1, $2)
		ON CONFLICT (registry, path) DO UPDATE SET updated_at = NOW()
		RETURNING id`,
		registryID, path,
	).Scan(&id)
	return id, err
}

// upsertManifest inserts a manifest row keyed on digest (or updates arch/os
// when better values arrive, without ever overwriting with blanks) and returns
// its id.  Existing rows preserve state, scan_report, and cache_registry —
// those are content-determined and therefore shared across every location
// that observes this digest.
func (d *DB) upsertManifest(digest, mediaType string, body []byte, arch, os string) (int64, error) {
	var id int64
	err := d.db.QueryRow(`
		INSERT INTO manifests (digest, media_type, body, arch, os)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''))
		ON CONFLICT (digest) DO UPDATE SET
			arch       = COALESCE(manifests.arch, NULLIF(EXCLUDED.arch, '')),
			os         = COALESCE(manifests.os,   NULLIF(EXCLUDED.os,   '')),
			updated_at = NOW()
		RETURNING id`,
		digest, mediaType, body, arch, os,
	).Scan(&id)
	return id, err
}

// upsertBlob inserts a blob digest if absent and returns its id.  Size and
// media type from manifest descriptors fill in best-effort; empty values are
// stored as NULL and never overwrite existing data.
func (d *DB) upsertBlob(digest string, size int64, mediaType string) (int64, error) {
	var id int64
	var sz interface{}
	if size > 0 {
		sz = size
	}
	err := d.db.QueryRow(`
		INSERT INTO blobs (digest, size, media_type)
		VALUES ($1, $2, NULLIF($3, ''))
		ON CONFLICT (digest) DO UPDATE SET
			size       = COALESCE(blobs.size,       EXCLUDED.size),
			media_type = COALESCE(blobs.media_type, EXCLUDED.media_type)
		RETURNING id`,
		digest, sz, mediaType,
	).Scan(&id)
	return id, err
}

// linkManifestBlob attaches a blob to a manifest with the given role.  Ordinal
// is used for layers (preserving order) and NULL for the config.  Idempotent.
func (d *DB) linkManifestBlob(manifestID, blobID int64, role string, ordinal int) error {
	var ord interface{}
	if role == roleLayer {
		ord = ordinal
	}
	_, err := d.db.Exec(`
		INSERT INTO manifest_blobs (manifest, blob, role, ordinal)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`,
		manifestID, blobID, role, ord,
	)
	return err
}

// getTagID returns the id of an existing tag, or 0 if absent.
func (d *DB) getTagID(repositoryID int64, tagName string) (int64, error) {
	var id int64
	err := d.db.QueryRow(`
		SELECT id FROM tags
		WHERE repository = $1 AND name = $2`,
		repositoryID, tagName,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// insertTag creates or updates a tag row and returns its id.  manifestID is
// the top-level (image manifest or index) manifests.id the tag resolves to;
// pass 0 for a stub tag with no resolved manifest yet.
func (d *DB) insertTag(repositoryID int64, tagName string, manifestID int64) (int64, error) {
	var id int64
	var mid interface{}
	if manifestID != 0 {
		mid = manifestID
	}
	err := d.db.QueryRow(`
		INSERT INTO tags (repository, name, manifest)
		VALUES ($1, $2, $3)
		ON CONFLICT (repository, name) DO UPDATE
			SET manifest = EXCLUDED.manifest, updated_at = NOW()
		RETURNING id`,
		repositoryID, tagName, mid,
	).Scan(&id)
	return id, err
}

// insertImagePolicy inserts or reuses the (repository → manifest) provenance
// row and returns its id.
func (d *DB) insertImagePolicy(repositoryID, manifestID int64) (int64, error) {
	var id int64
	err := d.db.QueryRow(`
		INSERT INTO images (repository, manifest)
		VALUES ($1, $2)
		ON CONFLICT (repository, manifest) DO UPDATE SET updated_at = NOW()
		RETURNING id`,
		repositoryID, manifestID,
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

// QueueStub ensures the registry, repository, and tag rows exist without making
// any outbound registry calls.  It is used by the API server to register a
// first-seen tag so operators can see it in 'hermes list'.  A stub tag has no
// linked image rows; manifest fetching and image insertion happen lazily the
// first time the operator runs scan/approve (or when the API later adopts the
// tag via AdoptTagByDigest).
func (d *DB) QueueStub(ref ImageRef) error {
	registryID, err := d.upsertRegistry(ref.Registry)
	if err != nil {
		return fmt.Errorf("upsert registry: %w", err)
	}
	repoID, err := d.upsertRepository(registryID, ref.Repository)
	if err != nil {
		return fmt.Errorf("upsert repository: %w", err)
	}
	tagID, err := d.getTagID(repoID, ref.Tag)
	if err != nil {
		return fmt.Errorf("get tag: %w", err)
	}
	if tagID == 0 {
		if _, err := d.insertTag(repoID, ref.Tag, 0); err != nil {
			return fmt.Errorf("insert stub tag: %w", err)
		}
	}
	return nil
}

// Queue ensures the registry, repository, tag, and per-platform image rows
// exist in the DB.  If the tag has no linked image rows yet (including when
// stub-registered by the API) it fetches the manifest via fetcher and either:
//   - adopts existing image rows when another tag in the same repository
//     already references the upstream-returned digest (alternate-tag case), or
//   - inserts new image rows per platform.
//
// Returns all image rows linked to the tag.
func (d *DB) Queue(ref ImageRef, fetcher Fetcher) ([]*Image, error) {
	// 1. Upsert registry + repository.
	registryID, err := d.upsertRegistry(ref.Registry)
	if err != nil {
		return nil, fmt.Errorf("upsert registry: %w", err)
	}
	repoID, err := d.upsertRepository(registryID, ref.Repository)
	if err != nil {
		return nil, fmt.Errorf("upsert repository: %w", err)
	}

	// 2. Check whether the tag already exists and is fully populated.
	tagID, err := d.getTagID(repoID, ref.Tag)
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
	existingIDs, err := d.findImageIDsByTagDigest(repoID, digest)
	if err != nil {
		return nil, fmt.Errorf("find images by digest: %w", err)
	}

	// 5. Upsert the top-level manifest row and link the tag to it.  For
	//    indexes we store the raw body but leave blob links to the per-platform
	//    manifests below.
	topID, err := d.upsertManifest(digest, mediaType, manifest, "", "")
	if err != nil {
		return nil, fmt.Errorf("upsert top manifest: %w", err)
	}
	tagID, err = d.insertTag(repoID, ref.Tag, topID)
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
		if err := d.queueSingleImage(tagID, repoID, ref.Registry, ref.Repository, topID, digest, mediaType, manifest, fetcher); err != nil {
			return nil, err
		}
	case isImageIndex(mediaType):
		if err := d.queueIndexImages(tagID, repoID, ref.Registry, ref.Repository, manifest, fetcher); err != nil {
			return nil, err
		}
	default:
		// Unknown media type — register a provenance row pointing at the
		// top-level manifest so the tag is tracked.
		imgID, err := d.insertImagePolicy(repoID, topID)
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
// linked to any tag in the given repository whose top-level manifest has the
// given digest.  This drives the alternate-tag adoption path.
func (d *DB) findImageIDsByTagDigest(repositoryID int64, digest string) ([]int64, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT ti.image
		FROM tags t
		JOIN manifests tm  ON tm.id = t.manifest
		JOIN tag_images ti ON ti.tag = t.id
		WHERE t.repository = $1 AND tm.digest = $2`,
		repositoryID, digest,
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

// storeManifestBlobs records the config and layer blob links for a manifest.
// Best-effort: a failure on any single blob aborts the manifest ingestion so
// the caller can surface the error, since the manifest row is useless for
// gatekeeping without its blob links.
func (d *DB) storeManifestBlobs(manifestID int64, body []byte) error {
	if cfg, err := extractConfigDigest(body); err == nil {
		blobID, err := d.upsertBlob(cfg, 0, "")
		if err != nil {
			return fmt.Errorf("upsert config blob: %w", err)
		}
		if err := d.linkManifestBlob(manifestID, blobID, roleConfig, 0); err != nil {
			return fmt.Errorf("link config blob: %w", err)
		}
	}
	layers, err := extractLayerDigests(body)
	if err != nil {
		return fmt.Errorf("extract layers: %w", err)
	}
	for i, l := range layers {
		blobID, err := d.upsertBlob(l.Digest, l.Size, l.MediaType)
		if err != nil {
			return fmt.Errorf("upsert layer blob %s: %w", l.Digest, err)
		}
		if err := d.linkManifestBlob(manifestID, blobID, roleLayer, i); err != nil {
			return fmt.Errorf("link layer blob %s: %w", l.Digest, err)
		}
	}
	return nil
}

// queueSingleImage records a single-platform manifest: upserts the manifest
// row (with arch/os from its config blob), extracts and stores its blob
// links, inserts the (repository → manifest) provenance row, and links it to
// the tag.
func (d *DB) queueSingleImage(tagID, repositoryID int64, registry, repository string, manifestID int64, digest, mediaType string, body []byte, fetcher Fetcher) error {
	arch, os := "", ""
	if configDigest, err := extractConfigDigest(body); err == nil {
		if a, o, err := fetcher.FetchConfig(registry, repository, configDigest); err == nil {
			arch, os = a, o
		}
	}
	// Re-upsert with arch/os now that we've resolved them.
	mid, err := d.upsertManifest(digest, mediaType, body, arch, os)
	if err != nil {
		return fmt.Errorf("upsert manifest: %w", err)
	}
	if mid != manifestID {
		manifestID = mid
	}
	if err := d.storeManifestBlobs(manifestID, body); err != nil {
		return err
	}
	imgID, err := d.insertImagePolicy(repositoryID, manifestID)
	if err != nil {
		return fmt.Errorf("insert image: %w", err)
	}
	return d.linkTagImage(tagID, imgID)
}

// queueIndexImages iterates the manifests in an image index, fetches each
// known platform's manifest + config, ingests them (manifest row + blob
// links), and links per-platform provenance rows to the tag.
func (d *DB) queueIndexImages(tagID, repositoryID int64, registry, repository string, indexManifest []byte, fetcher Fetcher) error {
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
		mDigest, mMediaType, mBody, err := fetcher.FetchManifest(registry, repository, entry.Digest)
		if err != nil {
			// Log and skip this platform rather than aborting the whole queue.
			continue
		}
		if mDigest == "" {
			mDigest = entry.Digest
		}
		if mMediaType == "" {
			mMediaType = entry.MediaType
		}

		// Fetch config for arch/os (best-effort).
		arch := entry.Platform.Architecture
		os := entry.Platform.OS
		if configDigest, err := extractConfigDigest(mBody); err == nil {
			if a, o, err := fetcher.FetchConfig(registry, repository, configDigest); err == nil {
				arch, os = a, o
			}
		}

		manifestID, err := d.upsertManifest(mDigest, mMediaType, mBody, arch, os)
		if err != nil {
			return fmt.Errorf("upsert manifest %s: %w", mDigest, err)
		}
		if err := d.storeManifestBlobs(manifestID, mBody); err != nil {
			return fmt.Errorf("store blobs for %s: %w", mDigest, err)
		}
		imgID, err := d.insertImagePolicy(repositoryID, manifestID)
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

// extractLayerDigests returns the layers[] descriptors from an image manifest,
// preserving order.  Returns an empty slice (not an error) if the manifest has
// no layers field.
func extractLayerDigests(manifest []byte) ([]blobDescriptor, error) {
	var m struct {
		Layers []struct {
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			MediaType string `json:"mediaType"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, err
	}
	out := make([]blobDescriptor, 0, len(m.Layers))
	for _, l := range m.Layers {
		if l.Digest == "" {
			continue
		}
		out = append(out, blobDescriptor{
			Digest:    l.Digest,
			Size:      l.Size,
			MediaType: l.MediaType,
		})
	}
	return out, nil
}

// ── image scan ────────────────────────────────────────────────────────────────

// SaveScan stores the trivy scan report on the manifest referenced by an
// image row and sets its state to scanned.  Because scan and state live on
// the content-addressed manifest, every other image row that shares this
// digest inherits the new report immediately.
func (d *DB) SaveScan(imageID int64, scanReport json.RawMessage) (*Image, error) {
	_, err := d.db.Exec(`
		UPDATE manifests SET
			scan_report = $1,
			scanned_at  = NOW(),
			state       = 'scanned',
			updated_at  = NOW()
		WHERE id = (SELECT manifest FROM images WHERE id = $2)`,
		[]byte(scanReport), imageID,
	)
	if err != nil {
		return nil, err
	}
	return d.GetByID(imageID)
}

// ── state transitions ─────────────────────────────────────────────────────────

// Approve sets the referenced manifest's state to approved and optionally
// records the cache registry URL.  Because approval is attached to the
// manifest, every image row referencing that digest shares the verdict.
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
		UPDATE manifests SET
			state          = 'approved',
			cache_registry = $1,
			updated_at     = NOW()
		WHERE id = (SELECT manifest FROM images WHERE id = $2)`,
		cacheRegID, imageID,
	)
	return err
}

// Rescind sets the referenced manifest's state to rescinded.
func (d *DB) Rescind(imageID int64) error {
	return d.setImageState(imageID, StateRescinded)
}

// Void sets the referenced manifest's state to voided — its digest no longer
// exists upstream and the image was not cached, so it cannot be served.
func (d *DB) Void(imageID int64) error {
	return d.setImageState(imageID, StateVoided)
}

// VoidByBlob flips every approved, uncached manifest in (registry, repository)
// whose config or layer set includes the given blob digest to the voided
// state.  Cached manifests are left alone — they remain servable from the
// cache registry regardless of upstream state.  Returns the IDs of the image
// rows that were voided so the caller can log them in an audit event.
func (d *DB) VoidByBlob(registry, repository, digest string) ([]int64, error) {
	rows, err := d.db.Query(`
		WITH affected AS (
			UPDATE manifests
			SET state = 'voided', updated_at = NOW()
			WHERE id IN (
				SELECT DISTINCT m.id
				FROM manifests m
				JOIN manifest_blobs mb ON mb.manifest = m.id
				JOIN blobs b           ON b.id = mb.blob
				JOIN images i          ON i.manifest = m.id
				JOIN repositories p    ON p.id = i.repository
				JOIN registries r      ON r.id = p.registry
				WHERE b.digest = $3
				  AND r.url = $1 AND p.path = $2
				  AND m.state = 'approved'
				  AND m.cache_registry IS NULL
			)
			RETURNING id
		)
		SELECT i.id
		FROM images i
		JOIN affected a     ON a.id = i.manifest
		JOIN repositories p ON p.id = i.repository
		JOIN registries r   ON r.id = p.registry
		WHERE r.url = $1 AND p.path = $2`,
		registry, repository, digest,
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

// Reject sets the referenced manifest's state to rejected.
func (d *DB) Reject(imageID int64) error {
	return d.setImageState(imageID, StateRejected)
}

// SetError sets the referenced manifest's state to errored.
func (d *DB) SetError(imageID int64) error {
	return d.setImageState(imageID, StateErrored)
}

func (d *DB) setImageState(imageID int64, state State) error {
	_, err := d.db.Exec(`
		UPDATE manifests SET state = $1, updated_at = NOW()
		WHERE id = (SELECT manifest FROM images WHERE id = $2)`,
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

// parseRefPattern splits "[registry/]repository[:tag]" into its three parts.
// The Docker heuristic identifies a registry prefix: the first "/"-separated
// segment must contain "." or ":", or be exactly "localhost".  All three
// parts may be empty.
func parseRefPattern(pattern string) (registry, repository, tag string) {
	// Tag separator: the last ":" that comes after any "/".  Protects
	// against registry-port colons (e.g. "example.com:5000/foo").
	slash := strings.LastIndex(pattern, "/")
	colon := strings.LastIndex(pattern, ":")
	if colon > slash {
		tag = pattern[colon+1:]
		pattern = pattern[:colon]
	}
	if i := strings.IndexByte(pattern, '/'); i > 0 {
		first := pattern[:i]
		if first == "localhost" || strings.ContainsAny(first, ".:") {
			return first, pattern[i+1:], tag
		}
	}
	return "", pattern, tag
}

// FindRegistriesForRef returns the distinct registry URLs where the given
// (repository, tag) pair is currently tracked.  Used by CLI commands to
// disambiguate when the operator provides an unqualified ref that could
// match images at multiple registries.  Results are sorted alphabetically.
func (d *DB) FindRegistriesForRef(repository, tag string) ([]string, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT registry_url
		FROM tag_image_rows
		WHERE repository = $1 AND tag_name = $2
		ORDER BY registry_url`,
		repository, tag,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, err
		}
		out = append(out, url)
	}
	return out, rows.Err()
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
			reg, repo, tag := parseRefPattern(r)
			var parts []string
			if reg != "" {
				parts = append(parts, fmt.Sprintf("registry_url = $%d", argIdx))
				args = append(args, reg)
				argIdx++
			}
			if repo != "" {
				parts = append(parts, fmt.Sprintf("repository = $%d", argIdx))
				args = append(args, repo)
				argIdx++
			}
			if tag != "" {
				parts = append(parts, fmt.Sprintf("tag_name = $%d", argIdx))
				args = append(args, tag)
				argIdx++
			}
			if len(parts) > 0 {
				refConds = append(refConds, "("+strings.Join(parts, " AND ")+")")
			}
		}
		if len(refConds) > 0 {
			conditions = append(conditions, "("+strings.Join(refConds, " OR ")+")")
		}
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
// manifest in (registry, repository).  A blob is authorized when it appears
// in manifest_blobs (config or layer role) for a manifest that is observed
// at (registry, repository) and is currently approved.  The check is a
// pure int-FK JOIN answered by the b-tree index on manifest_blobs(blob).
//
// The second return is the cache registry URL to forward the blob request to:
// when the owning manifest has cache_registry set hermes serves the blob from
// cache (protecting against upstream removal).  An empty string means
// "forward to origin".
func (d *DB) BlobAuthorized(registry, repository, digest string) (bool, string, error) {
	var cacheURL sql.NullString
	err := d.db.QueryRow(`
		SELECT COALESCE(cr.url, '')
		FROM blobs b
		JOIN manifest_blobs mb ON mb.blob = b.id
		JOIN manifests m       ON m.id = mb.manifest
		JOIN images i          ON i.manifest = m.id
		JOIN repositories p    ON p.id = i.repository
		JOIN registries r      ON r.id = p.registry
		LEFT JOIN registries cr ON cr.id = m.cache_registry
		WHERE b.digest = $3
		  AND r.url = $1 AND p.path = $2
		  AND m.state = 'approved'
		ORDER BY (m.cache_registry IS NULL), i.id
		LIMIT 1`,
		registry, repository, digest,
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
// (registry, repository) whose top-level manifest digest equals the given
// value, and links them to a (newly created if needed) tag with the supplied
// name.  It returns true when at least one of the adopted manifests is in
// the approved state, signalling to the caller that the new tag may be
// served immediately.
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
	repoID, err := d.upsertRepository(registryID, ref.Repository)
	if err != nil {
		return false, fmt.Errorf("upsert repository: %w", err)
	}

	// Resolve the top-level manifest id for the requested digest, if any.
	var topManifestID int64
	err = d.db.QueryRow(`SELECT id FROM manifests WHERE digest = $1`, digest).Scan(&topManifestID)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("lookup manifest: %w", err)
	}

	rows, err := d.db.Query(`
		SELECT DISTINCT ti.image, m.state::text
		FROM tags t
		JOIN manifests tm  ON tm.id = t.manifest
		JOIN tag_images ti ON ti.tag = t.id
		JOIN images i      ON i.id  = ti.image
		JOIN manifests m   ON m.id  = i.manifest
		WHERE t.repository = $1 AND tm.digest = $2`,
		repoID, digest,
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

	tagID, err := d.insertTag(repoID, ref.Tag, topManifestID)
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

// Event is one row from the events table, shaped for streaming through slog.
// Details is the raw JSON string as stored (empty for null).
type Event struct {
	ID        int64
	ImageID   *int64
	Source    EventSource
	EventType string
	Details   string
	CreatedAt time.Time
}

// LogEvent records an event and fires a Postgres NOTIFY on the hermes_events
// channel so a subscriber (hermes serve, via Listen) can stream the new row
// through slog into the container log.  Persistence errors are returned;
// notify failures are best-effort because the row is already committed.
func (d *DB) LogEvent(imageID *int64, source EventSource, eventType string, details map[string]interface{}) error {
	var detailsJSON interface{}
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err == nil {
			detailsJSON = string(b)
		}
	}
	var id int64
	if err := d.db.QueryRow(`
		INSERT INTO events (image_id, source, event_type, details)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		imageID, string(source), eventType, detailsJSON,
	).Scan(&id); err != nil {
		return err
	}
	_, _ = d.db.Exec(`SELECT pg_notify('hermes_events', $1)`, strconv.FormatInt(id, 10))
	return nil
}

// Listen subscribes to the hermes_events Postgres channel and delivers each
// newly persisted Event on the returned channel.  The goroutine terminates
// and closes the channel when ctx is cancelled.  Notification payloads are
// event IDs; the listener re-fetches each row through getEvent so the full
// payload is not constrained by Postgres's 8 KiB NOTIFY limit.
func (d *DB) Listen(ctx context.Context) (<-chan *Event, error) {
	listener := pq.NewListener(d.dsn, 10*time.Second, time.Minute, nil)
	if err := listener.Listen("hermes_events"); err != nil {
		_ = listener.Close()
		return nil, err
	}

	out := make(chan *Event, 64)
	go d.listenLoop(ctx, listener.Notify, out, func() { _ = listener.Close() })
	return out, nil
}

// listenLoop is the body of Listen's goroutine, split out so tests can feed
// a synthetic notify channel and verify delivery / cancellation without
// standing up a real pq.Listener.  Closes out on exit and runs cleanup (if
// non-nil) via defer.
func (d *DB) listenLoop(ctx context.Context, notify <-chan *pq.Notification, out chan<- *Event, cleanup func()) {
	defer close(out)
	if cleanup != nil {
		defer cleanup()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case n := <-notify:
			if !d.handleNotification(ctx, n, out) {
				return
			}
		}
	}
}

// handleNotification processes one pq notification and sends the resolved
// Event on out.  Returns false only when ctx is cancelled mid-send, so the
// Listen goroutine can stop promptly; bad payloads and row-fetch errors are
// logged and the listener keeps going.  Split out so it is testable without
// standing up a real Postgres listener.
func (d *DB) handleNotification(ctx context.Context, n *pq.Notification, out chan<- *Event) bool {
	if n == nil {
		return true // pq delivers nil on reconnect; nothing to emit.
	}
	id, err := strconv.ParseInt(n.Extra, 10, 64)
	if err != nil {
		slog.Warn("event notify: bad payload", "extra", n.Extra)
		return true
	}
	ev, err := d.getEvent(id)
	if err != nil {
		slog.Warn("event notify: fetch row", "id", id, "err", err)
		return true
	}
	select {
	case out <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// getEvent fetches a single event row by id.
func (d *DB) getEvent(id int64) (*Event, error) {
	var ev Event
	var imageID sql.NullInt64
	var source string
	var details sql.NullString
	if err := d.db.QueryRow(`
		SELECT id, image_id, source, event_type, details, created_at
		FROM events WHERE id = $1`, id,
	).Scan(&ev.ID, &imageID, &source, &ev.EventType, &details, &ev.CreatedAt); err != nil {
		return nil, err
	}
	if imageID.Valid {
		ev.ImageID = &imageID.Int64
	}
	ev.Source = EventSource(source)
	if details.Valid {
		ev.Details = details.String
	}
	return &ev, nil
}
