package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

// newMockDB creates a DB backed by a sqlmock connection.
func newMockDB(t *testing.T) (*DB, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &DB{db: sqlDB}, mock
}

// imageRowCols matches the column order returned by imageColumns.
var imageRowCols = []string{
	"id", "tag", "url", "repository", "name",
	"cache_url",
	"digest", "arch", "os",
	"manifest", "scan_report",
	"state", "created_at", "updated_at",
}

// testImageRow returns a sqlmock.Rows with all image columns populated.
func testImageRow(id int64, state string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(imageRowCols).AddRow(
		id, int64(1), "registry.example.com", "myrepo", "v1.0",
		"",
		"sha256:abc123", "amd64", "linux",
		`{"schemaVersion":2}`, "null",
		state, now, now,
	)
}

// ── upsertRegistry ────────────────────────────────────────────────────────────

func TestUpsertRegistry(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))

	id, err := d.upsertRegistry("registry.example.com")
	if err != nil {
		t.Fatalf("upsertRegistry: %v", err)
	}
	if id != 1 {
		t.Errorf("id = %d, want 1", id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet: %v", err)
	}
}

func TestUpsertRegistry_error(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnError(fmt.Errorf("connection refused"))

	_, err := d.upsertRegistry("registry.example.com")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestUpsertRegistry_walksMask verifies that the recursive CTE collapses a
// masked alias onto its canonical root id.  The mock returns whatever the
// CTE would produce — the real walk happens in Postgres — so here we just
// assert the call shape, but the test name documents the intent and would
// fail-loud if the query were ever regressed to the non-recursive form.
func TestUpsertRegistry_walksMask(t *testing.T) {
	d, mock := newMockDB(t)
	// The recursive CTE returns one id column; for an index.docker.io
	// alias the final id is docker.io's id (1), not the alias's own.
	mock.ExpectQuery(regexp.QuoteMeta(`WITH RECURSIVE upserted AS`)).
		WithArgs("index.docker.io").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))

	id, err := d.upsertRegistry("index.docker.io")
	if err != nil {
		t.Fatalf("upsertRegistry: %v", err)
	}
	if id != 1 {
		t.Errorf("id = %d, want 1 (the mask root)", id)
	}
}

// ── CanonicalRegistryURL ──────────────────────────────────────────────────────

func TestCanonicalRegistryURL_masked(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`WITH RECURSIVE chain AS`)).
		WithArgs("registry-1.docker.io").
		WillReturnRows(sqlmock.NewRows([]string{"url"}).AddRow("docker.io"))

	got, err := d.CanonicalRegistryURL("registry-1.docker.io")
	if err != nil {
		t.Fatalf("CanonicalRegistryURL: %v", err)
	}
	if got != "docker.io" {
		t.Errorf("got %q, want docker.io", got)
	}
}

func TestCanonicalRegistryURL_unknownFallsBackToInput(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`WITH RECURSIVE chain AS`)).
		WithArgs("quay.io").
		WillReturnRows(sqlmock.NewRows([]string{"url"})) // no rows

	got, err := d.CanonicalRegistryURL("quay.io")
	if err != nil {
		t.Fatalf("CanonicalRegistryURL unknown: %v", err)
	}
	if got != "quay.io" {
		t.Errorf("got %q, want quay.io (input unchanged)", got)
	}
}

// ── UpstreamRegistryURL ───────────────────────────────────────────────────────

func TestUpstreamRegistryURL_canonicalPicksChild(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT child.url`)).
		WithArgs("docker.io").
		WillReturnRows(sqlmock.NewRows([]string{"url"}).AddRow("registry-1.docker.io"))

	got, err := d.UpstreamRegistryURL("docker.io")
	if err != nil {
		t.Fatalf("UpstreamRegistryURL: %v", err)
	}
	if got != "registry-1.docker.io" {
		t.Errorf("got %q, want registry-1.docker.io", got)
	}
}

func TestUpstreamRegistryURL_concreteFallsBackToInput(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT child.url`)).
		WithArgs("quay.io").
		WillReturnRows(sqlmock.NewRows([]string{"url"})) // no rows

	got, err := d.UpstreamRegistryURL("quay.io")
	if err != nil {
		t.Fatalf("UpstreamRegistryURL concrete: %v", err)
	}
	if got != "quay.io" {
		t.Errorf("got %q, want quay.io (input unchanged)", got)
	}
}

// ── upsertRepository ──────────────────────────────────────────────────────────

func TestUpsertRepository(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO repositories`)).
		WithArgs(int64(1), "myrepo").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))

	id, err := d.upsertRepository(1, "myrepo")
	if err != nil {
		t.Fatalf("upsertRepository: %v", err)
	}
	if id != 11 {
		t.Errorf("id = %d, want 11", id)
	}
}

// ── upsertManifest ────────────────────────────────────────────────────────────

func TestUpsertManifest(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO manifests`)).
		WithArgs("sha256:abc", mediaTypeOCIManifest, sqlmock.AnyArg(), "amd64", "linux").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(33)))

	id, err := d.upsertManifest("sha256:abc", mediaTypeOCIManifest, []byte(`{}`), "amd64", "linux")
	if err != nil {
		t.Fatalf("upsertManifest: %v", err)
	}
	if id != 33 {
		t.Errorf("id = %d, want 33", id)
	}
}

// ── upsertBlob ────────────────────────────────────────────────────────────────

func TestUpsertBlob_withSize(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO blobs`)).
		WithArgs("sha256:layer", int64(4096), "application/vnd.oci.image.layer.v1.tar+gzip").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(77)))

	id, err := d.upsertBlob("sha256:layer", 4096, "application/vnd.oci.image.layer.v1.tar+gzip")
	if err != nil {
		t.Fatalf("upsertBlob: %v", err)
	}
	if id != 77 {
		t.Errorf("id = %d, want 77", id)
	}
}

func TestUpsertBlob_zeroSizeBecomesNil(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO blobs`)).
		WithArgs("sha256:cfg", nil, "").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(4)))

	if _, err := d.upsertBlob("sha256:cfg", 0, ""); err != nil {
		t.Fatalf("upsertBlob zero size: %v", err)
	}
}

// ── linkManifestBlob ──────────────────────────────────────────────────────────

func TestLinkManifestBlob_config(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO manifest_blobs`)).
		WithArgs(int64(1), int64(2), "config", nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := d.linkManifestBlob(1, 2, roleConfig, 0); err != nil {
		t.Fatalf("linkManifestBlob config: %v", err)
	}
}

func TestLinkManifestBlob_layer(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO manifest_blobs`)).
		WithArgs(int64(1), int64(3), "layer", 2).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := d.linkManifestBlob(1, 3, roleLayer, 2); err != nil {
		t.Fatalf("linkManifestBlob layer: %v", err)
	}
}

// ── getTagID ──────────────────────────────────────────────────────────────────

func TestGetTagID_found(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(11), "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))

	id, err := d.getTagID(11, "v1.0")
	if err != nil {
		t.Fatalf("getTagID: %v", err)
	}
	if id != 42 {
		t.Errorf("id = %d, want 42", id)
	}
}

func TestGetTagID_notFound(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(11), "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"})) // empty → ErrNoRows

	id, err := d.getTagID(11, "v1.0")
	if err != nil {
		t.Fatalf("getTagID not found: %v", err)
	}
	if id != 0 {
		t.Errorf("id = %d, want 0", id)
	}
}

// ── insertTag ─────────────────────────────────────────────────────────────────

func TestInsertTag_withManifest(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(11), "v1.0", int64(33)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(7)))

	id, err := d.insertTag(11, "v1.0", 33)
	if err != nil {
		t.Fatalf("insertTag: %v", err)
	}
	if id != 7 {
		t.Errorf("id = %d, want 7", id)
	}
}

func TestInsertTag_stub(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(11), "v1.0", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(3)))

	id, err := d.insertTag(11, "v1.0", 0)
	if err != nil {
		t.Fatalf("insertTag stub: %v", err)
	}
	if id != 3 {
		t.Errorf("id = %d, want 3", id)
	}
}

// ── insertImagePolicy ─────────────────────────────────────────────────────────

func TestInsertImagePolicy(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WithArgs(int64(11), int64(33)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))

	id, err := d.insertImagePolicy(11, 33)
	if err != nil {
		t.Fatalf("insertImagePolicy: %v", err)
	}
	if id != 42 {
		t.Errorf("id = %d, want 42", id)
	}
}

func TestInsertImagePolicy_error(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WithArgs(int64(11), int64(33)).
		WillReturnError(fmt.Errorf("unique violation"))

	if _, err := d.insertImagePolicy(11, 33); err == nil {
		t.Error("expected error, got nil")
	}
}

// ── linkTagImage ──────────────────────────────────────────────────────────────

func TestLinkTagImage(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WithArgs(int64(7), int64(42)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := d.linkTagImage(7, 42); err != nil {
		t.Fatalf("linkTagImage: %v", err)
	}
}

func TestLinkTagImage_error(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WithArgs(int64(7), int64(42)).
		WillReturnError(fmt.Errorf("constraint violation"))

	if err := d.linkTagImage(7, 42); err == nil {
		t.Error("expected error, got nil")
	}
}

// ── setImageState ─────────────────────────────────────────────────────────────

func TestSetImageState(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET state`)).
		WithArgs("approved", int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := d.setImageState(5, StateApproved); err != nil {
		t.Fatalf("setImageState: %v", err)
	}
}

func TestRescind(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET state`)).
		WithArgs("rescinded", int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.Rescind(1); err != nil {
		t.Fatalf("Rescind: %v", err)
	}
}

func TestReject(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET state`)).
		WithArgs("rejected", int64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.Reject(2); err != nil {
		t.Fatalf("Reject: %v", err)
	}
}

func TestSetError(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET state`)).
		WithArgs("errored", int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.SetError(3); err != nil {
		t.Fatalf("SetError: %v", err)
	}
}

func TestVoid(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET state`)).
		WithArgs("voided", int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.Void(4); err != nil {
		t.Fatalf("Void: %v", err)
	}
}

func TestVoidByBlob_voidsUncachedOwners(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`WITH affected AS`)).
		WithArgs("registry.example.com", "myrepo", "sha256:abc").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow(int64(7)).AddRow(int64(8)))

	ids, err := d.VoidByBlob("registry.example.com", "myrepo", "sha256:abc")
	if err != nil {
		t.Fatalf("VoidByBlob: %v", err)
	}
	if len(ids) != 2 || ids[0] != 7 || ids[1] != 8 {
		t.Errorf("ids = %v, want [7 8]", ids)
	}
}

func TestVoidByBlob_noMatches(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`WITH affected AS`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ids, err := d.VoidByBlob("registry.example.com", "myrepo", "sha256:abc")
	if err != nil {
		t.Fatalf("VoidByBlob: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want empty", ids)
	}
}

// ── Approve ───────────────────────────────────────────────────────────────────

func TestApprove_noCacheRegistry(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET`)).
		WithArgs(nil, int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := d.Approve(1, ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

func TestApprove_withCacheRegistry(t *testing.T) {
	d, mock := newMockDB(t)
	// upsertRegistry for cache registry.
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("cache.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(2)))
	// UPDATE manifests.
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET`)).
		WithArgs(int64(2), int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := d.Approve(1, "cache.example.com"); err != nil {
		t.Fatalf("Approve with cache: %v", err)
	}
}

// ── LogEvent ──────────────────────────────────────────────────────────────────

func TestLogEvent_withDetails(t *testing.T) {
	d, mock := newMockDB(t)
	id := int64(1)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO events`)).
		WithArgs(&id, "cli", "scan", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(7)))
	mock.ExpectExec(regexp.QuoteMeta(`pg_notify`)).
		WithArgs("7").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := d.LogEvent(&id, SourceCLI, "scan", map[string]interface{}{"key": "val"}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
}

func TestLogEvent_nilImageID(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO events`)).
		WithArgs(nil, "api", "validate_denied", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(8)))
	mock.ExpectExec(regexp.QuoteMeta(`pg_notify`)).
		WithArgs("8").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := d.LogEvent(nil, SourceAPI, "validate_denied", nil); err != nil {
		t.Fatalf("LogEvent nil id: %v", err)
	}
}

func TestLogEvent_insertFailureReturnsError(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO events`)).
		WillReturnError(fmt.Errorf("db offline"))

	if err := d.LogEvent(nil, SourceCLI, "scan", nil); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestLogEvent_notifyFailureNonFatal(t *testing.T) {
	d, mock := newMockDB(t)
	id := int64(1)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO events`)).
		WithArgs(&id, "cli", "scan", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(9)))
	mock.ExpectExec(regexp.QuoteMeta(`pg_notify`)).
		WillReturnError(fmt.Errorf("notify failed"))

	if err := d.LogEvent(&id, SourceCLI, "scan", nil); err != nil {
		t.Errorf("LogEvent should not surface notify failures: %v", err)
	}
}

// ── getEvent ──────────────────────────────────────────────────────────────────

func TestGetEvent_success(t *testing.T) {
	d, mock := newMockDB(t)
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, image_id, source, event_type, details, created_at`)).
		WithArgs(int64(5)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "image_id", "source", "event_type", "details", "created_at"}).
			AddRow(int64(5), int64(42), "cli", "scan", `{"digest":"sha256:abc"}`, now))

	ev, err := d.getEvent(5)
	if err != nil {
		t.Fatalf("getEvent: %v", err)
	}
	if ev.ID != 5 {
		t.Errorf("ID = %d, want 5", ev.ID)
	}
	if ev.ImageID == nil || *ev.ImageID != 42 {
		t.Errorf("ImageID = %v, want *42", ev.ImageID)
	}
	if ev.Source != SourceCLI {
		t.Errorf("Source = %q, want cli", ev.Source)
	}
	if ev.EventType != "scan" {
		t.Errorf("EventType = %q, want scan", ev.EventType)
	}
	if ev.Details != `{"digest":"sha256:abc"}` {
		t.Errorf("Details = %q, want the stored JSON string", ev.Details)
	}
}

func TestGetEvent_nullImageIDAndDetails(t *testing.T) {
	d, mock := newMockDB(t)
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, image_id, source, event_type, details, created_at`)).
		WithArgs(int64(6)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "image_id", "source", "event_type", "details", "created_at"}).
			AddRow(int64(6), nil, "api", "validate_approved", nil, now))

	ev, err := d.getEvent(6)
	if err != nil {
		t.Fatalf("getEvent: %v", err)
	}
	if ev.ImageID != nil {
		t.Errorf("ImageID = %v, want nil", ev.ImageID)
	}
	if ev.Details != "" {
		t.Errorf("Details = %q, want empty on NULL", ev.Details)
	}
}

func TestGetEvent_notFound(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, image_id, source, event_type, details, created_at`)).
		WithArgs(int64(99)).
		WillReturnError(sql.ErrNoRows)

	if _, err := d.getEvent(99); err == nil {
		t.Error("expected error for missing row, got nil")
	}
}

// ── handleNotification ────────────────────────────────────────────────────────

func TestHandleNotification_deliversEvent(t *testing.T) {
	d, mock := newMockDB(t)
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, image_id, source, event_type, details, created_at`)).
		WithArgs(int64(3)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "image_id", "source", "event_type", "details", "created_at"}).
			AddRow(int64(3), nil, "api", "validate_approved", nil, now))

	out := make(chan *Event, 1)
	ok := d.handleNotification(context.Background(),
		&pq.Notification{Channel: "hermes_events", Extra: "3"}, out)
	if !ok {
		t.Error("handleNotification returned false, want true")
	}
	select {
	case ev := <-out:
		if ev.ID != 3 || ev.EventType != "validate_approved" {
			t.Errorf("event = %+v, want id=3 validate_approved", ev)
		}
	default:
		t.Error("out channel empty; expected one event")
	}
}

func TestHandleNotification_nilNotification(t *testing.T) {
	d, _ := newMockDB(t)
	out := make(chan *Event, 1)
	if !d.handleNotification(context.Background(), nil, out) {
		t.Error("nil notify should not stop the listener")
	}
	if len(out) != 0 {
		t.Error("nil notify must not emit anything")
	}
}

func TestHandleNotification_badPayloadSkipped(t *testing.T) {
	d, _ := newMockDB(t)
	out := make(chan *Event, 1)
	if !d.handleNotification(context.Background(),
		&pq.Notification{Extra: "not-a-number"}, out) {
		t.Error("bad payload should not stop the listener")
	}
	if len(out) != 0 {
		t.Error("bad payload must not emit anything")
	}
}

func TestHandleNotification_fetchErrorSkipped(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, image_id, source, event_type, details, created_at`)).
		WithArgs(int64(4)).
		WillReturnError(fmt.Errorf("db offline"))

	out := make(chan *Event, 1)
	if !d.handleNotification(context.Background(),
		&pq.Notification{Extra: "4"}, out) {
		t.Error("fetch error should not stop the listener")
	}
	if len(out) != 0 {
		t.Error("fetch error must not emit anything")
	}
}

func TestHandleNotification_ctxCancelledMidSend(t *testing.T) {
	d, mock := newMockDB(t)
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, image_id, source, event_type, details, created_at`)).
		WithArgs(int64(5)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "image_id", "source", "event_type", "details", "created_at"}).
			AddRow(int64(5), nil, "cli", "scan", nil, now))

	// Unbuffered channel + cancelled ctx → send blocks, ctx.Done fires.
	out := make(chan *Event)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d.handleNotification(ctx, &pq.Notification{Extra: "5"}, out) {
		t.Error("cancelled ctx should signal listener to stop (returned true)")
	}
}

// ── listenLoop ────────────────────────────────────────────────────────────────

func TestListenLoop_deliversEventsUntilCancel(t *testing.T) {
	d, mock := newMockDB(t)
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, image_id, source, event_type, details, created_at`)).
		WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "image_id", "source", "event_type", "details", "created_at"}).
			AddRow(int64(1), nil, "cli", "scan", nil, now))

	notify := make(chan *pq.Notification, 1)
	out := make(chan *Event, 1)
	ctx, cancel := context.WithCancel(context.Background())

	cleanupCalled := make(chan struct{})
	go d.listenLoop(ctx, notify, out, func() { close(cleanupCalled) })

	notify <- &pq.Notification{Extra: "1"}

	select {
	case ev := <-out:
		if ev.ID != 1 || ev.EventType != "scan" {
			t.Errorf("event = %+v, want id=1 scan", ev)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no event delivered")
	}

	cancel()

	select {
	case _, ok := <-out:
		if ok {
			t.Error("out channel should be closed after cancel")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("listenLoop did not exit on cancel")
	}

	select {
	case <-cleanupCalled:
	case <-time.After(500 * time.Millisecond):
		t.Error("cleanup was not called")
	}
}

func TestListenLoop_nilCleanupIsAllowed(t *testing.T) {
	d, _ := newMockDB(t)
	notify := make(chan *pq.Notification)
	out := make(chan *Event)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // exit immediately

	done := make(chan struct{})
	go func() {
		d.listenLoop(ctx, notify, out, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("listenLoop with nil cleanup did not exit")
	}
}

// ── imagesByTagID ─────────────────────────────────────────────────────────────

func TestImagesByTagID_empty(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows(imageRowCols))

	imgs, err := d.imagesByTagID(1)
	if err != nil {
		t.Fatalf("imagesByTagID empty: %v", err)
	}
	if len(imgs) != 0 {
		t.Errorf("len = %d, want 0", len(imgs))
	}
}

func TestImagesByTagID_rows(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(5)).
		WillReturnRows(testImageRow(10, "queued"))

	imgs, err := d.imagesByTagID(5)
	if err != nil {
		t.Fatalf("imagesByTagID: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
	if imgs[0].ID != 10 {
		t.Errorf("id = %d, want 10", imgs[0].ID)
	}
	if imgs[0].State != StateQueued {
		t.Errorf("state = %q, want queued", imgs[0].State)
	}
}

// ── GetByID ───────────────────────────────────────────────────────────────────

func TestGetByID_found(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(10)).
		WillReturnRows(testImageRow(10, "scanned"))

	img, err := d.GetByID(10)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if img == nil {
		t.Fatal("GetByID returned nil")
	}
	if img.State != StateScanned {
		t.Errorf("state = %q, want scanned", img.State)
	}
}

func TestGetByID_notFound(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(99)).
		WillReturnRows(sqlmock.NewRows(imageRowCols))

	img, err := d.GetByID(99)
	if err != nil {
		t.Fatalf("GetByID not found: %v", err)
	}
	if img != nil {
		t.Errorf("expected nil, got %+v", img)
	}
}

// ── GetByRef ──────────────────────────────────────────────────────────────────

func TestGetByRef(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "v1.0").
		WillReturnRows(testImageRow(1, "queued"))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	imgs, err := d.GetByRef(ref)
	if err != nil {
		t.Fatalf("GetByRef: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
}

// ── GetApproved ───────────────────────────────────────────────────────────────

func TestGetApproved_notFound(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "v1.0").
		WillReturnRows(sqlmock.NewRows(imageRowCols))

	img, err := d.GetApproved("registry.example.com", "myrepo", "v1.0")
	if err != nil {
		t.Fatalf("GetApproved: %v", err)
	}
	if img != nil {
		t.Errorf("expected nil, got %+v", img)
	}
}

func TestGetApproved_found(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "v1.0").
		WillReturnRows(testImageRow(5, "approved"))

	img, err := d.GetApproved("registry.example.com", "myrepo", "v1.0")
	if err != nil {
		t.Fatalf("GetApproved found: %v", err)
	}
	if img == nil {
		t.Fatal("GetApproved returned nil")
	}
}

// ── GetApprovedByDigest ───────────────────────────────────────────────────────

func TestGetApprovedByDigest(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "sha256:abc").
		WillReturnRows(testImageRow(6, "approved"))

	img, err := d.GetApprovedByDigest("registry.example.com", "myrepo", "sha256:abc")
	if err != nil {
		t.Fatalf("GetApprovedByDigest: %v", err)
	}
	if img == nil {
		t.Fatal("expected image, got nil")
	}
}

func TestGetApprovedByDigest_indexMatch(t *testing.T) {
	// Single view query matches on tag_digest when image_digest doesn't.
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "sha256:idx").
		WillReturnRows(testImageRow(7, "approved"))

	img, err := d.GetApprovedByDigest("registry.example.com", "myrepo", "sha256:idx")
	if err != nil {
		t.Fatalf("GetApprovedByDigest: %v", err)
	}
	if img == nil {
		t.Fatal("expected image, got nil")
	}
}

// ── GetApprovedByTagAndDigest ─────────────────────────────────────────────────

func TestGetApprovedByTagAndDigest(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "v1.0", "sha256:abc").
		WillReturnRows(testImageRow(7, "approved"))

	img, err := d.GetApprovedByTagAndDigest("registry.example.com", "myrepo", "v1.0", "sha256:abc")
	if err != nil {
		t.Fatalf("GetApprovedByTagAndDigest: %v", err)
	}
	if img == nil {
		t.Fatal("expected image, got nil")
	}
}

func TestGetApprovedByTagAndDigest_indexMatch(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "v1.0", "sha256:idx").
		WillReturnRows(testImageRow(8, "approved"))

	img, err := d.GetApprovedByTagAndDigest("registry.example.com", "myrepo", "v1.0", "sha256:idx")
	if err != nil {
		t.Fatalf("GetApprovedByTagAndDigest: %v", err)
	}
	if img == nil {
		t.Fatal("expected image, got nil")
	}
}

// ── GetRejected ───────────────────────────────────────────────────────────────

func TestGetRejected_notFound(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("registry.example.com", "myrepo", "v1.0").
		WillReturnRows(sqlmock.NewRows(imageRowCols))

	img, err := d.GetRejected("registry.example.com", "myrepo", "v1.0")
	if err != nil {
		t.Fatalf("GetRejected: %v", err)
	}
	if img != nil {
		t.Errorf("expected nil, got %+v", img)
	}
}

// ── SaveScan ──────────────────────────────────────────────────────────────────

func TestSaveScan(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET`)).
		WithArgs(sqlmock.AnyArg(), int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// GetByID called internally.
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(1)).
		WillReturnRows(testImageRow(1, "scanned"))

	img, err := d.SaveScan(1, json.RawMessage(`{"SchemaVersion":2}`))
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	if img == nil {
		t.Fatal("SaveScan returned nil image")
	}
}

func TestSaveScan_error(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE manifests SET`)).
		WithArgs(sqlmock.AnyArg(), int64(1)).
		WillReturnError(fmt.Errorf("db error"))

	_, err := d.SaveScan(1, json.RawMessage(`{}`))
	if err == nil {
		t.Error("expected error from SaveScan, got nil")
	}
}

// ── List ──────────────────────────────────────────────────────────────────────

func TestList_noFilter(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WillReturnRows(testImageRow(1, "queued"))

	imgs, err := d.List(ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
}

func TestList_withStateFilter(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(testImageRow(2, "approved"))

	imgs, err := d.List(ListFilter{States: []State{StateApproved}})
	if err != nil {
		t.Fatalf("List with state: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
}

func TestList_withRefFilter_tag(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("myrepo", "v1.0").
		WillReturnRows(testImageRow(3, "scanned"))

	imgs, err := d.List(ListFilter{Refs: []string{"myrepo:v1.0"}})
	if err != nil {
		t.Fatalf("List with ref: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
}

func TestList_withRefFilter_noTag(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("myrepo").
		WillReturnRows(sqlmock.NewRows(imageRowCols))

	imgs, err := d.List(ListFilter{Refs: []string{"myrepo"}})
	if err != nil {
		t.Fatalf("List no-tag ref: %v", err)
	}
	if len(imgs) != 0 {
		t.Errorf("len = %d, want 0", len(imgs))
	}
}

func TestList_withPlatformFilter(t *testing.T) {
	d, mock := newMockDB(t)
	// os + arch both bound as query args in that order.
	mock.ExpectQuery(`SELECT`).
		WithArgs("linux", "arm64").
		WillReturnRows(testImageRow(4, "approved"))

	imgs, err := d.List(ListFilter{OS: "linux", Arch: "arm64"})
	if err != nil {
		t.Fatalf("List with platform: %v", err)
	}
	if len(imgs) != 1 {
		t.Errorf("len = %d, want 1", len(imgs))
	}
}

func TestList_withPlatformFilter_osOnly(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs("linux").
		WillReturnRows(sqlmock.NewRows(imageRowCols))

	_, err := d.List(ListFilter{OS: "linux"})
	if err != nil {
		t.Fatalf("List os-only: %v", err)
	}
}

func TestList_withRefFilter_registryPrefix(t *testing.T) {
	d, mock := newMockDB(t)
	// "example.com/myorg/myapp:v1" → registry, repo, tag all bound.
	mock.ExpectQuery(`SELECT`).
		WithArgs("example.com", "myorg/myapp", "v1").
		WillReturnRows(testImageRow(42, "approved"))

	imgs, err := d.List(ListFilter{Refs: []string{"example.com/myorg/myapp:v1"}})
	if err != nil {
		t.Fatalf("List registry-prefixed ref: %v", err)
	}
	if len(imgs) != 1 {
		t.Errorf("len = %d, want 1", len(imgs))
	}
}

// ── parseRefPattern ───────────────────────────────────────────────────────────

func TestParseRefPattern(t *testing.T) {
	cases := []struct {
		in             string
		reg, repo, tag string
	}{
		// No registry.
		{"myapp", "", "myapp", ""},
		{"myapp:v1", "", "myapp", "v1"},
		{"myorg/myapp:v1", "", "myorg/myapp", "v1"},
		// Registry with "." → detected.
		{"example.com/myapp:v1", "example.com", "myapp", "v1"},
		{"example.com/myorg/myapp:v1", "example.com", "myorg/myapp", "v1"},
		{"example.com/myapp", "example.com", "myapp", ""},
		// Registry with port (colon).
		{"example.com:5000/myapp:v1", "example.com:5000", "myapp", "v1"},
		// localhost special case.
		{"localhost/myapp:v1", "localhost", "myapp", "v1"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			reg, repo, tag := parseRefPattern(tc.in)
			if reg != tc.reg || repo != tc.repo || tag != tc.tag {
				t.Errorf("parseRefPattern(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tc.in, reg, repo, tag, tc.reg, tc.repo, tc.tag)
			}
		})
	}
}

// ── FindRegistriesForRef ──────────────────────────────────────────────────────

func TestFindRegistriesForRef(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT registry_url`)).
		WithArgs("myrepo", "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"registry_url"}).
			AddRow("docker.io").
			AddRow("example.com"))

	got, err := d.FindRegistriesForRef("myrepo", "v1.0")
	if err != nil {
		t.Fatalf("FindRegistriesForRef: %v", err)
	}
	if len(got) != 2 || got[0] != "docker.io" || got[1] != "example.com" {
		t.Errorf("got %v, want [docker.io example.com]", got)
	}
}

func TestFindRegistriesForRef_empty(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT registry_url`)).
		WithArgs("unknown", "v1").
		WillReturnRows(sqlmock.NewRows([]string{"registry_url"}))

	got, err := d.FindRegistriesForRef("unknown", "v1")
	if err != nil {
		t.Fatalf("FindRegistriesForRef empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// ── QueueStub ─────────────────────────────────────────────────────────────────

func TestQueueStub_newTag(t *testing.T) {
	d, mock := newMockDB(t)

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// upsertRepository
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO repositories`)).
		WithArgs(int64(1), "myrepo").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	// getTagID → not found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(11), "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	// insertTag (stub, no manifest)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(11), "v1.0", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(10)))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	if err := d.QueueStub(ref); err != nil {
		t.Fatalf("QueueStub: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet: %v", err)
	}
}

func TestQueueStub_existingTag(t *testing.T) {
	d, mock := newMockDB(t)

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// upsertRepository
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO repositories`)).
		WithArgs(int64(1), "myrepo").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	// getTagID → found; nothing else to do.
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(11), "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(10)))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	if err := d.QueueStub(ref); err != nil {
		t.Fatalf("QueueStub existing tag: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet: %v", err)
	}
}

// ── Queue ─────────────────────────────────────────────────────────────────────

// mockFetcher implements the Fetcher interface for Queue tests.
type mockFetcher struct {
	manifestDigest    string
	manifestMediaType string
	manifest          []byte
	manifestErr       error
	configArch        string
	configOS          string
	configErr         error
}

func (m *mockFetcher) FetchManifest(_, _, _ string) (string, string, []byte, error) {
	return m.manifestDigest, m.manifestMediaType, m.manifest, m.manifestErr
}
func (m *mockFetcher) FetchConfig(_, _, _ string) (string, string, error) {
	return m.configArch, m.configOS, m.configErr
}

// expectCommonQueuePrefix expects the registry+repository upserts and the
// getTagID lookup (returning no row).
func expectCommonQueuePrefix(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO repositories`)).
		WithArgs(int64(1), "myrepo").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
}

func TestQueue_singleImage(t *testing.T) {
	d, mock := newMockDB(t)

	fetcher := &mockFetcher{
		manifestDigest:    "sha256:toplevel",
		manifestMediaType: mediaTypeOCIManifest,
		manifest:          []byte(`{"config":{"digest":"sha256:cfgdigest"},"layers":[{"digest":"sha256:layer1","size":1024,"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"}]}`),
		configArch:        "amd64",
		configOS:          "linux",
	}

	expectCommonQueuePrefix(mock)
	// findImageIDsByTagDigest → empty
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WithArgs(int64(11), "sha256:toplevel").
		WillReturnRows(sqlmock.NewRows([]string{"image"}))
	// upsertManifest (initial, without arch/os)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO manifests`)).
		WithArgs("sha256:toplevel", mediaTypeOCIManifest, sqlmock.AnyArg(), "", "").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(30)))
	// insertTag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(11), "v1.0", int64(30)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(5)))
	// queueSingleImage: re-upsert manifest with arch/os from config
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO manifests`)).
		WithArgs("sha256:toplevel", mediaTypeOCIManifest, sqlmock.AnyArg(), "amd64", "linux").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(30)))
	// storeManifestBlobs: upsert config blob + link
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO blobs`)).
		WithArgs("sha256:cfgdigest", nil, "").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(40)))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO manifest_blobs`)).
		WithArgs(int64(30), int64(40), "config", nil).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// storeManifestBlobs: upsert layer blob + link
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO blobs`)).
		WithArgs("sha256:layer1", int64(1024), "application/vnd.oci.image.layer.v1.tar+gzip").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(41)))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO manifest_blobs`)).
		WithArgs(int64(30), int64(41), "layer", 0).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// insertImagePolicy → provenance row
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WithArgs(int64(11), int64(30)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(99)))
	// linkTagImage
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WithArgs(int64(5), int64(99)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// imagesByTagID
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(5)).
		WillReturnRows(testImageRow(99, "queued"))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	imgs, err := d.Queue(ref, fetcher)
	if err != nil {
		t.Fatalf("Queue single: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet: %v", err)
	}
}

func TestQueue_imageIndex(t *testing.T) {
	d, mock := newMockDB(t)

	// Index references two per-platform manifests; their per-platform
	// manifests are fetched by digest via the same mockFetcher.
	indexManifest := `{"manifests":[
		{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:plat1","platform":{"os":"linux","architecture":"amd64"}},
		{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:plat2","platform":{"os":"linux","architecture":"arm64"}}
	]}`

	// A single mockFetcher returns the same body for every FetchManifest call
	// — good enough since queueIndexImages uses the returned digest anyway.
	// Body has no layers to keep the expectation list compact.
	fetcher := &mockFetcher{
		manifestDigest:    "sha256:indexdigest",
		manifestMediaType: mediaTypeOCIIndex,
		manifest:          []byte(indexManifest),
	}

	expectCommonQueuePrefix(mock)
	// findImageIDsByTagDigest → empty
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WillReturnRows(sqlmock.NewRows([]string{"image"}))
	// upsertManifest for the top-level index
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO manifests`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1000)))
	// insertTag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(2)))
	// queueIndexImages: loops over the two entries.  Each entry refetches
	// via the mockFetcher (same body/digest), so the same ingestion pattern
	// runs twice.  Since the mock fetcher always returns "sha256:indexdigest",
	// both platforms resolve to the same manifest digest; second upsert is a
	// no-op on the manifest but still appears in the expectation list.
	for i := 0; i < 2; i++ {
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO manifests`)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1001 + i)))
		// no config digest in the body → no config blob link, no layers
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11 + i)))
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}
	// imagesByTagID
	mock.ExpectQuery(`SELECT`).
		WillReturnRows(testImageRow(11, "queued"))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	imgs, err := d.Queue(ref, fetcher)
	if err != nil {
		t.Fatalf("Queue index: %v", err)
	}
	if len(imgs) == 0 {
		t.Error("Queue index returned empty")
	}
}

func TestQueue_existingRealImages(t *testing.T) {
	d, mock := newMockDB(t)

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// upsertRepository
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO repositories`)).
		WithArgs(int64(1), "myrepo").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	// getTagID → found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(11), "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(5)))
	// imagesByTagID → already populated
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(5)).
		WillReturnRows(testImageRow(1, "queued"))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	imgs, err := d.Queue(ref, &mockFetcher{})
	if err != nil {
		t.Fatalf("Queue existing: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
}

func TestQueue_altTagAdoption(t *testing.T) {
	d, mock := newMockDB(t)

	fetcher := &mockFetcher{
		manifestDigest:    "sha256:shared",
		manifestMediaType: mediaTypeOCIIndex,
		manifest:          []byte(`{"manifests":[]}`),
	}

	expectCommonQueuePrefix(mock)
	// findImageIDsByTagDigest → existing image rows linked to a sibling tag
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WithArgs(int64(11), "sha256:shared").
		WillReturnRows(sqlmock.NewRows([]string{"image"}).
			AddRow(int64(101)).
			AddRow(int64(102)))
	// upsertManifest for the top-level digest
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO manifests`)).
		WithArgs("sha256:shared", mediaTypeOCIIndex, sqlmock.AnyArg(), "", "").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(55)))
	// insertTag for the new alt tag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(11), "v2.0", int64(55)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(7)))
	// linkTagImage twice (one per adopted image)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WithArgs(int64(7), int64(101)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WithArgs(int64(7), int64(102)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// imagesByTagID
	mock.ExpectQuery(`SELECT`).
		WithArgs(int64(7)).
		WillReturnRows(testImageRow(101, "approved"))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v2.0"}
	imgs, err := d.Queue(ref, fetcher)
	if err != nil {
		t.Fatalf("Queue altTag: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("len = %d, want 1", len(imgs))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet: %v", err)
	}
}

func TestQueue_fetchManifestError(t *testing.T) {
	d, mock := newMockDB(t)
	fetcher := &mockFetcher{manifestErr: fmt.Errorf("network error")}

	expectCommonQueuePrefix(mock)

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	_, err := d.Queue(ref, fetcher)
	if err == nil {
		t.Error("expected error from FetchManifest, got nil")
	}
}

func TestQueue_unknownMediaType(t *testing.T) {
	d, mock := newMockDB(t)
	fetcher := &mockFetcher{
		manifestDigest:    "sha256:abc",
		manifestMediaType: "application/unknown",
		manifest:          []byte(`{}`),
	}

	expectCommonQueuePrefix(mock)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WillReturnRows(sqlmock.NewRows([]string{"image"}))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO manifests`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(80)))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(3)))
	// Unknown media-type path: just insertImagePolicy + linkTagImage.
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(50)))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT`).
		WillReturnRows(testImageRow(50, "queued"))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	_, err := d.Queue(ref, fetcher)
	if err != nil {
		t.Fatalf("Queue unknown media type: %v", err)
	}
}

// ── GroupOf ───────────────────────────────────────────────────────────────────

func TestGroupOf(t *testing.T) {
	tests := []struct {
		state State
		want  Group
	}{
		{StateQueued, GroupPending},
		{StateScanned, GroupPending},
		{StateRescinded, GroupPending},
		{StateVoided, GroupPending},
		{StateApproved, GroupVerified},
		{StateRejected, GroupVerified},
		{StateErrored, ""},
	}
	for _, tc := range tests {
		got := GroupOf(tc.state)
		if got != tc.want {
			t.Errorf("GroupOf(%q) = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// ── ParseStateOrGroup ─────────────────────────────────────────────────────────

func TestParseStateOrGroup(t *testing.T) {
	tests := []struct {
		input   string
		want    []State
		wantErr bool
	}{
		{"queued", []State{StateQueued}, false},
		{"scanned", []State{StateScanned}, false},
		{"approved", []State{StateApproved}, false},
		{"rescinded", []State{StateRescinded}, false},
		{"voided", []State{StateVoided}, false},
		{"rejected", []State{StateRejected}, false},
		{"errored", []State{StateErrored}, false},
		{"pending", []State{StateQueued, StateScanned, StateRescinded, StateVoided}, false},
		{"verified", []State{StateApproved, StateRejected}, false},
		{"unknown", nil, true},
		{"", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseStateOrGroup(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseStateOrGroup(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStateOrGroup(%q) unexpected error: %v", tc.input, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParseStateOrGroup(%q) len = %d, want %d", tc.input, len(got), len(tc.want))
			}
			for i, s := range got {
				if s != tc.want[i] {
					t.Errorf("ParseStateOrGroup(%q)[%d] = %q, want %q", tc.input, i, s, tc.want[i])
				}
			}
		})
	}
}

// ── isImageManifest / isImageIndex ────────────────────────────────────────────

func TestIsImageManifest(t *testing.T) {
	trueCases := []string{
		mediaTypeOCIManifest,
		mediaTypeDockerV2,
	}
	falseCases := []string{
		mediaTypeOCIIndex,
		mediaTypeDockerList,
		"application/json",
		"",
	}
	for _, mt := range trueCases {
		if !isImageManifest(mt) {
			t.Errorf("isImageManifest(%q) = false, want true", mt)
		}
	}
	for _, mt := range falseCases {
		if isImageManifest(mt) {
			t.Errorf("isImageManifest(%q) = true, want false", mt)
		}
	}
}

func TestIsImageIndex(t *testing.T) {
	trueCases := []string{
		mediaTypeOCIIndex,
		mediaTypeDockerList,
	}
	falseCases := []string{
		mediaTypeOCIManifest,
		mediaTypeDockerV2,
		"application/json",
		"",
	}
	for _, mt := range trueCases {
		if !isImageIndex(mt) {
			t.Errorf("isImageIndex(%q) = false, want true", mt)
		}
	}
	for _, mt := range falseCases {
		if isImageIndex(mt) {
			t.Errorf("isImageIndex(%q) = true, want false", mt)
		}
	}
}

// ── extractConfigDigest ───────────────────────────────────────────────────────

func TestExtractConfigDigest(t *testing.T) {
	manifest := struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}{
		Config: struct {
			Digest string `json:"digest"`
		}{Digest: "sha256:abc123"},
	}
	b, _ := json.Marshal(manifest)

	got, err := extractConfigDigest(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sha256:abc123" {
		t.Errorf("digest = %q, want sha256:abc123", got)
	}
}

func TestExtractConfigDigest_missing(t *testing.T) {
	b := []byte(`{"config":{}}`)
	_, err := extractConfigDigest(b)
	if err == nil {
		t.Error("expected error for missing digest, got nil")
	}
}

func TestExtractConfigDigest_invalidJSON(t *testing.T) {
	_, err := extractConfigDigest([]byte("{invalid}"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ── BlobAuthorized ────────────────────────────────────────────────────────────

func TestBlobAuthorized_originForward(t *testing.T) {
	d, mock := newMockDB(t)
	// Authorized without a cache_registry → empty string, forward to origin.
	mock.ExpectQuery(`SELECT COALESCE\(cr\.url, ''\)`).
		WithArgs("registry.example.com", "myrepo", "sha256:abc").
		WillReturnRows(sqlmock.NewRows([]string{"cache_url"}).AddRow(""))

	ok, cache, err := d.BlobAuthorized("registry.example.com", "myrepo", "sha256:abc")
	if err != nil {
		t.Fatalf("BlobAuthorized: %v", err)
	}
	if !ok {
		t.Error("expected authorized=true")
	}
	if cache != "" {
		t.Errorf("cache = %q, want empty", cache)
	}
}

func TestBlobAuthorized_cacheForward(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT COALESCE\(cr\.url, ''\)`).
		WithArgs("registry.example.com", "myrepo", "sha256:abc").
		WillReturnRows(sqlmock.NewRows([]string{"cache_url"}).
			AddRow("cache.internal.example.com"))

	ok, cache, err := d.BlobAuthorized("registry.example.com", "myrepo", "sha256:abc")
	if err != nil {
		t.Fatalf("BlobAuthorized: %v", err)
	}
	if !ok {
		t.Error("expected authorized=true")
	}
	if cache != "cache.internal.example.com" {
		t.Errorf("cache = %q, want cache.internal.example.com", cache)
	}
}

func TestBlobAuthorized_noOwner(t *testing.T) {
	d, mock := newMockDB(t)
	// No rows → unauthorized.
	mock.ExpectQuery(`SELECT COALESCE\(cr\.url, ''\)`).
		WillReturnRows(sqlmock.NewRows([]string{"cache_url"}))

	ok, cache, err := d.BlobAuthorized("registry.example.com", "myrepo", "sha256:abc")
	if err != nil {
		t.Fatalf("BlobAuthorized: %v", err)
	}
	if ok {
		t.Error("expected authorized=false")
	}
	if cache != "" {
		t.Errorf("cache = %q, want empty on unauthorized", cache)
	}
}

func TestBlobAuthorized_dbError(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(`SELECT COALESCE\(cr\.url, ''\)`).
		WillReturnError(fmt.Errorf("connection refused"))

	_, _, err := d.BlobAuthorized("registry.example.com", "myrepo", "sha256:abc")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ── AdoptTagByDigest ──────────────────────────────────────────────────────────

// expectAdoptPrefix expects upsertRegistry, upsertRepository, and the
// manifest digest lookup returning the given manifestID (0 = not found).
func expectAdoptPrefix(mock sqlmock.Sqlmock, digest string, manifestID int64) {
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO repositories`)).
		WithArgs(int64(1), "myrepo").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	if manifestID == 0 {
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM manifests`)).
			WithArgs(digest).
			WillReturnRows(sqlmock.NewRows([]string{"id"}))
	} else {
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM manifests`)).
			WithArgs(digest).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(manifestID))
	}
}

func TestAdoptTagByDigest_approved(t *testing.T) {
	d, mock := newMockDB(t)

	expectAdoptPrefix(mock, "sha256:shared", 55)
	// Per-image state lookup → finds an approved image
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image, m.state::text`)).
		WithArgs(int64(11), "sha256:shared").
		WillReturnRows(sqlmock.NewRows([]string{"image", "state"}).
			AddRow(int64(101), "approved"))
	// insertTag for the new alt tag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(11), "v2.0", int64(55)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(7)))
	// linkTagImage
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WithArgs(int64(7), int64(101)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v2.0"}
	adopted, err := d.AdoptTagByDigest(ref, "sha256:shared")
	if err != nil {
		t.Fatalf("AdoptTagByDigest: %v", err)
	}
	if !adopted {
		t.Error("expected adopted=true")
	}
}

func TestAdoptTagByDigest_unapproved(t *testing.T) {
	d, mock := newMockDB(t)

	expectAdoptPrefix(mock, "sha256:other", 56)
	// Found but state is queued — should still link but return adopted=false.
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image, m.state::text`)).
		WillReturnRows(sqlmock.NewRows([]string{"image", "state"}).
			AddRow(int64(202), "queued"))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(8)))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v3.0"}
	adopted, err := d.AdoptTagByDigest(ref, "sha256:other")
	if err != nil {
		t.Fatalf("AdoptTagByDigest: %v", err)
	}
	if adopted {
		t.Error("expected adopted=false for non-approved image")
	}
}

func TestAdoptTagByDigest_noMatch(t *testing.T) {
	d, mock := newMockDB(t)

	expectAdoptPrefix(mock, "sha256:none", 0)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image, m.state::text`)).
		WillReturnRows(sqlmock.NewRows([]string{"image", "state"}))

	ref := ImageRef{Registry: "registry.example.com", Repository: "myrepo", Tag: "v1.0"}
	adopted, err := d.AdoptTagByDigest(ref, "sha256:none")
	if err != nil {
		t.Fatalf("AdoptTagByDigest: %v", err)
	}
	if adopted {
		t.Error("expected adopted=false")
	}
}

// ── extractLayerDigests ───────────────────────────────────────────────────────

func TestExtractLayerDigests(t *testing.T) {
	manifest := []byte(`{
		"layers":[
			{"digest":"sha256:a","size":100,"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"},
			{"digest":"sha256:b","size":200}
		]
	}`)
	got, err := extractLayerDigests(manifest)
	if err != nil {
		t.Fatalf("extractLayerDigests: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Digest != "sha256:a" || got[0].Size != 100 {
		t.Errorf("got[0] = %+v, want digest sha256:a size 100", got[0])
	}
	if got[1].Digest != "sha256:b" || got[1].MediaType != "" {
		t.Errorf("got[1] = %+v, want digest sha256:b empty mediaType", got[1])
	}
}

func TestExtractLayerDigests_noLayers(t *testing.T) {
	got, err := extractLayerDigests([]byte(`{}`))
	if err != nil {
		t.Fatalf("extractLayerDigests empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d layers, want 0", len(got))
	}
}

func TestExtractLayerDigests_invalidJSON(t *testing.T) {
	if _, err := extractLayerDigests([]byte("{invalid")); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
