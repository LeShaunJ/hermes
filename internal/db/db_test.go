package db

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
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

// ── getTagID ──────────────────────────────────────────────────────────────────

func TestGetTagID_found(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(1), "myrepo", "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))

	id, err := d.getTagID(1, "myrepo", "v1.0")
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
		WithArgs(int64(1), "myrepo", "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"})) // empty → ErrNoRows

	id, err := d.getTagID(1, "myrepo", "v1.0")
	if err != nil {
		t.Fatalf("getTagID not found: %v", err)
	}
	if id != 0 {
		t.Errorf("id = %d, want 0", id)
	}
}

// ── insertTag ─────────────────────────────────────────────────────────────────

func TestInsertTag_withDigest(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(1), "myrepo", "v1.0", "sha256:abc").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(7)))

	id, err := d.insertTag(1, "myrepo", "v1.0", "sha256:abc")
	if err != nil {
		t.Fatalf("insertTag: %v", err)
	}
	if id != 7 {
		t.Errorf("id = %d, want 7", id)
	}
}

func TestInsertTag_emptyDigest(t *testing.T) {
	d, mock := newMockDB(t)
	// When digest is empty, nil is passed as the value.
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(1), "myrepo", "v1.0", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(3)))

	id, err := d.insertTag(1, "myrepo", "v1.0", "")
	if err != nil {
		t.Fatalf("insertTag empty digest: %v", err)
	}
	if id != 3 {
		t.Errorf("id = %d, want 3", id)
	}
}

// ── insertImage ───────────────────────────────────────────────────────────────

func TestInsertImage(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WithArgs(int64(1), "myrepo", "sha256:abc", "amd64", "linux", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))

	id, err := d.insertImage(1, "myrepo", "sha256:abc", "amd64", "linux", []byte(`{}`))
	if err != nil {
		t.Fatalf("insertImage: %v", err)
	}
	if id != 42 {
		t.Errorf("id = %d, want 42", id)
	}
}

func TestInsertImage_error(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WithArgs(int64(1), "myrepo", "sha256:abc", "amd64", "linux", sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("unique violation"))

	_, err := d.insertImage(1, "myrepo", "sha256:abc", "amd64", "linux", []byte(`{}`))
	if err == nil {
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
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET state`)).
		WithArgs("approved", int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := d.setImageState(5, StateApproved); err != nil {
		t.Fatalf("setImageState: %v", err)
	}
}

func TestRescind(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET state`)).
		WithArgs("rescinded", int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.Rescind(1); err != nil {
		t.Fatalf("Rescind: %v", err)
	}
}

func TestReject(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET state`)).
		WithArgs("rejected", int64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.Reject(2); err != nil {
		t.Fatalf("Reject: %v", err)
	}
}

func TestSetError(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET state`)).
		WithArgs("errored", int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.SetError(3); err != nil {
		t.Fatalf("SetError: %v", err)
	}
}

func TestVoid(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET state`)).
		WithArgs("voided", int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := d.Void(4); err != nil {
		t.Fatalf("Void: %v", err)
	}
}

func TestVoidByBlob_voidsUncachedOwners(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE images`)).
		WithArgs("registry.example.com", "myrepo",
			sqlmock.AnyArg(), sqlmock.AnyArg()).
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
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE images`)).
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
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET`)).
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
	// UPDATE images.
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET`)).
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
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO events`)).
		WithArgs(&id, "cli", "scan", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := d.LogEvent(&id, SourceCLI, "scan", map[string]interface{}{"key": "val"})
	if err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
}

func TestLogEvent_nilImageID(t *testing.T) {
	d, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO events`)).
		WithArgs(nil, "api", "validate_denied", nil).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := d.LogEvent(nil, SourceAPI, "validate_denied", nil)
	if err != nil {
		t.Fatalf("LogEvent nil id: %v", err)
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
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET`)).
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
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE images SET`)).
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

// ── QueueStub ─────────────────────────────────────────────────────────────────

func TestQueueStub_newTag(t *testing.T) {
	d, mock := newMockDB(t)

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// getTagID → not found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(1), "myrepo", "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	// insertTag (stub, empty digest) — no placeholder image inserted
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(1), "myrepo", "v1.0", nil).
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
	// getTagID → found; nothing else to do.
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(1), "myrepo", "v1.0").
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

func TestQueue_singleImage(t *testing.T) {
	d, mock := newMockDB(t)

	fetcher := &mockFetcher{
		manifestDigest:    "sha256:toplevel",
		manifestMediaType: mediaTypeOCIManifest,
		manifest:          []byte(`{"config":{"digest":"sha256:cfgdigest"}}`),
		configArch:        "amd64",
		configOS:          "linux",
	}

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// getTagID → not found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(1), "myrepo", "v1.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	// findImageIDsByTagDigest → no existing rows
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WithArgs(int64(1), "myrepo", "sha256:toplevel").
		WillReturnRows(sqlmock.NewRows([]string{"image"}))
	// insertTag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(1), "myrepo", "v1.0", "sha256:toplevel").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(5)))
	// insertImage → returns id
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WithArgs(int64(1), "myrepo", "sha256:toplevel", "amd64", "linux", sqlmock.AnyArg()).
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
}

func TestQueue_imageIndex(t *testing.T) {
	d, mock := newMockDB(t)

	indexManifest := `{"manifests":[
		{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:plat1","platform":{"os":"linux","architecture":"amd64"}},
		{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:plat2","platform":{"os":"linux","architecture":"arm64"}}
	]}`

	fetcher := &mockFetcher{
		manifestDigest:    "sha256:indexdigest",
		manifestMediaType: mediaTypeOCIIndex,
		manifest:          []byte(indexManifest),
		configArch:        "amd64",
		configOS:          "linux",
	}

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// getTagID → not found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	// findImageIDsByTagDigest → empty
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WillReturnRows(sqlmock.NewRows([]string{"image"}))
	// insertTag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(2)))
	// For each platform: insertImage + linkTagImage (2 platforms).
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO images`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(12)))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tag_images`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
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
	// getTagID → found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(1), "myrepo", "v1.0").
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

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// getTagID → not found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WithArgs(int64(1), "myrepo", "v2.0").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	// findImageIDsByTagDigest → existing image rows linked to a sibling tag
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WithArgs(int64(1), "myrepo", "sha256:shared").
		WillReturnRows(sqlmock.NewRows([]string{"image"}).
			AddRow(int64(101)).
			AddRow(int64(102)))
	// insertTag for the new alt tag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(1), "myrepo", "v2.0", "sha256:shared").
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

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// getTagID → not found
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

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

	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image`)).
		WillReturnRows(sqlmock.NewRows([]string{"image"}))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(3)))
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
		WithArgs("registry.example.com", "myrepo",
			sqlmock.AnyArg(), sqlmock.AnyArg()).
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
		WithArgs("registry.example.com", "myrepo",
			sqlmock.AnyArg(), sqlmock.AnyArg()).
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

func TestAdoptTagByDigest_approved(t *testing.T) {
	d, mock := newMockDB(t)

	// upsertRegistry
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WithArgs("registry.example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// digest lookup → finds an approved image
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image, i.state::text`)).
		WithArgs(int64(1), "myrepo", "sha256:shared").
		WillReturnRows(sqlmock.NewRows([]string{"image", "state"}).
			AddRow(int64(101), "approved"))
	// insertTag for the new alt tag
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO tags`)).
		WithArgs(int64(1), "myrepo", "v2.0", "sha256:shared").
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

	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	// Found but state is queued — should still link but return adopted=false.
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image, i.state::text`)).
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

	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO registries`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT ti.image, i.state::text`)).
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
