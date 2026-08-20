package services

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Audit-log retention is an archive-then-delete pipeline, and every hop of it
// runs SQL that only a real Postgres can accept or reject:
//
//   - MarkLogsAsArchived binds $1 inside jsonb_build_object, where every
//     argument position is "any" — a bare parameter cannot be typed and the
//     statement is rejected at Parse time with 42P18.
//   - all three id-list statements bind a []uuid.UUID, which lib/pq cannot
//     convert at all ("unsupported type []uuid.UUID, a slice of array"), so
//     they never reach the server.
//
// Both defects are invisible to a compile and to any mock: the Go code is
// well-typed. They meant nothing was ever stamped archived, so the
// archive-before-delete gate could never open and retention silently deleted
// nothing — while ArchiveLogs kept re-uploading the same LIMIT-1000 rows under
// a fresh S3 key every cycle. These tests exercise the statements against the
// real database, which is the only place the bugs exist.
//
// The owner connection stands in for both handles: production passes a
// BYPASSRLS pool as bypassDB because the sweep is cross-tenant, and what is
// under test here is statement validity and gate ordering, not RLS.

// retentionFixture seeds n activity_logs rows old enough to be swept, all
// carrying a unique event_type so the policy's own filter scopes every query in
// this test to just these rows (the retention statements are LIMIT-1000
// table-wide and would otherwise pick up whatever else lives in the database).
type retentionFixture struct {
	db     *sql.DB
	policy *RetentionPolicy
	ids    []uuid.UUID
}

func newRetentionFixture(t *testing.T, n int) *retentionFixture {
	t.Helper()
	db := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, db)

	// occurred_at is the partition key; make sure the month it lands in has a
	// partition rather than depending on which ones happen to be attached.
	occurredAt := time.Now().AddDate(0, 0, -60)
	if _, err := db.Exec(`SELECT audit.create_activity_logs_partition($1, $2)`,
		occurredAt.Year(), int(occurredAt.Month())); err != nil {
		t.Fatalf("ensure partition for %s: %v", occurredAt.Format("2006-01"), err)
	}

	eventType := "retention.itest." + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM audit.activity_logs WHERE event_type = $1`, eventType)
	})

	ids := make([]uuid.UUID, 0, n)
	for i := 0; i < n; i++ {
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO audit.activity_logs
			    (id, tenant_id, user_type, event_type, event_category, action, occurred_at)
			VALUES ($1, $2, 'tenant', $3, 'system', 'retention.fixture', $4)`,
			id, tenantID, eventType, occurredAt); err != nil {
			t.Fatalf("seed activity log %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	return &retentionFixture{
		db:  db,
		ids: ids,
		policy: &RetentionPolicy{
			ID:                 uuid.New(),
			PolicyName:         "retention-itest",
			EventType:          &eventType,
			HotStorageDays:     30, // rows at -60d are past this
			TotalRetentionDays: 45, // ...and past this
			IsActive:           true,
		},
	}
}

func (f *retentionFixture) service() *RetentionService {
	return &RetentionService{db: f.db, bypassDB: f.db}
}

func (f *retentionFixture) countRemaining(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(
		`SELECT count(*) FROM audit.activity_logs WHERE id = ANY($1::uuid[])`,
		pq.Array(f.ids)).Scan(&n); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	return n
}

// TestIntegration_RetentionArchiveThenDeleteCycle walks one full policy cycle
// and pins every step the two binding defects broke.
func TestIntegration_RetentionArchiveThenDeleteCycle(t *testing.T) {
	f := newRetentionFixture(t, 3)
	svc := f.service()
	ctx := context.Background()

	// 1. The sweep picks the rows up.
	forArchival, err := svc.GetLogsForArchival(ctx, f.policy)
	if err != nil {
		t.Fatalf("GetLogsForArchival: %v", err)
	}
	if len(forArchival) != 3 {
		t.Fatalf("GetLogsForArchival returned %d rows, want 3", len(forArchival))
	}

	// 2. Nothing is archived yet, so the delete gate is shut. This call is one
	//    of the three that could not bind []uuid.UUID at all.
	archived, err := svc.FilterArchivedLogs(ctx, forArchival)
	if err != nil {
		t.Fatalf("FilterArchivedLogs before marking: %v", err)
	}
	if len(archived) != 0 {
		t.Fatalf("delete gate opened before anything was archived: %d rows", len(archived))
	}

	// 3. Stamp them. Pre-fix this failed with 42P18 (untyped $1) behind a raw
	//    []uuid.UUID that lib/pq rejected first.
	const s3Key = "audit-archive/platform/itest/logs.json.gz"
	if err := svc.MarkLogsAsArchived(ctx, forArchival, s3Key); err != nil {
		t.Fatalf("MarkLogsAsArchived: %v", err)
	}

	var stampedKey string
	var stampedFlag bool
	if err := f.db.QueryRow(`
		SELECT metadata->>'s3_key', (metadata->>'archived')::bool
		FROM audit.activity_logs WHERE id = $1`, forArchival[0]).
		Scan(&stampedKey, &stampedFlag); err != nil {
		t.Fatalf("read archival stamp: %v", err)
	}
	if stampedKey != s3Key || !stampedFlag {
		t.Fatalf("archival stamp = (%q, %v), want (%q, true)", stampedKey, stampedFlag, s3Key)
	}

	// 4. The re-upload loop is closed: already-stamped rows are no longer
	//    offered for archival, so ArchiveLogs cannot mint a second S3 object
	//    (generateKey appends a fresh uuid) for the same bytes next cycle.
	again, err := svc.GetLogsForArchival(ctx, f.policy)
	if err != nil {
		t.Fatalf("GetLogsForArchival (second pass): %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second archival pass re-offered %d already-archived rows — the "+
			"unbounded S3 re-upload loop is back", len(again))
	}

	// 5. Now the gate opens...
	archived, err = svc.FilterArchivedLogs(ctx, forArchival)
	if err != nil {
		t.Fatalf("FilterArchivedLogs after marking: %v", err)
	}
	if len(archived) != 3 {
		t.Fatalf("FilterArchivedLogs after marking returned %d rows, want 3", len(archived))
	}

	// 6. ...and only then does anything get deleted.
	if err := svc.DeleteLogs(ctx, archived); err != nil {
		t.Fatalf("DeleteLogs: %v", err)
	}
	if n := f.countRemaining(t); n != 0 {
		t.Fatalf("%d rows survived DeleteLogs, want 0", n)
	}
}

// TestIntegration_RetentionDeleteGateRequiresArchiveStamp pins the safety
// property directly: FilterArchivedLogs — the only thing standing between
// GetLogsForDeletion and permanent deletion when S3 archival is enabled —
// returns exactly the rows that carry an archival stamp, never more. A partial
// archive must yield a partial delete, not an all-or-nothing one.
func TestIntegration_RetentionDeleteGateRequiresArchiveStamp(t *testing.T) {
	f := newRetentionFixture(t, 3)
	svc := f.service()
	ctx := context.Background()

	forDeletion, err := svc.GetLogsForDeletion(ctx, f.policy)
	if err != nil {
		t.Fatalf("GetLogsForDeletion: %v", err)
	}
	if len(forDeletion) != 3 {
		t.Fatalf("GetLogsForDeletion returned %d rows, want 3", len(forDeletion))
	}

	// Archive exactly one of the three.
	if err := svc.MarkLogsAsArchived(ctx, forDeletion[:1], "audit-archive/partial.json.gz"); err != nil {
		t.Fatalf("MarkLogsAsArchived (partial): %v", err)
	}

	archived, err := svc.FilterArchivedLogs(ctx, forDeletion)
	if err != nil {
		t.Fatalf("FilterArchivedLogs: %v", err)
	}
	if len(archived) != 1 || archived[0] != forDeletion[0] {
		t.Fatalf("gate returned %v, want exactly [%v]", archived, forDeletion[0])
	}

	// Deleting what the gate allowed leaves the two unarchived rows intact.
	if err := svc.DeleteLogs(ctx, archived); err != nil {
		t.Fatalf("DeleteLogs: %v", err)
	}
	if n := f.countRemaining(t); n != 2 {
		t.Fatalf("%d rows remain after gated delete, want 2 (the unarchived ones)", n)
	}
}

// TestIntegration_RetentionArchivalSkipsNullMetadata guards the NULL trap in
// the not-already-archived predicate. metadata is nullable and the 'archived'
// key is absent on every unswept row, so `NOT (metadata->>'archived' = 'true')`
// evaluates to NULL there and would filter out precisely the rows that still
// need archiving — silently reintroducing "retention deletes nothing", with a
// green build and no error anywhere.
func TestIntegration_RetentionArchivalSkipsNullMetadata(t *testing.T) {
	f := newRetentionFixture(t, 2)
	svc := f.service()
	ctx := context.Background()

	// One row with metadata explicitly NULL, one with the column's '{}' default.
	if _, err := f.db.Exec(
		`UPDATE audit.activity_logs SET metadata = NULL WHERE id = $1`, f.ids[0]); err != nil {
		t.Fatalf("null out metadata: %v", err)
	}

	forArchival, err := svc.GetLogsForArchival(ctx, f.policy)
	if err != nil {
		t.Fatalf("GetLogsForArchival: %v", err)
	}
	if len(forArchival) != 2 {
		t.Fatalf("GetLogsForArchival returned %d rows, want 2 — a row with NULL or "+
			"key-less metadata was dropped by the not-archived predicate", len(forArchival))
	}

	// And the stamp still applies to the NULL-metadata row (COALESCE).
	if err := svc.MarkLogsAsArchived(ctx, forArchival, "audit-archive/null-meta.json.gz"); err != nil {
		t.Fatalf("MarkLogsAsArchived: %v", err)
	}
	archived, err := svc.FilterArchivedLogs(ctx, forArchival)
	if err != nil {
		t.Fatalf("FilterArchivedLogs: %v", err)
	}
	if len(archived) != 2 {
		t.Fatalf("FilterArchivedLogs returned %d rows, want 2", len(archived))
	}
}
