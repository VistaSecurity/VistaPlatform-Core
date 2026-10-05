package autoscan

// AdoptRecentJobs against a real Postgres.
//
// Creating a large automatic job can outlast inventory-service's 30 s client
// timeout while cluster-sensor-service still creates it. The sweep then sees an
// error, writes no stamp, and re-queues the same hosts on the next pass. These
// tests seed the state that leaves behind: an automatic job and its targets,
// and an asset with no stamp.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const adoptAddr = "10.20.30.51"

func seedAdoptAsset(t *testing.T, db *sql.DB, tenant uuid.UUID, addr string, stampAt string, stampJob string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	meta := `{"keep_me":"yes"}`
	if stampAt != "" {
		meta = `{"keep_me":"yes","last_auto_scan_at":"` + stampAt + `","last_auto_scan_job_id":"` + stampJob + `"}`
	}
	execOrFail(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, primary_address, metadata,
		                    last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'adopt.example.test', 'server', 'hardware.computer.server', 'monitoring', $3::inet, $4::jsonb,
		        NOW(), NOW(), NOW(), NOW())`, id, tenant, addr, meta)
	return id
}

// seedAdoptJob writes one job and one target for addr. `ageMinutes` is how long
// ago it was created.
func seedAdoptJob(t *testing.T, db *sql.DB, tenant uuid.UUID, addr, status string, started, automatic bool, ageMinutes int) (uuid.UUID, time.Time) {
	t.Helper()
	jobID := uuid.New()
	metadata := `{"options":{"active_scan":true}}`
	if automatic {
		metadata = `{"options":{"active_scan":true,"origin":"` + Origin + `"}}`
	}
	var startedAt any
	if started {
		startedAt = time.Now().Add(-time.Duration(ageMinutes) * time.Minute)
	}
	createdAt := time.Now().UTC().Add(-time.Duration(ageMinutes) * time.Minute).Truncate(time.Microsecond)
	execOrFail(t, db, `
		INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, started_at, metadata, created_at, updated_at)
		VALUES ($1, $2, 'async', $3, $4, $5::jsonb, $6, $6)`,
		jobID, tenant, status, startedAt, metadata, createdAt)
	execOrFail(t, db, `
		INSERT INTO discovery_targets (id, job_id, tenant_id, input, protocols, ports)
		VALUES ($1, $2, $3, $4, ARRAY['tls'], ARRAY[443])`,
		uuid.New(), jobID, tenant, addr)
	return jobID, createdAt
}

func readAdoptStamp(t *testing.T, db *sql.DB, tenant, assetID uuid.UUID) (at, job, keep sql.NullString) {
	t.Helper()
	if err := db.QueryRow(`
		SELECT metadata ->> 'last_auto_scan_at', metadata ->> 'last_auto_scan_job_id', metadata ->> 'keep_me'
		FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).Scan(&at, &job, &keep); err != nil {
		t.Fatalf("read the asset: %v", err)
	}
	return
}

func dueAddresses(t *testing.T, store *Store, tenant uuid.UUID) map[string]bool {
	t.Helper()
	pol := Policy{Enabled: true, RescanIntervalHours: 24}
	targets, _, err := store.EligibleTargets(context.Background(), tenant, pol, time.Now(), nil)
	if err != nil {
		t.Fatalf("EligibleTargets: %v", err)
	}
	out := map[string]bool{}
	for _, tg := range targets {
		out[tg.Address] = true
	}
	return out
}

func TestIntegration_AdoptRecentJobs_StampsAnOrphanedJobAndTheAssetLeavesTheDueList(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	assetID := seedAdoptAsset(t, db, tenant, adoptAddr, "", "")
	jobID, createdAt := seedAdoptJob(t, db, tenant, adoptAddr, "completed", true, true, 20)

	if !dueAddresses(t, store, tenant)[adoptAddr] {
		t.Fatal("setup: an unstamped asset must be due before the job is adopted")
	}

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("AdoptRecentJobs: %v", err)
	}
	if n != 1 {
		t.Fatalf("adopted %d assets, want 1", n)
	}
	at, job, keep := readAdoptStamp(t, db, tenant, assetID)
	if job.String != jobID.String() {
		t.Errorf("last_auto_scan_job_id = %q, want %s", job.String, jobID)
	}
	stamped, err := time.Parse(time.RFC3339Nano, at.String)
	if err != nil || !stamped.Equal(createdAt) {
		t.Errorf("last_auto_scan_at = %q (%v), want the job's created_at %v", at.String, err, createdAt)
	}
	if keep.String != "yes" {
		t.Errorf("keep_me = %q — adoption must merge into the metadata, not replace it", keep.String)
	}

	if dueAddresses(t, store, tenant)[adoptAddr] {
		t.Fatal("the adopted asset is still due: the next sweep would dispatch it again")
	}

	// Idempotent: the stamp now names the job, so nothing more to do.
	n, err = store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("second pass adopted %d (err %v), want 0", n, err)
	}
}

func TestIntegration_AdoptRecentJobs_DoesNotAdoptAJobThatFailedWithoutStarting(t *testing.T) {
	// It scanned nothing. ClearUnstartedScanStamps would hand the stamp back on
	// the very next pass, so adopting it would just make the two undo each
	// other.
	store, db, tenant := newStampFixture(t)
	assetID := seedAdoptAsset(t, db, tenant, adoptAddr, "", "")
	seedAdoptJob(t, db, tenant, adoptAddr, "failed", false, true, 20)

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("adopted %d, want 0 for a failed job that never started", n)
	}
	if at, _, _ := readAdoptStamp(t, db, tenant, assetID); at.Valid {
		t.Fatalf("stamp written from a job that never ran: %v", at)
	}
	if !dueAddresses(t, store, tenant)[adoptAddr] {
		t.Fatal("the asset must stay due when its job never started")
	}
}

func TestIntegration_AdoptRecentJobs_KeepsAFailedJobThatDidStart(t *testing.T) {
	// A started job probed the address even if it then failed; same rule as
	// ClearUnstartedScanStamps keeps.
	store, db, tenant := newStampFixture(t)
	assetID := seedAdoptAsset(t, db, tenant, adoptAddr, "", "")
	seedAdoptJob(t, db, tenant, adoptAddr, "failed", true, true, 20)

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("adopted %d (err %v), want 1", n, err)
	}
	if at, _, _ := readAdoptStamp(t, db, tenant, assetID); !at.Valid {
		t.Fatal("a job that started and then failed must still count as a probe")
	}
}

func TestIntegration_AdoptRecentJobs_NeverOverwritesANewerStamp(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	newer := time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339Nano)
	other := uuid.New().String()
	assetID := seedAdoptAsset(t, db, tenant, adoptAddr, newer, other)
	seedAdoptJob(t, db, tenant, adoptAddr, "completed", true, true, 30)

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("adopted %d, want 0 — the asset already has a newer stamp", n)
	}
	at, job, _ := readAdoptStamp(t, db, tenant, assetID)
	if at.String != newer || job.String != other {
		t.Fatalf("newer stamp overwritten: at=%q job=%q, want at=%q job=%q", at.String, job.String, newer, other)
	}
}

func TestIntegration_AdoptRecentJobs_LeavesAHealthyDispatchAlone(t *testing.T) {
	// RecordScanned stamps with the sweep's clock, a moment BEFORE the job
	// row's created_at. A stamp that already names the job is the normal,
	// reported case and must not be "adopted" (and counted) on every sweep.
	store, db, tenant := newStampFixture(t)
	jobID := uuid.New()
	stampAt := time.Now().UTC().Add(-20 * time.Minute).Add(-2 * time.Second).Format(time.RFC3339Nano)
	assetID := seedAdoptAsset(t, db, tenant, adoptAddr, stampAt, jobID.String())
	execOrFail(t, db, `
		INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, metadata, created_at, updated_at)
		VALUES ($1, $2, 'async', 'completed', $3::jsonb, NOW() - interval '20 minutes', NOW())`,
		jobID, tenant, `{"options":{"origin":"`+Origin+`"}}`)
	execOrFail(t, db, `
		INSERT INTO discovery_targets (id, job_id, tenant_id, input, protocols, ports)
		VALUES ($1, $2, $3, $4, ARRAY['tls'], ARRAY[443])`, uuid.New(), jobID, tenant, adoptAddr)

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("adopted %d, want 0 — the stamp already names the job", n)
	}
	if at, _, _ := readAdoptStamp(t, db, tenant, assetID); at.String != stampAt {
		t.Fatalf("stamp rewritten: %q, want %q", at.String, stampAt)
	}
}

func TestIntegration_AdoptRecentJobs_ReplacesAnOlderStamp(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	old := time.Now().UTC().Add(-30 * time.Hour).Format(time.RFC3339Nano)
	assetID := seedAdoptAsset(t, db, tenant, adoptAddr, old, uuid.New().String())
	jobID, _ := seedAdoptJob(t, db, tenant, adoptAddr, "queued", false, true, 5)

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("adopted %d (err %v), want 1", n, err)
	}
	if _, job, _ := readAdoptStamp(t, db, tenant, assetID); job.String != jobID.String() {
		t.Fatalf("job = %q, want the newer job %s", job.String, jobID)
	}
}

func TestIntegration_AdoptRecentJobs_IgnoresManualJobsAndJobsOutsideTheWindow(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	manual := seedAdoptAsset(t, db, tenant, "10.20.30.52", "", "")
	seedAdoptJob(t, db, tenant, "10.20.30.52", "completed", true, false, 20)
	stale := seedAdoptAsset(t, db, tenant, "10.20.30.53", "", "")
	seedAdoptJob(t, db, tenant, "10.20.30.53", "completed", true, true, 60*30)

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("adopted %d, want 0 (a manual job and a job older than the rescan interval)", n)
	}
	for _, id := range []uuid.UUID{manual, stale} {
		if at, _, _ := readAdoptStamp(t, db, tenant, id); at.Valid {
			t.Fatalf("asset %s was stamped", id)
		}
	}
}

func TestIntegration_AdoptRecentJobs_IsTenantScoped(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	other := testdb.NewTenant(t, db)
	// Same address, other tenant's asset and job.
	otherAsset := seedAdoptAsset(t, db, other, adoptAddr, "", "")
	seedAdoptJob(t, db, other, adoptAddr, "completed", true, true, 20)
	mine := seedAdoptAsset(t, db, tenant, adoptAddr, "", "")

	n, err := store.AdoptRecentJobs(context.Background(), tenant, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("adopted %d for a tenant with no job", n)
	}
	if at, _, _ := readAdoptStamp(t, db, tenant, mine); at.Valid {
		t.Fatal("tenant's asset stamped from another tenant's job")
	}
	if at, _, _ := readAdoptStamp(t, db, other, otherAsset); at.Valid {
		t.Fatal("another tenant's asset was stamped by this tenant's call")
	}
}
