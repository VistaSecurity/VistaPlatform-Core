package autoscan

// StampCompletedScans against a real Postgres: the one rule about which
// endpoints an automatic scan may mark as scanned, in both polarities.
//
// The owner's decision: stamp `asset_endpoints.last_scanned_at`
// when the asset is `monitoring` and the completed job actually wrote a finding
// for that endpoint; leave `pending_approval` assets unstamped, because their
// findings are deferred and "scanned" would overclaim. Every test here seeds
// the same shape — asset, endpoint, the automatic job the asset's stamp names,
// a target and a finding — and varies exactly one thing.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newStampFixture(t *testing.T) (*Store, *sql.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return NewStore(db), raw, testdb.NewTenant(t, raw)
}

func execOrFail(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

// stampSeed is one auto-scanned host as the stamp sees it.
type stampSeed struct {
	assetStatus  string // 'monitoring' | 'pending_approval'
	endpointPort int    // the endpoint's port
	findingPort  int    // the port the job's finding is for; 0 = no finding at all
	jobStatus    string // 'completed' | 'running' | ...
	automatic    bool   // false = a manual job, which this path must ignore
}

// seedAutoScannedHost writes the asset, its endpoint, the job the asset's
// `last_auto_scan_job_id` names, one target and (unless findingPort is 0) one
// finding. Returns the endpoint id and the job's completion time.
func seedAutoScannedHost(t *testing.T, db *sql.DB, tenant uuid.UUID, seed stampSeed) (uuid.UUID, time.Time) {
	t.Helper()
	assetID, endpointID, jobID, targetID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const addr = "10.20.30.40"
	completedAt := time.Date(2026, 9, 17, 6, 30, 0, 0, time.UTC)

	execOrFail(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, primary_address, metadata,
		                    last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'stamp.example.test', 'server', 'hardware.computer.server', $3, $4::inet,
		        jsonb_build_object('last_auto_scan_job_id', $5::text, 'last_auto_scan_at', '2026-09-17T06:00:00Z'),
		        NOW(), NOW(), NOW(), NOW())`,
		assetID, tenant, seed.assetStatus, addr, jobID.String())
	execOrFail(t, db, `
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4::inet, $5, 'tcp', NOW(), NOW())`,
		endpointID, tenant, assetID, addr, seed.endpointPort)

	metadata := `{"options":{"active_scan":true}}`
	if seed.automatic {
		metadata = `{"options":{"active_scan":true,"origin":"` + Origin + `"}}`
	}
	var completed any
	if seed.jobStatus == "completed" {
		completed = completedAt
	}
	execOrFail(t, db, `
		INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, started_at, completed_at, metadata, created_at, updated_at)
		VALUES ($1, $2, 'async', $3, NOW() - interval '1 hour', $4, $5::jsonb, NOW() - interval '1 hour', NOW())`,
		jobID, tenant, seed.jobStatus, completed, metadata)
	execOrFail(t, db, `
		INSERT INTO discovery_targets (id, job_id, tenant_id, input, protocols, ports, status)
		VALUES ($1, $2, $3, $4, ARRAY['TLS'], ARRAY[$5::int], 'completed')`,
		targetID, jobID, tenant, addr, seed.endpointPort)
	if seed.findingPort > 0 {
		execOrFail(t, db, `
			INSERT INTO discovery_findings (job_id, target_id, tenant_id, executed_via, protocol, port, resolved_ip, details, created_at)
			VALUES ($1, $2, $3, 'cloud', 'TLS', $4, $5::inet, '{"cipher_suite":"TLS_AES_128_GCM_SHA256"}'::jsonb, NOW())`,
			jobID, targetID, tenant, seed.findingPort, addr)
	}
	return endpointID, completedAt
}

func readStamp(t *testing.T, db *sql.DB, tenant, endpointID uuid.UUID) (sql.NullTime, sql.NullString) {
	t.Helper()
	var at sql.NullTime
	var status sql.NullString
	if err := db.QueryRow(`SELECT last_scanned_at, last_scan_status FROM asset_endpoints WHERE tenant_id = $1 AND id = $2`,
		tenant, endpointID).Scan(&at, &status); err != nil {
		t.Fatalf("read the endpoint: %v", err)
	}
	return at, status
}

func TestIntegration_StampCompletedScans_StampsAMonitoringAssetTheJobReached(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	endpointID, completedAt := seedAutoScannedHost(t, db, tenant, stampSeed{
		assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: true,
	})

	n, err := store.StampCompletedScans(context.Background(), tenant)
	if err != nil {
		t.Fatalf("StampCompletedScans: %v", err)
	}
	if n != 1 {
		t.Fatalf("stamped %d endpoints, want 1", n)
	}
	at, status := readStamp(t, db, tenant, endpointID)
	if !at.Valid || !at.Time.Equal(completedAt) {
		t.Errorf("last_scanned_at = %v, want the job's completion %v", at, completedAt)
	}
	if status.String != "completed" {
		t.Errorf("last_scan_status = %q, want completed", status.String)
	}

	// Idempotent: the sweep calls this every pass, and a second pass must
	// neither re-stamp nor report work it did not do.
	n, err = store.StampCompletedScans(context.Background(), tenant)
	if err != nil {
		t.Fatalf("second StampCompletedScans: %v", err)
	}
	if n != 0 {
		t.Errorf("second pass stamped %d endpoints, want 0", n)
	}
}

// The other polarity of the owner's decision. A pending-approval asset's
// findings are deferred until someone approves it, so "scanned" would claim
// something the inventory does not yet hold — it stays on the manual Active
// Scan list until it is approved or scanned by hand.
func TestIntegration_StampCompletedScans_LeavesAPendingApprovalAssetAlone(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	endpointID, _ := seedAutoScannedHost(t, db, tenant, stampSeed{
		assetStatus: "pending_approval", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: true,
	})

	n, err := store.StampCompletedScans(context.Background(), tenant)
	if err != nil {
		t.Fatalf("StampCompletedScans: %v", err)
	}
	if n != 0 {
		t.Fatalf("stamped %d endpoints of a pending_approval asset, want 0", n)
	}
	if at, _ := readStamp(t, db, tenant, endpointID); at.Valid {
		t.Errorf("last_scanned_at = %v on a pending_approval asset, want NULL", at.Time)
	}
}

// "Delivered findings for that endpoint" means THAT endpoint. A job that
// answered on 22 says nothing about 443 on the same host.
func TestIntegration_StampCompletedScans_NeedsAFindingForThatEndpoint(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	t.Run("finding on a different port", func(t *testing.T) {
		endpointID, _ := seedAutoScannedHost(t, db, tenant, stampSeed{
			assetStatus: "monitoring", endpointPort: 443, findingPort: 22, jobStatus: "completed", automatic: true,
		})
		if n, err := store.StampCompletedScans(context.Background(), tenant); err != nil || n != 0 {
			t.Fatalf("stamped %d endpoints (err %v) on a finding for another port, want 0", n, err)
		}
		if at, _ := readStamp(t, db, tenant, endpointID); at.Valid {
			t.Errorf("last_scanned_at = %v, want NULL", at.Time)
		}
	})
	t.Run("no finding at all", func(t *testing.T) {
		endpointID, _ := seedAutoScannedHost(t, db, tenant, stampSeed{
			assetStatus: "monitoring", endpointPort: 8443, findingPort: 0, jobStatus: "completed", automatic: true,
		})
		if n, err := store.StampCompletedScans(context.Background(), tenant); err != nil || n != 0 {
			t.Fatalf("stamped %d endpoints (err %v) with no finding, want 0", n, err)
		}
		if at, _ := readStamp(t, db, tenant, endpointID); at.Valid {
			t.Errorf("last_scanned_at = %v, want NULL", at.Time)
		}
	})
}

// A job still running has not delivered anything yet.
func TestIntegration_StampCompletedScans_WaitsForTheJobToComplete(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	endpointID, _ := seedAutoScannedHost(t, db, tenant, stampSeed{
		assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "running", automatic: true,
	})
	if n, err := store.StampCompletedScans(context.Background(), tenant); err != nil || n != 0 {
		t.Fatalf("stamped %d endpoints (err %v) for a running job, want 0", n, err)
	}
	if at, _ := readStamp(t, db, tenant, endpointID); at.Valid {
		t.Errorf("last_scanned_at = %v, want NULL", at.Time)
	}
}

// Manual scans stamp themselves at dispatch (revalidation_service.go). This
// path is the automatic sweep's and must not reach past its own jobs.
func TestIntegration_StampCompletedScans_IgnoresManualJobs(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	endpointID, _ := seedAutoScannedHost(t, db, tenant, stampSeed{
		assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: false,
	})
	if n, err := store.StampCompletedScans(context.Background(), tenant); err != nil || n != 0 {
		t.Fatalf("stamped %d endpoints (err %v) from a manual job, want 0", n, err)
	}
	if at, _ := readStamp(t, db, tenant, endpointID); at.Valid {
		t.Errorf("last_scanned_at = %v, want NULL", at.Time)
	}
}

// RLS: one tenant's completed job must not stamp another tenant's endpoint.
func TestIntegration_StampCompletedScans_IsTenantScoped(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	other := testdb.NewTenant(t, db)
	endpointID, _ := seedAutoScannedHost(t, db, other, stampSeed{
		assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: true,
	})
	if n, err := store.StampCompletedScans(context.Background(), tenant); err != nil || n != 0 {
		t.Fatalf("tenant %s stamped %d endpoints (err %v) belonging to %s", tenant, n, err, other)
	}
	if at, _ := readStamp(t, db, other, endpointID); at.Valid {
		t.Errorf("the other tenant's endpoint was stamped: %v", at.Time)
	}
}
