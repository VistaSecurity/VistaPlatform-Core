package services

// Integration proof of the POST-MIGRATIONS backfill in scripts/database/schema.sql
// that settles `sensor_discoveries.approval_status` on rows written BEFORE
// discovery-processor-service learned the `observed` (host observations) and
// `suppressed` (archived/denied assets) terminal values — see the owner's
// re-observation model review (2026-09). Both classes of PROCESSED row used
// to sit `pending` forever because no approval decision was ever going to be
// made about them.
//
// Same double-apply-with-data pattern as
// crypto_subset_absorb_integration_test.go's
// TestIntegration_Schema_AbsorbsPartialCryptoConfigurations: seed the
// pre-fix shape directly, re-apply schema.sql, assert the backfill, then
// re-apply again and assert it was a no-op (idempotent).
//
// Mutation that proves this test: in the POST-MIGRATIONS DO block, drop the
// `approval_status = 'pending'` predicate from either UPDATE — the "stays
// pending" negative controls go red (a row already `auto_approved`, or a
// genuinely pending row with no archived/denied match, gets rewritten). Drop
// the whole host-observation UPDATE — "observed" assertion goes red. Drop the
// asset_endpoints join UPDATE — "suppressed" assertions go red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Schema_BackfillsHonestApprovalStatus(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	// An archived asset and a denied asset, each with one endpoint — the
	// identity a discovery's (dest_ip, port) resolves through.
	archivedAssetID, deniedAssetID := uuid.New(), uuid.New()
	mustExec(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'backfill-archived.example.test', 'server', 'hardware.computer.server', 'archived', NOW(), NOW(), NOW(), NOW())`,
		archivedAssetID, tenant)
	mustExec(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'backfill-denied.example.test', 'server', 'hardware.computer.server', 'denied', NOW(), NOW(), NOW(), NOW())`,
		deniedAssetID, tenant)

	archivedEndpointID, deniedEndpointID := uuid.New(), uuid.New()
	mustExec(t, db, `
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, '198.51.100.71'::inet, 443, 'tcp', NOW(), NOW())`,
		archivedEndpointID, tenant, archivedAssetID)
	mustExec(t, db, `
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, '198.51.100.72'::inet, 443, 'tcp', NOW(), NOW())`,
		deniedEndpointID, tenant, deniedAssetID)

	// Five PROCESSED rows, written the way discovery-processor-service wrote
	// them before it knew `observed`/`suppressed`:
	hostObsID := uuid.New()
	mustExec(t, db, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'mdns', '198.51.100.73'::inet, 0, 0.9,
		        '{"discovery_type":"host_observation"}'::jsonb, 'pending', NOW())`,
		hostObsID, uuid.New(), tenant, uuid.New().String())

	hostObsNestedID := uuid.New()
	mustExec(t, db, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'nbns', '198.51.100.74'::inet, 0, 0.9,
		        '{"raw_metadata":{"discovery_type":"host_observation"}}'::jsonb, 'pending', NOW())`,
		hostObsNestedID, uuid.New(), tenant, uuid.New().String())

	onArchivedID := uuid.New()
	mustExec(t, db, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'TLS', '198.51.100.71'::inet, 443, 0.9, '{}'::jsonb, 'pending', NOW())`,
		onArchivedID, uuid.New(), tenant, uuid.New().String())

	onDeniedID := uuid.New()
	mustExec(t, db, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'TLS', '198.51.100.72'::inet, 443, 0.9, '{}'::jsonb, 'pending', NOW())`,
		onDeniedID, uuid.New(), tenant, uuid.New().String())

	// Negative control 1: a genuinely pending row — no host-observation
	// marker, no archived/denied match. Must stay pending.
	genuinelyPendingID := uuid.New()
	mustExec(t, db, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'TLS', '198.51.100.75'::inet, 443, 0.9, '{}'::jsonb, 'pending', NOW())`,
		genuinelyPendingID, uuid.New(), tenant, uuid.New().String())

	// Negative control 2: already auto_approved. The backfill is scoped to
	// approval_status = 'pending' and must never touch this.
	alreadyApprovedID := uuid.New()
	mustExec(t, db, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'TLS', '198.51.100.71'::inet, 443, 0.9, '{}'::jsonb, 'auto_approved', NOW())`,
		alreadyApprovedID, uuid.New(), tenant, uuid.New().String())

	// Negative control 3: matches the archived asset's endpoint by IP/port but
	// is still UNPROCESSED. The backfill must never touch an unprocessed row,
	// whatever its predicate would otherwise say.
	unprocessedOnArchivedID := uuid.New()
	mustExec(t, db, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'TLS', '198.51.100.71'::inet, 443, 0.9, '{}'::jsonb, 'pending', NULL)`,
		unprocessedOnArchivedID, uuid.New(), tenant, uuid.New().String())

	reapply := func() {
		t.Helper()
		schemaPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql")
		body, err := os.ReadFile(schemaPath)
		if err != nil {
			t.Fatalf("read schema: %v", err)
		}
		ctx := context.Background()
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer func() { _ = conn.Close() }()
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(889)`); err != nil {
			t.Fatalf("pg_advisory_lock: %v", err)
		}
		defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(889)`) }()
		if _, err := conn.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("schema.sql is not re-appliable over pre-fix sensor_discoveries rows — "+
				"the migration Job would abort on the next helm upgrade: %v", err)
		}
	}

	statusOf := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		var status string
		if err := db.QueryRow(`SELECT approval_status FROM sensor_discoveries WHERE tenant_id = $1 AND id = $2`, tenant, id).
			Scan(&status); err != nil {
			t.Fatalf("read approval_status for %s: %v", id, err)
		}
		return status
	}

	assertBackfilled := func(label string) {
		t.Helper()
		if got := statusOf(t, hostObsID); got != "observed" {
			t.Errorf("%s: top-level host observation approval_status = %q, want %q", label, got, "observed")
		}
		if got := statusOf(t, hostObsNestedID); got != "observed" {
			t.Errorf("%s: nested (raw_metadata) host observation approval_status = %q, want %q", label, got, "observed")
		}
		if got := statusOf(t, onArchivedID); got != "suppressed" {
			t.Errorf("%s: row on archived asset approval_status = %q, want %q", label, got, "suppressed")
		}
		if got := statusOf(t, onDeniedID); got != "suppressed" {
			t.Errorf("%s: row on denied asset approval_status = %q, want %q", label, got, "suppressed")
		}
		if got := statusOf(t, genuinelyPendingID); got != "pending" {
			t.Errorf("%s: genuinely pending row approval_status = %q, want %q (untouched)", label, got, "pending")
		}
		if got := statusOf(t, alreadyApprovedID); got != "auto_approved" {
			t.Errorf("%s: already-approved row approval_status = %q, want %q (untouched)", label, got, "auto_approved")
		}
		if got := statusOf(t, unprocessedOnArchivedID); got != "pending" {
			t.Errorf("%s: UNPROCESSED row on archived asset approval_status = %q, want %q — the backfill must never "+
				"touch an unprocessed row", label, got, "pending")
		}
	}

	reapply()
	assertBackfilled("first re-apply")

	// Idempotent: a second re-apply must find nothing left to backfill (every
	// row that could match has already moved off `pending`) and change
	// nothing further.
	reapply()
	assertBackfilled("second re-apply (idempotency)")
}
