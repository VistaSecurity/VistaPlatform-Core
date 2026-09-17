package services

// Integration proof of the owner's re-observation model for a DENIED asset:
// when an existing CI is re-observed, it is enriched if the observation
// carries new data, and otherwise only its last-seen moves. That already held
// for `monitoring`, `pending_approval` and `archived` assets — the identity
// engine's Touch in shared/identity/engine.go is unconditional on a match —
// but `denied` short-circuited BEFORE the observation ever reached the engine
// (`if found && existingStatus == "denied" { continue }`, pre-dating the
// identity resolve), so a denied asset's last_seen_at never moved again no
// matter how many times a sensor kept reporting it.
//
// The fix does not route denied re-observations through the full identity
// engine the way `archived` is (resolveDiscoveryObservation): that path can
// attach new identifiers and can reroute the observation to
// external_connections depending on how ownership is freshly classified. Both
// would grow new evidence on a decision the tenant already made. Instead it
// calls the engine repository's Touch directly — last_seen_at only.
//
// Mutation that proves this test: restore the early
// `if found && existingStatus == "denied" { continue }` with no Touch call —
// the "last-seen still advances" assertion goes red while status/crypto/defer
// assertions stay green (the early return already got those right).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Ingest_DeniedAssetIsTouchedNotResurrected(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	const host = "denied-host.example.test"
	const addr = "198.51.100.61"

	// Discovered once, then denied by the tenant.
	if _, err := svc.IngestFindings(tenant,
		[]IngestFinding{effectiveStatusFinding(host, addr, 443, hexFingerprint("denied-443"))},
		identity.StatusMonitoring); err != nil {
		t.Fatalf("seeding the asset: %v", err)
	}
	var assetID uuid.UUID
	if err := db.QueryRow(
		`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
		tenant, host).Scan(&assetID); err != nil {
		t.Fatalf("read back the asset: %v", err)
	}
	mustExec(t, raw, `UPDATE assets SET asset_status = 'denied' WHERE tenant_id = $1 AND id = $2`, tenant, assetID)

	// Push last_seen_at into the past so a real advance is unambiguous — the
	// asset was just created, so "now" and "after re-observation" could
	// otherwise land in the same instant on a fast test run.
	past := time.Now().Add(-6 * time.Hour).UTC()
	mustExec(t, raw, `UPDATE assets SET last_seen_at = $3 WHERE tenant_id = $1 AND id = $2`, tenant, assetID, past)

	var beforeSeen time.Time
	if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).
		Scan(&beforeSeen); err != nil {
		t.Fatalf("read last_seen_at before re-observation: %v", err)
	}

	// The sensor keeps reporting the same denied host, on a new port, in a
	// batch whose rule evaluation said monitoring — the most permissive
	// possible re-observation, so "it stayed denied" is not an accident of a
	// conservative batch status.
	report, err := svc.IngestFindingsReport(tenant,
		[]IngestFinding{effectiveStatusFinding(host, addr, 8443, hexFingerprint("denied-8443"))},
		identity.StatusMonitoring)
	if err != nil {
		t.Fatalf("IngestFindingsReport: %v", err)
	}

	t.Run("the asset stays denied", func(t *testing.T) {
		var status string
		if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).
			Scan(&status); err != nil {
			t.Fatalf("read asset status: %v", err)
		}
		if status != identity.StatusDenied {
			t.Errorf("the asset is %q; a re-discovery undid the tenant's deny decision", status)
		}
	})

	t.Run("last_seen_at advances", func(t *testing.T) {
		var afterSeen time.Time
		if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).
			Scan(&afterSeen); err != nil {
			t.Fatalf("read last_seen_at after re-observation: %v", err)
		}
		if !afterSeen.After(beforeSeen) {
			t.Errorf("last_seen_at is %s, want after %s — a denied asset that is still being observed must still "+
				"advance its last-seen, or every operational surface ordered by recency silently pretends it went "+
				"dark", afterSeen, beforeSeen)
		}
	})

	t.Run("no crypto configuration materialized on the new port", func(t *testing.T) {
		var onNewPort int
		if err := db.QueryRow(`
			SELECT count(*)
			  FROM crypto_implementations ci
			  JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND e.port = 8443 AND ci.deleted_at IS NULL`,
			tenant, assetID).Scan(&onNewPort); err != nil {
			t.Fatalf("count configurations: %v", err)
		}
		if onNewPort != 0 {
			t.Errorf("%d crypto configuration(s) materialized on a denied device", onNewPort)
		}
	})

	t.Run("no endpoint was attached for the new port", func(t *testing.T) {
		// The minimal Touch must not go through UpsertEndpoints either — a
		// denied asset gains no new evidence at all, not even a socket.
		var endpoints int
		if err := db.QueryRow(`
			SELECT count(*) FROM asset_endpoints
			 WHERE tenant_id = $1 AND asset_id = $2 AND port = 8443`,
			tenant, assetID).Scan(&endpoints); err != nil {
			t.Fatalf("count endpoints: %v", err)
		}
		if endpoints != 0 {
			t.Errorf("%d endpoint(s) attached to a denied asset on :8443 — a denied asset must not grow new "+
				"identity evidence", endpoints)
		}
	})

	t.Run("nothing was parked in deferred_findings", func(t *testing.T) {
		var deferred int
		if err := db.QueryRow(`
			SELECT COALESCE(jsonb_array_length(metadata->'deferred_findings'), 0)
			  FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).Scan(&deferred); err != nil {
			t.Fatalf("read deferred_findings: %v", err)
		}
		if deferred != 0 {
			t.Errorf("%d finding(s) were deferred onto a denied asset, where no approval will ever replay them",
				deferred)
		}
	})

	t.Run("the caller is told the asset is denied, not promoted", func(t *testing.T) {
		if len(report.EffectiveStatus) != 1 || report.EffectiveStatus[0] != identity.StatusDenied {
			t.Errorf("report says %v, want one %q — reporting monitoring would stamp the discovery row as "+
				"approved on the strength of a promotion that did not happen",
				report.EffectiveStatus, identity.StatusDenied)
		}
	})
}
