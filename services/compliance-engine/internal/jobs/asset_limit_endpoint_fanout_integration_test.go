package jobs

// Phase 1 (workstream 1.5): an asset is a THING, not a listening port.
//
// `network_assets` held one row per (host, port), so a server exposing HTTPS,
// SSH and LDAPS was three assets and consumed three units of the tenant's
// max_assets cap. `assets` holds one row per host and `asset_endpoints` holds
// its faces, so the same server is one unit.
//
// That makes the fan-out join the one dangerous edit in this file. Anything
// reaching through asset_endpoints to count "assets" restores the old inflation
// silently: the number still looks plausible, it just bills the customer for
// ports and warns them to upgrade a plan they are nowhere near exhausting. This
// test seeds an estate whose ENDPOINT count is over the cap and whose ASSET
// count is well under it, so a join that counted faces cannot stay quiet.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedHostWithEndpoints inserts one asset and `faces` endpoints on it, each a
// distinct (address, port) — the way a multi-service host is actually recorded.
// Addresses come from RFC 5737 TEST-NET-1 (192.0.2.0/24), which is reserved for
// documentation and which the public-tree export's leak gate accepts.
func (h *jobHarness) seedHostWithEndpoints(t *testing.T, tenant uuid.UUID, host, faces int) {
	t.Helper()
	addr := fmt.Sprintf("192.0.2.%d", host)
	var assetID uuid.UUID
	if err := h.owner.QueryRow(`
		INSERT INTO assets (tenant_id, class_key, class_path, hostname, primary_address, asset_status)
		VALUES ($1, 'server', 'hardware.computer.server', $2, $3::inet, 'monitoring')
		RETURNING id`,
		tenant, fmt.Sprintf("fanout-host-%d.example.test", host), addr,
	).Scan(&assetID); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	for f := 0; f < faces; f++ {
		h.exec(t, `
			INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, transport, status)
			VALUES ($1, $2, $3::inet, $4, 'tcp', 'active')`,
			tenant, assetID, addr, 8000+f)
	}
}

// TestIntegration_AssetLimitScan_CountsHostsNotEndpoints pins the unit of the
// asset cap to the asset, not to its faces.
func TestIntegration_AssetLimitScan_CountsHostsNotEndpoints(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	h.newTierWithAssetCap(t, tenant, 10, 10)

	// 3 hosts, 4 endpoints each: 3/10 = 30% of the cap by asset (silent), but
	// 12/10 = 120% by endpoint (which would alert at the `high` rung).
	for host := 1; host <= 3; host++ {
		h.seedHostWithEndpoints(t, tenant, host, 4)
	}

	// Guard the guard: if the endpoints did not land, "no alert" below would
	// pass for the wrong reason.
	var endpoints int
	if err := h.owner.QueryRow(
		`SELECT COUNT(*) FROM asset_endpoints WHERE tenant_id = $1`, tenant).Scan(&endpoints); err != nil {
		t.Fatalf("count endpoints: %v", err)
	}
	if endpoints != 12 {
		t.Fatalf("seed produced %d endpoints, want 12 — the test would pass vacuously", endpoints)
	}

	job := NewAssetLimitScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "asset_limit_approaching"); got != 0 {
		t.Fatalf("3 hosts against a cap of 10 alerted: got %d, want 0. Twelve "+
			"endpoints live on those three hosts, so the count has reached "+
			"through asset_endpoints and is measuring ports — which bills a "+
			"customer for the faces of one machine", got)
	}

	// Positive control: the same job MUST still alert when the ASSET count
	// genuinely approaches the cap. Without this, a count that always returned
	// zero would sail through the assertion above.
	for host := 4; host <= 9; host++ {
		h.seedHostWithEndpoints(t, tenant, host, 1)
	}
	job.ScanAll()

	if got := h.alertCount(t, tenant, "asset_limit_approaching"); got != 1 {
		t.Fatalf("9 hosts against a cap of 10 (90%%) did not alert: got %d, want 1", got)
	}
}
