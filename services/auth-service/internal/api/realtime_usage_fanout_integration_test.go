package api

// Phase 1 (workstream 1.5): the asset usage a tenant is shown.
//
// GetRealtimeCounts feeds the usage figures on the tenant's own billing page,
// beside the limits their plan allows. Before phase 1, `network_assets` held a
// row per (host, port), so a server exposing HTTPS, SSH and LDAPS was reported
// as three assets against the cap. `assets` holds one row per host and the
// faces are `asset_endpoints` rows, so it is one — and a query that reaches
// through asset_endpoints to "restore" the familiar larger number is billing a
// customer for ports.
//
// Two properties are only observable against a real database and are pinned
// together here:
//
//  1. the count is per host, not per endpoint;
//  2. it runs with app.tenant_id set. `assets` carries an
//     assets_tenant_isolation policy, and a plain-pool read of an RLS-policied
//     table returns ZERO rows rather than an error — so a regression that
//     dropped the WithTenantTx would report every tenant as using nothing, and
//     no test asserting only "no error" would notice.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedMonitoredHosts creates `hosts` monitored assets under the tenant, each
// with `faces` endpoints, plus one asset that must NOT be counted for each of
// the two reasons this query already filters on: soft-deleted, and still
// pending approval. Addresses are RFC 5737 TEST-NET-1.
func seedMonitoredHosts(t *testing.T, db *sql.DB, tenant uuid.UUID, hosts, faces int) {
	t.Helper()
	newAsset := func(status string, deleted bool, n int) uuid.UUID {
		addr := fmt.Sprintf("192.0.2.%d", n)
		var id uuid.UUID
		deletedAt := "NULL"
		if deleted {
			deletedAt = "NOW()"
		}
		if err := db.QueryRow(fmt.Sprintf(`
			INSERT INTO assets (tenant_id, class_key, class_path, hostname, primary_address, asset_status, deleted_at)
			VALUES ($1, 'server', 'hardware.computer.server', $2, $3::inet, $4, %s)
			RETURNING id`, deletedAt),
			tenant, fmt.Sprintf("usage-%d.example.test", n), addr, status).Scan(&id); err != nil {
			t.Fatalf("insert asset %d: %v", n, err)
		}
		for f := 0; f < faces; f++ {
			if _, err := db.Exec(`
				INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, transport, status)
				VALUES ($1, $2, $3::inet, $4, 'tcp', 'active')`,
				tenant, id, addr, 8000+f); err != nil {
				t.Fatalf("insert endpoint %d/%d: %v", n, f, err)
			}
		}
		return id
	}

	for h := 1; h <= hosts; h++ {
		newAsset("monitoring", false, h)
	}
	newAsset("monitoring", true, hosts+1)        // soft-deleted
	newAsset("pending_approval", false, hosts+2) // not yet approved

	var endpoints int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM asset_endpoints WHERE tenant_id = $1`, tenant).Scan(&endpoints); err != nil {
		t.Fatalf("count endpoints: %v", err)
	}
	if want := (hosts + 2) * faces; endpoints != want {
		t.Fatalf("seed produced %d endpoints, want %d — the fan-out assertion would be vacuous", endpoints, want)
	}
}

// TestIntegration_RealtimeCounts_CountsHostsNotEndpoints pins the number a
// customer reads as their own usage.
func TestIntegration_RealtimeCounts_CountsHostsNotEndpoints(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)

	const hosts, faces = 3, 4
	seedMonitoredHosts(t, owner, tenant, hosts, faces)

	// Read as the non-owner `crypto_app` role, the way the service connects.
	// The owner bypasses RLS, so an owner-only test could not tell a correctly
	// scoped read from one that forgot to set app.tenant_id.
	app := testdb.ConnectAsAppRole(t, owner)

	_, assets, _ := newBillingRepo(app).GetRealtimeCounts(context.Background(), tenant)

	switch assets {
	case hosts:
		// correct
	case 0:
		t.Fatalf("assets = 0 with %d monitored hosts seeded. `assets` is RLS-policied, "+
			"so a read outside WithTenantTx returns no rows and no error — which is "+
			"reported to the customer as zero usage", hosts)
	case (hosts + 2) * faces, hosts * faces:
		t.Fatalf("assets = %d, want %d — that is an ENDPOINT count. The query reached "+
			"through asset_endpoints, so a host exposing %d services is charged %d "+
			"times against the plan limit", assets, hosts, faces, faces)
	default:
		t.Fatalf("assets = %d, want %d (monitored, live hosts only: one soft-deleted and "+
			"one pending_approval asset were seeded and must not count)", assets, hosts)
	}
}
