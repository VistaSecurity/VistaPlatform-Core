package services

// A carrier-grade NAT address is an internal candidate, not a third party
// ( F3, D1).
//
// Tailscale, ZeroTier and mobile carriers hand out 100.64.0.0/10. Before the
// shared address predicate, ClassifyAsset knew only RFC 1918 (and later ULA),
// so a tenant's own overlay host that matched no segment was classified
// third_party and filed in external_connections. This drives the REAL ingest
// path, both polarities:
//
//	CGNAT       100.64.x, no segment → a managed asset, ownership unknown,
//	            no external_connections row
//	public      a documentation address, no segment → still
//	            external_connections, so the change did not widen to
//	            everything
//
// Reverting NetworkTypeForAddress to IsPrivate-only turns the first red;
// making it answer "private" for everything turns the second red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CGNATFindingIsAnInternalCandidate(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := newCloudRoutingAssetService(db)

	finding := func(host, ip string) IngestFinding {
		port := 443
		version := "TLS 1.3"
		return IngestFinding{
			Hostname:        &host,
			IPAddress:       &ip,
			Port:            &port,
			Protocol:        "TLS",
			ProtocolVersion: &version,
			// A connection has two ends ( D2): without source_ip the
			// public finding would be dropped, not routed.
			RawData: map[string]interface{}{"source": "sensor_discovery", "discovery_method": "passive", "source_ip": "10.0.0.5"},
		}
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{finding("peer.overlay.example", "100.100.7.9")}, "pending_approval"); err != nil {
		t.Fatalf("IngestFindings(CGNAT): %v", err)
	}
	if n := countExternalConnections(t, raw, tenant); n != 0 {
		t.Fatalf("a CGNAT host produced %d external_connections row(s), want 0 — it is an internal candidate", n)
	}
	var ownership string
	if err := raw.QueryRow(`SELECT asset_ownership FROM assets WHERE tenant_id = $1 AND hostname = 'peer.overlay.example' AND deleted_at IS NULL`,
		tenant).Scan(&ownership); err != nil {
		t.Fatalf("the CGNAT host is not a managed asset: %v", err)
	}
	if ownership != "unknown" {
		t.Fatalf("CGNAT asset ownership = %q, want unknown", ownership)
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{finding("vendor.example", "203.0.113.80")}, "pending_approval"); err != nil {
		t.Fatalf("IngestFindings(public): %v", err)
	}
	if n := countExternalConnections(t, raw, tenant); n != 1 {
		t.Fatalf("a public address produced %d external_connections row(s), want 1", n)
	}
}
