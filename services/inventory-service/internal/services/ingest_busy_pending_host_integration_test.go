package services

// Hole H12: a pending host with many open ports keeps every port, and
// the crypto of every TLS port, through approval.
//
// A pending asset parks the findings it will materialize on approval in a
// capped metadata array (maxDeferredFindings, deduplicated by fingerprint).
// Two things lost data on a busy host:
//
//   - the fingerprint ignored the endpoint, so the same certificate and suite
//     on :443 and :8443 were ONE deferred finding and approval put the
//     configuration on one port only — where the approved path stores one per
//     port;
//   - a full-estate scan reports every open port, most of them unidentified
//     ("tcp"), and those parked findings — which materialize nothing — took
//     slots, so the cap dropped the oldest entries: the TLS ports found first.
//
// The ports themselves are endpoints of the asset from the moment they are
// observed. Driven through the real IngestFindings and ApproveAssets.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Ingest_BusyPendingHostKeepsItsPortsAndCrypto(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	const host, addr = "busy-01.example.test", "198.51.100.61"
	// The TLS listeners first — one certificate served on three ports, the
	// usual case — then 60 open ports nothing could name: the order a scan
	// reports them in, and the order that used to lose the TLS.
	var findings []IngestFinding
	tlsPorts := []int{443, 8443, 9443}
	for _, port := range tlsPorts {
		findings = append(findings, effectiveStatusFinding(host, addr, port, hexFingerprint("busy-host-cert")))
	}
	for port := 20000; port < 20060; port++ {
		h, a, p := host, addr, port
		findings = append(findings, IngestFinding{
			Hostname: &h, IPAddress: &a, Port: &p, Protocol: "tcp", AssetType: "server",
			RawData: map[string]interface{}{"source": "platform", "discovery_method": "active", "transport": "tcp", "unidentified": true, "banner_len": 0},
		})
	}
	for _, f := range findings {
		if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, identity.StatusPendingApproval); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	var assetID uuid.UUID
	if err := db.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`, tenant, host).Scan(&assetID); err != nil {
		t.Fatalf("read back the asset: %v", err)
	}
	endpoints := func() int {
		var n int
		if err := db.QueryRow(`SELECT count(DISTINCT port) FROM asset_endpoints WHERE tenant_id = $1 AND asset_id = $2`, tenant, assetID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := endpoints(); n != 63 {
		t.Fatalf("pending host has %d endpoint ports, want all 63 observed", n)
	}

	if err := svc.ApproveAssets(tenant, []uuid.UUID{assetID}, uuid.Nil); err != nil {
		t.Fatalf("ApproveAssets: %v", err)
	}
	if n := endpoints(); n != 63 {
		t.Errorf("approved host has %d endpoint ports, want 63", n)
	}
	var withCrypto []int
	if err := db.Select(&withCrypto, `
		SELECT DISTINCT e.port FROM crypto_implementations ci
		JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
		WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND ci.deleted_at IS NULL ORDER BY e.port`, tenant, assetID); err != nil {
		t.Fatal(err)
	}
	if len(withCrypto) != len(tlsPorts) {
		t.Fatalf("after approval the TLS configuration is on ports %v, want all of %v", withCrypto, tlsPorts)
	}
}
