package services

// Elevating a third-party connection into a managed asset — PARITY_LEDGER J6,
// which had no test at all.
//
// It is the one intake path where a person promotes something the platform had
// deliberately kept OUT of inventory, so the questions it has to answer are
// exactly the ones the identification engine exists to answer: does it get real
// identifiers, does a second elevation of the same connection make a second
// asset, and does it claim to be something nobody observed.
//
// Skips without TEST_DATABASE_URL.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// seedExternalConnection writes one row of `external_connections` and returns
// its id.
func seedExternalConnection(t *testing.T, svc *AssetService, tenant uuid.UUID, host, ip string, port int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := svc.db.Exec(`
		INSERT INTO external_connections (id, tenant_id, source_ip, dest_ip, dest_hostname, dest_port, protocol)
		VALUES ($1, $2, '198.51.100.20', $3::inet, $4, $5, 'TLS')`,
		id, tenant, ip, host, port); err != nil {
		t.Fatalf("seed external connection: %v", err)
	}
	return id
}

// TestIntegration_ElevateExternalConnection_GoesThroughTheEngine: the elevated
// asset must carry the identifiers the connection described, so the NEXT
// observation of that host matches it instead of minting a duplicate beside it.
func TestIntegration_ElevateExternalConnection_GoesThroughTheEngine(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)
	svc.externalConnectionsSvc = NewExternalConnectionsService(svc.db, NewAlgorithmService(svc.db))

	connID := seedExternalConnection(t, svc, tenant, "api.vendor.example.test", "203.0.113.40", 443)

	asset, err := svc.ElevateExternalConnection(tenant, connID)
	if err != nil {
		t.Fatalf("elevate: %v", err)
	}
	if asset == nil {
		t.Fatal("elevate returned no asset")
	}

	// `external` — the class for a third party's endpoint. NOT `server`: the
	// platform has observed a socket, not a kind of machine, and asserting one
	// would be a guess shown as a fact.
	if asset.ClassKey != assetclass.KeyExternal {
		t.Errorf("class_key = %q, want %q — elevating promotes something to WATCH, not something we own",
			asset.ClassKey, assetclass.KeyExternal)
	}
	if asset.AssetOwnership != "third_party" {
		t.Errorf("asset_ownership = %q, want third_party", asset.AssetOwnership)
	}
	// `monitoring`, deliberately. Elevating is an explicit, permission-gated,
	// confirmed click on one named connection — the click IS the approval, and
	// queuing it would ask the operator to approve their own deliberate action.
	// (The gate-1 note expected pending_approval here; the code's stated reason
	// for `monitoring` is the better one, and it is what the spec documents.)
	if asset.AssetStatus != "monitoring" {
		t.Errorf("asset_status = %q, want monitoring", asset.AssetStatus)
	}

	rows := identifierRows(t, svc, tenant, asset.ID)
	if _, ok := rows["fqdn|api.vendor.example.test|"]; !ok {
		t.Errorf("the elevated asset has no fqdn identifier; the next sighting of that host would "+
			"mint a duplicate beside it. rows = %v", rows)
	}
	foundIP := false
	for key := range rows {
		if len(key) > 11 && key[:11] == "ip_address|" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("the elevated asset has no ip_address identifier; rows = %v", rows)
	}

	// The connection now points at the asset, and the metadata says where it
	// came from — an elevated asset that cannot be traced back to its
	// connection is an asset nobody can explain.
	var elevated *uuid.UUID
	if err := db.QueryRow(`SELECT elevated_asset_id FROM external_connections WHERE tenant_id=$1 AND id=$2`,
		tenant, connID).Scan(&elevated); err != nil {
		t.Fatalf("re-read the connection: %v", err)
	}
	if elevated == nil || *elevated != asset.ID {
		t.Errorf("external_connections.elevated_asset_id = %v, want the new asset %s", elevated, asset.ID)
	}
}

// TestIntegration_ElevateExternalConnection_IsIdempotent: a second click must
// return the SAME asset, not a second one. Two assets for one vendor endpoint
// is the duplicate-minting this whole workstream exists to end, and the button
// is one a person can double-click.
func TestIntegration_ElevateExternalConnection_IsIdempotent(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)
	svc.externalConnectionsSvc = NewExternalConnectionsService(svc.db, NewAlgorithmService(svc.db))

	connID := seedExternalConnection(t, svc, tenant, "idem.vendor.example.test", "203.0.113.41", 8443)

	first, err := svc.ElevateExternalConnection(tenant, connID)
	if err != nil {
		t.Fatalf("first elevate: %v", err)
	}
	second, err := svc.ElevateExternalConnection(tenant, connID)
	if err != nil {
		t.Fatalf("second elevate: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("elevating twice produced two assets (%s then %s)", first.ID, second.ID)
	}

	var n int
	if err := db.QueryRow(`
		SELECT count(*) FROM assets
		WHERE tenant_id = $1 AND hostname = 'idem.vendor.example.test' AND deleted_at IS NULL`,
		tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d assets for one elevated connection, want 1", n)
	}
}
