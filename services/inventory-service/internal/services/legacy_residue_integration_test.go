package services

// DB-backed complement to scripts/audit-legacy-residue.mjs (the static guard
// in `make audit`). The partition conversion left the drained *_legacy tables
// behind, and the stale objects pinned to them caused four incidents: junction
// FKs that broke populated re-applies, a v_ci_inventory that made
// Enterprise CMDB sync export nothing, matviews that kept the remediation
// queue permanently empty, and FKs that forced
// external_connections.source_asset_id to stay NULL forever.
//
// These tests prove, against a real schema-loaded Postgres, that
//   1. no *_legacy relation exists and nothing depends on one (pg_class /
//      pg_depend / pg_constraint — not name-regex over source);
//   2. the partitioned tables' (tenant_id, id) PRIMARY KEYs are VALID — the
//      pre-retirement schema created the old asset table's PK with
//      ALTER TABLE ONLY, which left it INVALID (uniqueness unenforced) and
//      unusable as an FK target;
//   3. the composite FK accepts a same-tenant asset reference and makes a
//      cross-tenant reference unrepresentable;
//   4. ExternalConnectionsService.Upsert persists source_asset_id when the
//      source IP matches an inventoried asset (the "best-effort" resolution
//      used to be discarded by the legacy FK: the legacy table was empty, so
//      every resolved id violated it);
//   5. v_ci_inventory serves live inventory through exactly the query
//      Enterprise CMDB sync runs.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/testdb"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func TestIntegration_Schema_NoLegacyResidue(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM pg_class WHERE relname LIKE '%\_legacy' AND relkind IN ('r','p','v','m')`,
	).Scan(&n); err != nil {
		t.Fatalf("pg_class query: %v", err)
	}
	if n != 0 {
		t.Errorf("expected zero *_legacy relations after retirement, found %d", n)
	}

	// Nothing may depend on a legacy relation either (vacuously true once the
	// tables are gone, but this is the check that catches a partial revert
	// where a table came back with a dependent view or FK).
	if err := db.QueryRow(`
		SELECT count(*) FROM pg_depend d
		JOIN pg_class c ON c.oid = d.refobjid
		WHERE c.relname LIKE '%\_legacy'`).Scan(&n); err != nil {
		t.Fatalf("pg_depend query: %v", err)
	}
	if n != 0 {
		t.Errorf("expected zero dependencies on *_legacy relations, found %d", n)
	}

	// The dead crypto_configurations table (unrouted service, zero readers)
	// must stay gone too.
	if err := db.QueryRow(
		`SELECT count(*) FROM pg_class WHERE relname = 'crypto_configurations' AND relkind = 'r'`,
	).Scan(&n); err != nil {
		t.Fatalf("crypto_configurations query: %v", err)
	}
	if n != 0 {
		t.Errorf("crypto_configurations table exists — it was dropped with its unrouted service")
	}

	// The composite FKs' referenced keys must be VALID primary keys. An
	// invalid partitioned PK enforces nothing and rejects FK creation.
	rows, err := db.Query(`
		SELECT c.relname, i.indisvalid FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.relname IN ('assets_pkey',
		                    'crypto_implementations_partitioned_pkey',
		                    'sensor_discoveries_partitioned_pkey')`)
	if err != nil {
		t.Fatalf("pkey validity query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var valid bool
		if err := rows.Scan(&name, &valid); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[name] = true
		if !valid {
			t.Errorf("%s is INVALID — (tenant_id, id) uniqueness is not enforced", name)
		}
	}
	for _, want := range []string{
		// network_assets_partitioned_pkey is gone with its table (phase 1,
		// ADR-0007 D2). `assets_pkey` replaces it and is declared IN the
		// CREATE TABLE, so it cannot be created INVALID the way an
		// ALTER TABLE ONLY parent key was.
		"assets_pkey",
		"crypto_implementations_partitioned_pkey",
		"sensor_discoveries_partitioned_pkey",
	} {
		if !seen[want] {
			t.Errorf("%s does not exist", want)
		}
	}
}

func TestIntegration_CompositeAssetFK_TenantScoped(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantA := testdb.NewTenant(t, db)
	tenantB := testdb.NewTenant(t, db)

	assetID := uuid.New()
	mustExec(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, primary_address, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'fk-scope.example.test', '10.44.44.44', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, assetID, tenantA)

	// Same tenant: accepted.
	mustExec(t, db, `
		INSERT INTO external_connections (tenant_id, source_ip, source_asset_id, dest_ip, dest_port, protocol, first_seen_at, last_seen_at)
		VALUES ($1,'10.44.44.44',$2,'203.0.113.7',443,'TLS',NOW(),NOW())`, tenantA, assetID)

	// Cross tenant: unrepresentable.
	if _, err := db.Exec(`
		INSERT INTO external_connections (tenant_id, source_ip, source_asset_id, dest_ip, dest_port, protocol, first_seen_at, last_seen_at)
		VALUES ($1,'10.44.44.44',$2,'203.0.113.7',443,'TLS',NOW(),NOW())`, tenantB, assetID); err == nil {
		t.Fatalf("cross-tenant source_asset_id was accepted — the composite FK is missing or wrong")
	}
}

func TestIntegration_ExternalConnection_PersistsSourceAssetID(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	assetID := uuid.New()
	mustExec(t, raw, `
		INSERT INTO assets (id, tenant_id, hostname, primary_address, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'ext-src.example.test', '10.55.55.55', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, assetID, tenant)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	conn, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP: "10.55.55.55",
		DestIP:   "203.0.113.9",
		DestPort: 443,
		Protocol: "TLS",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if conn.SourceAssetID == nil || *conn.SourceAssetID != assetID {
		t.Fatalf("source_asset_id not persisted: got %v, want %s — the resolved asset id "+
			"is being dropped again (the legacy FK rejected every live id)", conn.SourceAssetID, assetID)
	}
}

func TestIntegration_ExternalConnection_HonoursMeasuredSourceAssetIDOnSecondaryAddress(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	otherTenant := testdb.NewTenant(t, raw)

	assetID := uuid.New()
	mustExec(t, raw, `INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,last_seen_at,first_discovered_at,created_at,updated_at)
		VALUES($1,$2,'agent-host.example.test','10.55.55.55','server','hardware.computer.server','monitoring',NOW(),NOW(),NOW(),NOW())`, assetID, tenant)
	foreignAssetID := uuid.New()
	mustExec(t, raw, `INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,last_seen_at,first_discovered_at,created_at,updated_at)
		VALUES($1,$2,'foreign-agent.example.test','10.77.77.77','server','hardware.computer.server','monitoring',NOW(),NOW(),NOW(),NOW())`, foreignAssetID, otherTenant)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	conn, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		// A secondary interface that is intentionally neither primary_address
		// nor an endpoint. Address-only inference cannot resolve this source.
		SourceIP: "10.66.66.66", SourceAssetID: &assetID,
		DestIP: "8.8.8.8", DestPort: 443, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if conn.SourceAssetID == nil || *conn.SourceAssetID != assetID {
		t.Fatalf("source_asset_id=%v, want explicitly measured host %s", conn.SourceAssetID, assetID)
	}

	conn, err = svc.Upsert(tenant, models.ExternalConnectionUpsert{
		// A caller cannot attribute its tenant's observation to an asset owned
		// by another tenant. The unrecorded address also proves this did not
		// silently resolve through the source-address fallback.
		SourceIP: "10.88.88.88", SourceAssetID: &foreignAssetID,
		DestIP: "1.1.1.1", DestPort: 443, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("Upsert with foreign source_asset_id: %v", err)
	}
	if conn.SourceAssetID != nil {
		t.Fatalf("foreign source_asset_id was trusted across tenants: got %s", *conn.SourceAssetID)
	}
}

func TestIntegration_RouteToExternalConnection_PreservesHostInventorySourceAsset(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	assetID := uuid.New()
	mustExec(t, raw, `INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,last_seen_at,first_discovered_at,created_at,updated_at)
		VALUES($1,$2,'fallback-source.example.test','10.55.55.55','server','hardware.computer.server','monitoring',NOW(),NOW(),NOW(),NOW())`, assetID, tenant)

	svc := NewAssetService(db)
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, NewAlgorithmService(db)))
	dest, source, port := "8.8.4.4", "10.66.66.66", 443
	if err := svc.routeToExternalConnection(tenant, IngestFinding{
		IPAddress: &dest, Port: &port, Protocol: "tcp",
		RawData: map[string]interface{}{
			"source_ip": source, "source_asset_id": assetID.String(),
			"discovery_type": "host_connection", "discovery_method": "host_inventory",
		},
	}); err != nil {
		t.Fatalf("routeToExternalConnection: %v", err)
	}
	var got uuid.UUID
	if err := raw.QueryRow(`SELECT source_asset_id FROM external_connections WHERE tenant_id=$1 AND dest_ip=$2::inet AND dest_port=$3`, tenant, dest, port).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != assetID {
		t.Fatalf("source_asset_id=%s, want measured host %s", got, assetID)
	}

	// The same field from an unrelated producer is not identity evidence.
	dest, port = "8.8.4.5", 444
	if err := svc.routeToExternalConnection(tenant, IngestFinding{
		IPAddress: &dest, Port: &port, Protocol: "tcp",
		RawData: map[string]interface{}{
			"source_ip": source, "source_asset_id": assetID.String(), "discovery_method": "passive",
		},
	}); err != nil {
		t.Fatalf("route unrelated producer: %v", err)
	}
	var unrelated *uuid.UUID
	if err := raw.QueryRow(`SELECT source_asset_id FROM external_connections WHERE tenant_id=$1 AND dest_ip=$2::inet AND dest_port=$3`, tenant, dest, port).Scan(&unrelated); err != nil {
		t.Fatal(err)
	}
	if unrelated != nil {
		t.Fatalf("unrelated producer selected source asset %s", *unrelated)
	}
}

func TestIntegration_VCIInventory_ServesLiveInventory(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	assetID, implID := uuid.New(), uuid.New()
	mustExec(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'ci-inv.example.test', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, assetID, tenant)
	mustExec(t, db, `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',75,NOW(),NOW())`, implID, tenant, assetID)

	// Exactly the query Enterprise CMDB sync runs (ee/cmdbsync fetchCIsForSync).
	rows, err := db.Query(`
		SELECT id, ci_category FROM v_ci_inventory
		WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant)
	if err != nil {
		t.Fatalf("v_ci_inventory query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]bool{}
	for rows.Next() {
		var id uuid.UUID
		var cat string
		if err := rows.Scan(&id, &cat); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if id == assetID || id == implID {
			got[cat] = true
		}
	}
	if !got["infrastructure_asset"] {
		t.Errorf("v_ci_inventory does not surface the live asset — CMDB sync would export nothing")
	}
	if !got["crypto_configuration"] {
		t.Errorf("v_ci_inventory does not surface the live crypto implementation")
	}
}
