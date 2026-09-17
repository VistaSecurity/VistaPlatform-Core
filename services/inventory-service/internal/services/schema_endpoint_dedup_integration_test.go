package services

// Regression guard for the POST-MIGRATIONS block in scripts/database/schema.sql
// that merges asset_endpoints rows the IP-literal-fqdn defect duplicated on
// existing installs (see the long comment above that block, and CLAUDE.md's
// "Endpoint Identity" fix summary).
//
// This is the double-apply-with-data pattern schema_reapply_integration_test.go
// established: populate the tables the merge touches BEFORE re-applying
// schema.sql, because every constraint and every merge query is trivially
// correct against an empty table. Here that means seeding two duplicate
// asset_endpoints rows for one (address, port, transport) — the exact shape
// the defect produced — plus one dependent row in each of the three tables the
// merge re-points (crypto_implementations, external_connections, ssh_keys),
// then asserting the merge actually happened AND that a second re-apply is a
// no-op (idempotent).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Schema_MergesDuplicateAssetEndpoints(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	assetID := uuid.New()
	mustExec(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'endpoint-merge.example.test', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
		assetID, tenant)

	// Two rows the IP-literal-fqdn defect produced for ONE listener:
	// survivorID is the OLDER row (a passive observation, no name yet);
	// loserID is the NEWER row (an active scan that resolved a real name this
	// time — the merge's job is to keep that name, not just the older row).
	survivorID, loserID := uuid.New(), uuid.New()
	mustExec(t, db, `
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, fqdn, port, transport, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, '192.0.2.230'::inet, NULL, 443, 'tcp', NOW() - interval '2 days', NOW() - interval '2 days')`,
		survivorID, tenant, assetID)
	mustExec(t, db, `
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, fqdn, port, transport, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, '192.0.2.230'::inet, 'host.corp.example', 443, 'tcp', NOW() - interval '1 day', NOW() - interval '1 day')`,
		loserID, tenant, assetID)

	// One dependent in each of the three tables the merge must re-point,
	// every one of them pointing at the row that is about to be deleted.
	implID := uuid.New()
	mustExec(t, db, `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, endpoint_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,$4,'TLS','active',NOW(),NOW())`,
		implID, tenant, assetID, loserID)

	connID := uuid.New()
	mustExec(t, db, `
		INSERT INTO external_connections (id, tenant_id, source_ip, dest_ip, dest_port, protocol, source_endpoint_id)
		VALUES ($1,$2,'192.0.2.1'::inet,'192.0.2.230'::inet,443,'TLS',$3)`,
		connID, tenant, loserID)

	keyID := uuid.New()
	mustExec(t, db, `
		INSERT INTO ssh_keys (id, tenant_id, asset_id, endpoint_id, key_type, fingerprint_sha256, key_source)
		VALUES ($1,$2,$3,$4,'rsa',encode(gen_random_bytes(32),'hex'),'host_key')`,
		keyID, tenant, assetID, loserID)

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
		// Same advisory lock every applier in this module uses — see
		// schema_reapply_integration_test.go's comment on why an unlocked
		// applier breaks every OTHER package's schema-apply running in
		// parallel against the same database.
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(889)`); err != nil {
			t.Fatalf("pg_advisory_lock: %v", err)
		}
		defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(889)`) }()
		if _, err := conn.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("schema.sql is not re-appliable over duplicate asset_endpoints rows — "+
				"the migration Job would abort on the next helm upgrade: %v", err)
		}
	}

	assertMerged := func(label string) {
		t.Helper()
		var count int
		if err := db.QueryRow(`
			SELECT count(*) FROM asset_endpoints
			 WHERE tenant_id = $1 AND asset_id = $2 AND address = '192.0.2.230'::inet
			   AND port = 443 AND transport = 'tcp'`, tenant, assetID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s: asset_endpoints rows for 192.0.2.230:443/tcp = %d, want 1 (the merge did not run, or ran again and re-split them)", label, count)
		}

		var id uuid.UUID
		var fqdn sql.NullString
		if err := db.QueryRow(`
			SELECT id, fqdn FROM asset_endpoints
			 WHERE tenant_id = $1 AND asset_id = $2 AND address = '192.0.2.230'::inet
			   AND port = 443 AND transport = 'tcp'`, tenant, assetID).Scan(&id, &fqdn); err != nil {
			t.Fatal(err)
		}
		if id != survivorID {
			t.Errorf("%s: surviving endpoint id = %s, want the OLDER row %s", label, id, survivorID)
		}
		if !fqdn.Valid || fqdn.String != "host.corp.example" {
			t.Errorf("%s: surviving endpoint fqdn = %v, want %q — empty never wins, the name the loser carried must be kept", label, fqdn, "host.corp.example")
		}

		var loserStillExists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM asset_endpoints WHERE tenant_id = $1 AND id = $2)`,
			tenant, loserID).Scan(&loserStillExists); err != nil {
			t.Fatal(err)
		}
		if loserStillExists {
			t.Errorf("%s: the loser row %s still exists; it should have been deleted", label, loserID)
		}

		var implEndpoint, connEndpoint, keyEndpoint uuid.UUID
		if err := db.QueryRow(`SELECT endpoint_id FROM crypto_implementations WHERE id = $1`, implID).Scan(&implEndpoint); err != nil {
			t.Fatal(err)
		}
		if implEndpoint != survivorID {
			t.Errorf("%s: crypto_implementations.endpoint_id = %s, want the survivor %s", label, implEndpoint, survivorID)
		}
		if err := db.QueryRow(`SELECT source_endpoint_id FROM external_connections WHERE id = $1`, connID).Scan(&connEndpoint); err != nil {
			t.Fatal(err)
		}
		if connEndpoint != survivorID {
			t.Errorf("%s: external_connections.source_endpoint_id = %s, want the survivor %s", label, connEndpoint, survivorID)
		}
		if err := db.QueryRow(`SELECT endpoint_id FROM ssh_keys WHERE id = $1`, keyID).Scan(&keyEndpoint); err != nil {
			t.Fatal(err)
		}
		if keyEndpoint != survivorID {
			t.Errorf("%s: ssh_keys.endpoint_id = %s, want the survivor %s", label, keyEndpoint, survivorID)
		}
	}

	reapply()
	assertMerged("after first re-apply")

	// Idempotency: a second re-apply must find nothing left to merge and must
	// not disturb what the first pass already fixed.
	reapply()
	assertMerged("after second re-apply")
}

// TestIntegration_Schema_MergeNeverBackfillsAnIPLiteralFqdn covers the shape
// TestIntegration_Schema_MergesDuplicateAssetEndpoints deliberately does not:
// a losing row whose fqdn IS the address spelled as text. That is the value
// the defect actually wrote, so it is the value the merge is most likely to
// meet, and backfilling it onto the survivor would re-create the exact data
// this release exists to stop producing — permanently, because
// mergeEndpointByAddress fills fqdn only when the row's is empty, so no later
// observation carrying the real name could ever replace it.
//
// Three cases, because the survivor is the OLDEST row and which row that is
// depends on whether a scan or a name arrived first:
//
//	A. survivor has no name; losers are an IP literal AND a real name
//	   → the real name wins, the literal is never considered
//	B. the survivor itself carries the IP literal; a loser has the real name
//	   → the literal is overwritten
//	C. one row, no duplicate, IP literal in fqdn
//	   → cleared to NULL; there is nothing to merge it into, and steps 1-5
//	     only ever look at groups with more than one row
//
// Plus a control (D) that an address-less, fqdn-only endpoint is untouched:
// for those, fqdn is the whole identity and blanking it would leave a row
// identifying nothing.
func TestIntegration_Schema_MergeNeverBackfillsAnIPLiteralFqdn(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	newAsset := func(hostname string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		mustExec(t, db, `
			INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
				VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
			id, tenant, hostname)
		return id
	}
	endpoint := func(asset uuid.UUID, address string, fqdn *string, port int, ageDays int) uuid.UUID {
		t.Helper()
		id := uuid.New()
		var addr any
		if address == "" {
			addr = nil
		} else {
			addr = address
		}
		mustExec(t, db, `
			INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, fqdn, port, transport, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4::inet, $5, $6, 'tcp', NOW() - make_interval(days => $7), NOW())`,
			id, tenant, asset, addr, fqdn, port, ageDays)
		return id
	}
	name := func(s string) *string { return &s }

	assetA := newAsset("ipliteral-a.example.test")
	survivorA := endpoint(assetA, "192.0.2.5", nil, 8443, 3)
	endpoint(assetA, "192.0.2.5", name("192.0.2.5"), 8443, 2)
	endpoint(assetA, "192.0.2.5", name("a-host.corp.example"), 8443, 1)

	assetB := newAsset("ipliteral-b.example.test")
	survivorB := endpoint(assetB, "198.51.100.7", name("198.51.100.7"), 22, 3)
	endpoint(assetB, "198.51.100.7", name("b-host.corp.example"), 22, 1)

	assetC := newAsset("ipliteral-c.example.test")
	onlyC := endpoint(assetC, "203.0.113.9", name("203.0.113.9"), 443, 3)

	assetD := newAsset("ipliteral-d.example.test")
	onlyD := endpoint(assetD, "", name("d-named-only.corp.example"), 443, 3)

	reapply := func() {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))
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
			t.Fatalf("schema.sql is not re-appliable over IP-literal fqdn rows: %v", err)
		}
	}

	fqdnOf := func(id uuid.UUID) (string, bool) {
		t.Helper()
		var f sql.NullString
		var found bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM asset_endpoints WHERE tenant_id=$1 AND id=$2)`, tenant, id).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if !found {
			return "", false
		}
		if err := db.QueryRow(`SELECT fqdn FROM asset_endpoints WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&f); err != nil {
			t.Fatal(err)
		}
		return f.String, true
	}
	countFor := func(asset uuid.UUID) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, tenant, asset).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	assertAll := func(label string) {
		t.Helper()
		if n := countFor(assetA); n != 1 {
			t.Errorf("%s: case A rows = %d, want 1", label, n)
		}
		if got, ok := fqdnOf(survivorA); !ok || got != "a-host.corp.example" {
			t.Errorf("%s: case A survivor fqdn = %q (exists=%v), want %q — an IP literal must never be a backfill candidate",
				label, got, ok, "a-host.corp.example")
		}
		if n := countFor(assetB); n != 1 {
			t.Errorf("%s: case B rows = %d, want 1", label, n)
		}
		if got, ok := fqdnOf(survivorB); !ok || got != "b-host.corp.example" {
			t.Errorf("%s: case B survivor fqdn = %q (exists=%v), want %q — a survivor's OWN IP-literal fqdn must be replaced by the real name",
				label, got, ok, "b-host.corp.example")
		}
		if got, ok := fqdnOf(onlyC); !ok || got != "" {
			t.Errorf("%s: case C fqdn = %q (exists=%v), want empty — a lone row's IP-literal fqdn must be cleared, nothing will ever replace it otherwise",
				label, got, ok)
		}
		if got, ok := fqdnOf(onlyD); !ok || got != "d-named-only.corp.example" {
			t.Errorf("%s: case D fqdn = %q (exists=%v), want it untouched — for an address-less endpoint the name IS the identity",
				label, got, ok)
		}
	}

	reapply()
	assertAll("after first re-apply")
	reapply()
	assertAll("after second re-apply")
}
