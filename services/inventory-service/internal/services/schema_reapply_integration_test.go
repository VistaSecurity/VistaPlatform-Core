package services

// Regression guard: scripts/database/schema.sql must stay re-appliable AFTER the
// database has data in it — not merely against an empty one.
//
// The chart's schema-migration Job re-runs the whole file on every helm upgrade
// under `psql -v ON_ERROR_STOP=1`, so any statement that only succeeds on an
// empty database breaks upgrades for every existing install.
//
// That is exactly what happened with the four crypto_implementations junction
// FKs. They targeted crypto_implementations_legacy(id), an empty residual table,
// so they could never be satisfied by live (partitioned) implementations; they
// were dropped in POST-MIGRATIONS but the pg_dump body still re-ADDed them
// earlier in the same file. On a fresh database both passes succeeded (the
// junctions were empty, so ADD CONSTRAINT was trivially satisfiable). Once real
// rows existed the re-ADD failed, aborting the migration Job.
//
// Testing double-apply on an empty database — which is what the previous
// idempotency checks did — cannot catch this. Populate first, then re-apply.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Schema_ReappliesOverPopulatedJunctions(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	// Populate every junction that hangs off crypto_implementations. Each of
	// these inserts was blocked outright by the stale legacy FKs, and each would
	// then break the next re-apply once the FK was dropped but still re-added.
	assetID, implID := uuid.New(), uuid.New()
	mustExec(t, db, `
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'schema-reapply.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`, assetID, tenant)
	mustExec(t, db, `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`, implID, tenant, assetID)

	keyID := uuid.New()
	mustExec(t, db, `INSERT INTO keys (id, tenant_id, key_type, state, created_at) VALUES ($1,$2,'rsa','active',NOW())`, keyID, tenant)
	mustExec(t, db, `INSERT INTO implementation_keys (implementation_id, key_id) VALUES ($1,$2)`, implID, keyID)

	var algID uuid.UUID
	if err := db.QueryRow(`SELECT id FROM algorithms LIMIT 1`).Scan(&algID); err != nil {
		t.Fatalf("no algorithms seeded: %v", err)
	}
	mustExec(t, db, `
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
		VALUES ($1,$2,'symmetric',false)`, implID, algID)

	certID := uuid.New()
	mustExec(t, db, `
		INSERT INTO certificates (id, tenant_id, serial_number, subject_dn, issuer_dn, fingerprint_sha256, not_before, not_after, created_at, updated_at)
		VALUES ($1,$2,'01','CN=a','CN=b',encode(gen_random_bytes(32),'hex'),NOW(),NOW()+interval '1 year',NOW(),NOW())`, certID, tenant)
	// role 'leaf' deliberately: it is what LinkCertificateToImplementation writes
	// for the primary certificate, and the original valid_certificate_role CHECK
	// did not allow it — every leaf-cert junction insert failed silently while
	// chain certs linked fine. This pins the widened CHECK.
	mustExec(t, db, `INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role) VALUES ($1,$2,'leaf')`, implID, certID)

	libID := uuid.New()
	mustExec(t, db, `INSERT INTO crypto_libraries (id, tenant_id, name, version, created_at, updated_at) VALUES ($1,$2,'openssl','3.0',NOW(),NOW())`, libID, tenant)
	mustExec(t, db, `INSERT INTO implementation_libraries (implementation_id, library_id) VALUES ($1,$2)`, implID, libID)

	// Now re-apply the schema exactly as the migration Job does.
	schemaPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql")
	body, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("schema.sql is not re-appliable once the junctions have rows — "+
			"the migration Job would abort on the next helm upgrade: %v", err)
	}

	// And the data must survive it.
	var links int
	if err := db.QueryRow(`SELECT COUNT(*) FROM implementation_keys WHERE implementation_id = $1`, implID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Errorf("implementation_keys row count = %d after re-apply, want 1", links)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec failed: %v\nSQL: %s", err, q)
	}
}
