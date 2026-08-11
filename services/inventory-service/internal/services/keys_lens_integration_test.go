package services

// Integration proof that the Keys-lens reads (ListKeys / GetKeyByID) can scan a
// key whose driver-typed columns are populated. key_usage is text[] and
// metadata is jsonb; both used to be scanned straight into models.Key's
// []string / map[string]interface{} fields, which lib/pq cannot do — so the
// whole Keys lens errored ("unsupported Scan, storing []uint8") the moment any
// key carried a usage array or metadata. These pin the fix.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newKeysSvc(t *testing.T) (*AssetService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	return &AssetService{db: db}, db, tenant
}

func insertKey(t *testing.T, db *database.DB, tenant uuid.UUID, usage, metadata string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO keys (id, tenant_id, key_type, key_usage, metadata, state, created_at)
		VALUES ($1, $2, 'rsa', $3::text[], $4::jsonb, 'active', NOW())`,
		id, tenant, usage, metadata)
	if err != nil {
		t.Fatalf("insert key: %v", err)
	}
	return id
}

func TestIntegration_KeysLens_ScansUsageAndMetadata(t *testing.T) {
	svc, db, tenant := newKeysSvc(t)
	id := insertKey(t, db, tenant, `{encrypt,sign}`, `{"origin":"unit"}`)

	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys failed on a key with usage+metadata (the bug): %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListKeys returned %d keys, want 1", len(keys))
	}
	if got := keys[0].KeyUsage; len(got) != 2 || got[0] != "encrypt" || got[1] != "sign" {
		t.Errorf("KeyUsage = %v, want [encrypt sign]", got)
	}
	if keys[0].Metadata["origin"] != "unit" {
		t.Errorf("Metadata = %v, want origin=unit", keys[0].Metadata)
	}

	one, err := svc.GetKeyByID(tenant, id)
	if err != nil {
		t.Fatalf("GetKeyByID failed: %v", err)
	}
	if len(one.KeyUsage) != 2 {
		t.Errorf("GetKeyByID KeyUsage = %v, want 2 entries", one.KeyUsage)
	}
}

// A key with NULL usage/metadata must still scan (the pre-fix code happened to
// work only in this case, which is why the bug hid).
func TestIntegration_KeysLens_ScansNullColumns(t *testing.T) {
	svc, db, tenant := newKeysSvc(t)
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO keys (id, tenant_id, key_type, state, created_at)
		VALUES ($1, $2, 'ec', 'active', NOW())`, id, tenant); err != nil {
		t.Fatalf("insert bare key: %v", err)
	}
	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys failed on a bare key: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
}
