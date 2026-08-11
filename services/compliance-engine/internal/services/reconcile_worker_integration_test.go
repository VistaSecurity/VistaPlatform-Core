package services

// Database-integration test for SEC-5's tenant-enumerator fix: the reconcile
// fan-out must not enqueue jobs for soft-deleted tenants. Skips unless
// TEST_DATABASE_URL is set (see shared/testdb); run locally via
// `make test-integration-db`.

import (
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ListActiveTenantIDs_ExcludesSoftDeleted(t *testing.T) {
	raw := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	db := sqlx.NewDb(raw, "postgres")

	active := testdb.NewTenant(t, raw)
	deleted := testdb.NewTenant(t, raw)

	if _, err := raw.Exec(`UPDATE tenants SET deleted_at = now() WHERE id = $1`, deleted); err != nil {
		t.Fatalf("soft-delete fixture tenant: %v", err)
	}

	ids, err := listActiveTenantIDs(db)
	if err != nil {
		t.Fatalf("listActiveTenantIDs: %v", err)
	}

	var sawActive, sawDeleted bool
	for _, id := range ids {
		if id == active {
			sawActive = true
		}
		if id == deleted {
			sawDeleted = true
		}
	}

	if !sawActive {
		t.Error("listActiveTenantIDs omitted a non-deleted tenant")
	}
	// This is the SEC-5 mutation check: before the fix, the query had no
	// deleted_at filter at all, so the soft-deleted tenant would appear here
	// and receive reconcile jobs it should never get.
	if sawDeleted {
		t.Error("listActiveTenantIDs included a soft-deleted tenant — SEC-5 regression")
	}
}
