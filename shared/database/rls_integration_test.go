package database_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// These tests prove REAL Row-Level Security enforcement — not the app-level
// WHERE-clause filtering the sqlmock IDOR tests assert. They run only when
// TEST_DATABASE_URL points at a schema-loaded Postgres (nightly + `make
// test-integration-db`); otherwise they skip.
//
// api_format_preferences is the probe table: it carries a plain tenant_id, a
// uuid-defaulted PK, and otherwise-nullable columns, so a row needs only a
// tenant_id. It has the canonical tenant_isolation policy (USING + WITH CHECK).

const probeTable = "public.api_format_preferences"

// TestIntegration_RLS_Enforcement proves that under the non-owner app role the
// policies deny cross-tenant reads, deny cross-tenant writes (WITH CHECK), allow
// same-tenant writes, and fail closed when no tenant context is set.
func TestIntegration_RLS_Enforcement(t *testing.T) {
	db := testdb.Connect(t)
	testdb.EnsureRLSAppRole(t, db)

	tA := testdb.NewTenant(t, db)
	tB := testdb.NewTenant(t, db)
	tC := testdb.NewTenant(t, db) // no probe row — used for the write-allow case
	tD := testdb.NewTenant(t, db) // no probe row — the cross-tenant write target

	// Seed one probe row each for tA and tB as the owner (RLS bypassed).
	seedProbe(t, db, tA)
	seedProbe(t, db, tB)

	t.Run("read-deny: tenant A sees only its own row", func(t *testing.T) {
		testdb.AsTenant(t, db, tA, func(tx *sql.Tx) {
			if got := countProbe(t, tx); got != 1 {
				t.Fatalf("tenant A visible rows = %d, want 1 (cross-tenant read leaked)", got)
			}
			var seen uuid.UUID
			if err := tx.QueryRow(`SELECT tenant_id FROM ` + probeTable).Scan(&seen); err != nil {
				t.Fatalf("scan visible tenant_id: %v", err)
			}
			if seen != tA {
				t.Fatalf("visible row tenant_id = %s, want %s", seen, tA)
			}
		})
	})

	t.Run("read-deny: tenant B sees only its own row", func(t *testing.T) {
		testdb.AsTenant(t, db, tB, func(tx *sql.Tx) {
			if got := countProbe(t, tx); got != 1 {
				t.Fatalf("tenant B visible rows = %d, want 1", got)
			}
		})
	})

	t.Run("fail-closed: no tenant context sees zero rows", func(t *testing.T) {
		testdb.AsRoleNoTenant(t, db, func(tx *sql.Tx) {
			if got := countProbe(t, tx); got != 0 {
				t.Fatalf("rows with no app.tenant_id = %d, want 0 (RLS not failing closed)", got)
			}
		})
	})

	t.Run("write-allow: same-tenant INSERT succeeds", func(t *testing.T) {
		testdb.AsTenant(t, db, tC, func(tx *sql.Tx) {
			if _, err := tx.Exec(`INSERT INTO `+probeTable+` (tenant_id) VALUES ($1)`, tC); err != nil {
				t.Fatalf("same-tenant INSERT denied unexpectedly: %v", err)
			}
		})
	})

	t.Run("write-deny: cross-tenant INSERT blocked by WITH CHECK", func(t *testing.T) {
		testdb.AsTenant(t, db, tC, func(tx *sql.Tx) {
			_, err := tx.Exec(`INSERT INTO `+probeTable+` (tenant_id) VALUES ($1)`, tD)
			if err == nil {
				t.Fatal("cross-tenant INSERT succeeded — WITH CHECK is missing or not enforced")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
				t.Fatalf("cross-tenant INSERT failed with the wrong error: %v", err)
			}
		})
	})
}

// TestIntegration_WithTenantTx_SetsContext proves the shared primitive sets
// app.tenant_id on the same connection the queries run on (the connection-pool
// pinning guarantee). It runs over the owner connection, so it checks the GUC
// directly rather than relying on enforcement.
func TestIntegration_WithTenantTx_SetsContext(t *testing.T) {
	db := testdb.Connect(t)
	tID := testdb.NewTenant(t, db)

	err := database.WithTenantTx(context.Background(), db, tID, func(tx *sql.Tx) error {
		var got string
		if err := tx.QueryRow(`SELECT current_setting('app.tenant_id', true)`).Scan(&got); err != nil {
			return err
		}
		if got != tID.String() {
			t.Fatalf("app.tenant_id in tx = %q, want %q", got, tID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTenantTx: %v", err)
	}

	// A zero tenant must be rejected by set_tenant_context's NULL guard.
	err = database.WithTenantTx(context.Background(), db, uuid.Nil, func(tx *sql.Tx) error { return nil })
	if err == nil {
		t.Fatal("WithTenantTx accepted a nil tenant; expected the NULL guard to reject it")
	}
}

func seedProbe(t *testing.T, db *sql.DB, tenantID uuid.UUID) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO `+probeTable+` (tenant_id) VALUES ($1)`, tenantID); err != nil {
		t.Fatalf("seed probe row for %s: %v", tenantID, err)
	}
}

func countProbe(t *testing.T, tx *sql.Tx) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM ` + probeTable).Scan(&n); err != nil {
		t.Fatalf("count probe rows: %v", err)
	}
	return n
}
