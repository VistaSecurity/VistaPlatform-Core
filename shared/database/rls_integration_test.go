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

// knownPoliciesWithoutWithCheck lists tenant-isolation policies deliberately
// left USING-only, with the reason. It is EMPTY and should stay that way —
// it exists so that an exception, if one is ever justified, has to be written
// down here rather than simply existing.
//
// Note what an omitted WITH CHECK does and does not mean. Postgres reuses the
// USING expression as the WITH CHECK when the latter is omitted (CREATE POLICY),
// so a USING-only tenant-isolation policy still rejects cross-tenant INSERTs.
// originally reported the opposite; it was verified false against a real
// Postgres before this test was written. The value of stating both clauses is
// legibility — an auditor reading a policy should not have to know the fallback
// rule to know what it enforces.
var knownPoliciesWithoutWithCheck = map[string]string{}

// TestIntegration_RLS_EveryTenantPolicyHasWithCheck reads pg_policy directly and
// fails if any *_tenant_isolation policy lacks an explicit WITH CHECK. It exists
// because invitations and legal_acceptances sat USING-only among 131 otherwise
// uniform policies, and the inconsistency alone was enough to produce a
// confident, wrong security report that cost real review time.
//
// This asserts the property, not a count, so adding a correctly-formed table
// does not churn the test.
func TestIntegration_RLS_EveryTenantPolicyHasWithCheck(t *testing.T) {
	db := testdb.Connect(t)

	rows, err := db.Query(`
		SELECT n.nspname || '.' || c.relname AS tbl, p.polname
		FROM pg_policy p
		JOIN pg_class c ON c.oid = p.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE p.polname LIKE '%_tenant_isolation'
		  AND p.polwithcheck IS NULL
		ORDER BY 1`)
	if err != nil {
		t.Fatalf("query pg_policy: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var unexpected []string
	seen := map[string]bool{}
	for rows.Next() {
		var tbl, pol string
		if err := rows.Scan(&tbl, &pol); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[tbl] = true
		if _, ok := knownPoliciesWithoutWithCheck[tbl]; !ok {
			unexpected = append(unexpected, tbl+" ("+pol+")")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	if len(unexpected) > 0 {
		t.Fatalf("tenant-isolation policies with USING but no explicit WITH CHECK: %s\n"+
			"Postgres reuses USING as the new-row check, so this is a legibility gap, not an open write hole — "+
			"but every other policy states both clauses and an auditor should not have to know the fallback rule.\n"+
			"Add WITH CHECK in the RLS HARDENING block in scripts/database/schema.sql (or, for a table created "+
			"below that block, at its own definition), or add an entry to knownPoliciesWithoutWithCheck with a reason.",
			strings.Join(unexpected, ", "))
	}

	// Fail the other way too: an entry that no longer reproduces is a stale
	// exemption, and a stale exemption is how a real gap hides.
	for tbl, why := range knownPoliciesWithoutWithCheck {
		if !seen[tbl] {
			t.Errorf("%s is exempted (%s) but now HAS a WITH CHECK — remove it from knownPoliciesWithoutWithCheck", tbl, why)
		}
	}
}

// TestIntegration_RLS_InvitationsRejectsCrossTenantWrite pins the actual
// behaviour of the invitations table: same-tenant writes allowed, cross-tenant
// writes rejected, under the non-owner app role. On the owner connection RLS is
// bypassed entirely, so an owner-connection version of this test would pass
// against any schema at all.
//
// Deliberately NOT a proof that WITH CHECK specifically is present — it cannot
// be. Postgres falls back to USING for the new-row check, so this test passes
// with or without the explicit clause (confirmed by mutation). The explicit
// clause is enforced by TestIntegration_RLS_EveryTenantPolicyHasWithCheck
// reading pg_policy; this test guards the behaviour that actually matters.
func TestIntegration_RLS_InvitationsRejectsCrossTenantWrite(t *testing.T) {
	db := testdb.Connect(t)
	testdb.EnsureRLSAppRole(t, db)

	tA := testdb.NewTenant(t, db)
	tB := testdb.NewTenant(t, db)

	insert := `INSERT INTO public.invitations (tenant_id, email, role, token_hash, status, expires_at)
	           VALUES ($1, $2, 'viewer', $3, 'pending', now() + interval '7 days')`

	t.Run("same-tenant INSERT succeeds", func(t *testing.T) {
		testdb.AsTenant(t, db, tA, func(tx *sql.Tx) {
			if _, err := tx.Exec(insert, tA, "ok@example.com", "hash-same-"+tA.String()); err != nil {
				t.Fatalf("same-tenant INSERT denied unexpectedly: %v", err)
			}
		})
	})

	t.Run("cross-tenant INSERT blocked by WITH CHECK", func(t *testing.T) {
		testdb.AsTenant(t, db, tA, func(tx *sql.Tx) {
			_, err := tx.Exec(insert, tB, "evil@example.com", "hash-cross-"+tB.String())
			if err == nil {
				t.Fatal("cross-tenant INSERT into invitations succeeded — WITH CHECK is missing (#1297 regressed)")
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
