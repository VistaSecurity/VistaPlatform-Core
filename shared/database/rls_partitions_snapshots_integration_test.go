package database_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Two gaps the RLS coverage guard used to carry as named exemptions, closed:
//
//   - audit.activity_logs PARTITIONS. The parent's tenant policy covers every
//     query that names audit.activity_logs, but a query that names a partition
//     directly (`FROM audit.activity_logs_y2026m10`) consults only the
//     partition's own policies. With RLS off on the partitions, the blanket
//     audit-schema GRANT to crypto_app served every tenant's audit trail through
//     them. Each partition now has RLS ENABLED with no policy (default-deny), the
//     shape assets / sensor_discoveries / crypto_implementations partitions
//     already use, and create_activity_logs_partition() does the same to every
//     partition it creates at run time.
//
//   - public.alert_framework_score_snapshots, which had no RLS at all. Its
//     tenant isolation is proven by the generic probe (it is in
//     sensitiveTables); this file proves the platform path still works.

// TestIntegration_RLS_ActivityLogPartitionsDenyDirectAccess proves the
// partition-direct path is closed for crypto_app while the parent path and the
// BYPASSRLS platform path are unchanged.
func TestIntegration_RLS_ActivityLogPartitionsDenyDirectAccess(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	testdb.EnsureRLSAppRole(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	bypass := testdb.ConnectAsBypassRole(t, owner)

	// Catalogue first, because the behavioural check below can only see a leak
	// from the one partition the fixture rows land in. This holds for every
	// partition whether or not it holds anything.
	t.Run("every-partition-has-rls-enabled", func(t *testing.T) {
		rows, err := owner.Query(`
			SELECT i.inhrelid::regclass::text, c.relrowsecurity
			  FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
			 WHERE i.inhparent = 'audit.activity_logs'::regclass
			 ORDER BY 1`)
		if err != nil {
			t.Fatalf("list partitions: %v", err)
		}
		defer func() { _ = rows.Close() }()
		n := 0
		for rows.Next() {
			var part string
			var on bool
			if err := rows.Scan(&part, &on); err != nil {
				t.Fatalf("scan: %v", err)
			}
			n++
			if !on {
				t.Errorf("%s has RLS DISABLED: a query naming the partition directly bypasses the "+
					"parent's activity_logs_tenant_isolation policy, and crypto_app holds SELECT on it", part)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("audit.activity_logs has no partitions — the enumeration is broken, not the schema")
		}
	})

	// A partition created at RUN TIME (audit-service's PartitionManager and
	// ensure_future_partitions both go through this function) must come out
	// with RLS on, or the hole reopens a month after install. Inside a rolled-
	// back transaction so no test leaves a partition behind.
	t.Run("runtime-created-partition-has-rls-enabled", func(t *testing.T) {
		tx, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		var name sql.NullString
		if err := tx.QueryRow(`SELECT audit.create_activity_logs_partition(2099, 7)`).Scan(&name); err != nil {
			t.Fatalf("create_activity_logs_partition: %v", err)
		}
		if !name.Valid {
			t.Fatal("audit.activity_logs_y2099m07 already exists — the test cannot observe a fresh creation")
		}
		var on bool
		if err := tx.QueryRow(`SELECT relrowsecurity FROM pg_class WHERE oid = ('audit.' || quote_ident($1))::regclass`,
			name.String).Scan(&on); err != nil {
			t.Fatalf("read relrowsecurity: %v", err)
		}
		if !on {
			t.Errorf("create_activity_logs_partition made %s with RLS DISABLED — every partition "+
				"created after install is readable across tenants by naming it", name.String)
		}
	})

	tA := testdb.NewTenant(t, owner)
	tB := testdb.NewTenant(t, owner)
	rowA, rowB := uuid.New(), uuid.New()
	for _, r := range []struct {
		id, tenant uuid.UUID
	}{{rowA, tA}, {rowB, tB}} {
		if _, err := owner.Exec(`
			INSERT INTO audit.activity_logs (id, tenant_id, user_type, event_type, event_category, action, occurred_at)
			VALUES ($1, $2, 'tenant', 'rls.partition_probe', 'system', 'probe', now())`, r.id, r.tenant); err != nil {
			t.Fatalf("seed activity_logs: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(`DELETE FROM audit.activity_logs WHERE id IN ($1, $2)`, rowA, rowB)
	})

	// The partition both rows landed in (same occurred_at month).
	var part string
	if err := owner.QueryRow(`SELECT tableoid::regclass::text FROM audit.activity_logs WHERE id = $1`, rowA).Scan(&part); err != nil {
		t.Fatalf("locate partition: %v", err)
	}
	if part == "audit.activity_logs" || !strings.HasPrefix(part, "audit.activity_logs_") {
		t.Fatalf("row landed in %q, not a partition — the probe proves nothing", part)
	}

	ctx := context.Background()
	ids := []any{rowA, rowB}

	t.Run("parent-path-still-isolates-and-serves-own-rows", func(t *testing.T) {
		err := database.WithTenantTx(ctx, app, tA, func(tx *sql.Tx) error {
			var mine, theirs int
			if err := tx.QueryRow(`SELECT count(*) FROM audit.activity_logs WHERE id = $1`, rowA).Scan(&mine); err != nil {
				return err
			}
			if err := tx.QueryRow(`SELECT count(*) FROM audit.activity_logs WHERE id = $1`, rowB).Scan(&theirs); err != nil {
				return err
			}
			if mine != 1 {
				t.Errorf("tenant A reads %d of its own rows through the parent, want 1 — partition RLS must not touch the parent path", mine)
			}
			if theirs != 0 {
				t.Errorf("tenant A reads tenant B's row through the parent")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("parent read: %v", err)
		}
	})

	t.Run("partition-is-not-a-back-door", func(t *testing.T) {
		err := database.WithTenantTx(ctx, app, tA, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE id IN ($1, $2)`, part), ids...).Scan(&n); err != nil {
				return fmt.Errorf("partition read: %w", err)
			}
			if n != 0 {
				t.Errorf("%s returned %d row(s) to tenant A's session (tenant B's included) — "+
					"the partition needs ENABLE ROW LEVEL SECURITY of its own", part, n)
			}
			res, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET action = action WHERE id IN ($1, $2)`, part), ids...)
			if err != nil {
				return fmt.Errorf("partition update: %w", err)
			}
			if k, _ := res.RowsAffected(); k != 0 {
				t.Errorf("tenant A UPDATEd %d row(s) through %s", k, part)
			}
			res, err = tx.Exec(fmt.Sprintf(`DELETE FROM %s WHERE id IN ($1, $2)`, part), ids...)
			if err != nil {
				return fmt.Errorf("partition delete: %w", err)
			}
			if k, _ := res.RowsAffected(); k != 0 {
				t.Errorf("tenant A DELETEd %d row(s) through %s", k, part)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("partition-direct as tenant A: %v", err)
		}

		// A row written straight into the partition, even one for the
		// session's OWN tenant, is refused: no policy means default-deny.
		expectRLSDenied(t, app, tA, "inserting directly into "+part,
			fmt.Sprintf(`INSERT INTO %s (tenant_id, user_type, event_type, event_category, action, occurred_at)
			             VALUES ($1, 'tenant', 'rls.partition_probe', 'system', 'probe', now())`, part), tA)

		testdb.AsRoleNoTenant(t, owner, func(tx *sql.Tx) {
			var n int
			if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE id IN ($1, $2)`, part), ids...).Scan(&n); err != nil {
				t.Fatalf("no-context partition read: %v", err)
			}
			if n != 0 {
				t.Errorf("with no app.tenant_id, %s returned %d rows, want 0", part, n)
			}
		})
	})

	// The platform path — the BYPASSRLS handle audit-service's retention sweep
	// and admin-service's security views run on — still sees every tenant.
	t.Run("bypass-role-sees-all-tenants", func(t *testing.T) {
		var viaParent, viaPart int
		if err := bypass.QueryRow(`SELECT count(*) FROM audit.activity_logs WHERE id IN ($1, $2)`, ids...).Scan(&viaParent); err != nil {
			t.Fatalf("bypass parent read: %v", err)
		}
		if err := bypass.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE id IN ($1, $2)`, part), ids...).Scan(&viaPart); err != nil {
			t.Fatalf("bypass partition read: %v", err)
		}
		if viaParent != 2 || viaPart != 2 {
			t.Errorf("bypass role reads parent=%d partition=%d, want 2 and 2", viaParent, viaPart)
		}
	})

	// B's row survived tenant A's attempts.
	var survivors int
	if err := owner.QueryRow(`SELECT count(*) FROM audit.activity_logs WHERE id = $1`, rowB).Scan(&survivors); err != nil {
		t.Fatal(err)
	}
	if survivors != 1 {
		t.Errorf("tenant B's row is gone after tenant A's partition-direct attempts")
	}
}

// TestIntegration_RLS_ScoreSnapshotsPlatformPath: with RLS on, the BYPASSRLS
// handle still sees every tenant's snapshot trail (tenant isolation itself is
// the generic probe's job — the table is in sensitiveTables), and a tenant-
// scoped session on crypto_app can write and read back its own row, which is
// the path compliance-engine's score-drop job now takes.
func TestIntegration_RLS_ScoreSnapshotsPlatformPath(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	testdb.EnsureRLSAppRole(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	bypass := testdb.ConnectAsBypassRole(t, owner)

	tA := testdb.NewTenant(t, owner)
	tB := testdb.NewTenant(t, owner)
	fw := uuid.New() // no FK on platform_framework_id

	ctx := context.Background()
	for _, tenant := range []uuid.UUID{tA, tB} {
		if err := database.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
			_, err := tx.Exec(`INSERT INTO alert_framework_score_snapshots (tenant_id, platform_framework_id, score)
			                   VALUES ($1, $2, 70)`, tenant, fw)
			return err
		}); err != nil {
			t.Fatalf("tenant-scoped snapshot insert as crypto_app: %v", err)
		}
	}

	var own int
	if err := database.WithTenantTx(ctx, app, tA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM alert_framework_score_snapshots WHERE platform_framework_id = $1`, fw).Scan(&own)
	}); err != nil {
		t.Fatal(err)
	}
	if own != 1 {
		t.Errorf("tenant A sees %d snapshot rows for the framework, want exactly its own 1", own)
	}

	var all int
	if err := bypass.QueryRow(`SELECT count(*) FROM alert_framework_score_snapshots WHERE platform_framework_id = $1`, fw).Scan(&all); err != nil {
		t.Fatalf("bypass read: %v", err)
	}
	if all != 2 {
		t.Errorf("bypass role sees %d snapshot rows, want 2 (both tenants)", all)
	}
}
