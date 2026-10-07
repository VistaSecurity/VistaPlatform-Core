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

// Live RLS verification for the tables whose cross-tenant exposure would hurt
// most (credentials, identities, audit trail, inventory, findings, tickets).
//
// Unlike TestIntegration_RLS_Enforcement (one probe table, `SET LOCAL ROLE`),
// this opens a REAL login as crypto_app — the role every backend's DATABASE_URL
// points at in the chart (serviceRls.enabled, the default) — and drives the same
// shared/database.WithTenantTx the services use. For each table it proves, with
// app.tenant_id = A and a row seeded for each of A and B:
//
//   - B's row is invisible (filtered and unfiltered reads),
//   - B's row cannot be updated or deleted (0 rows affected, no error),
//   - A's row cannot be re-pointed at B (UPDATE ... SET tenant_id = B),
//   - a row carrying B's tenant_id cannot be INSERTed (WITH CHECK),
//   - with no tenant context the table reads as empty, and
//   - B's row is still intact afterwards (read through the owner).
//
// It also pins the posture the whole defence rests on: crypto_app is not a
// superuser, does not BYPASSRLS, and owns no tenant table (an owner bypasses RLS
// unless FORCE is set, and nothing sets FORCE).

// sensitiveTables are the probed tables. Add to this list rather than loosening
// a check; a table that cannot be seeded generically belongs in its own test.
var sensitiveTables = []string{
	"public.users",
	"public.api_tokens",
	"public.sso_providers",
	"public.invitations",
	"public.integrations",
	"public.asset_credentials",
	"public.tenant_admin_settings",
	"public.tickets",
	"public.findings",
	"public.alerts",
	"public.assets",
	"public.certificates",
	"public.keys",
	"public.sensors",
	"public.billing_subscriptions",
	"audit.activity_logs",
	"public.alert_framework_score_snapshots",
}

// textOverrides gives a column a value its CHECK constraint accepts where the
// generic filler's choice is rejected. Keyed "table.column".
var textOverrides = map[string]string{
	"public.users.email":                     "rls-probe-%s@example.invalid",
	"public.invitations.email":               "rls-probe-%s@example.invalid",
	"public.invitations.token_hash":          "%s",
	"public.api_tokens.token_hash":           "%s",
	"public.api_tokens.token_prefix":         "qvpat_rls",
	"public.sso_providers.provider_type":     "okta",
	"public.findings.severity":               "low",
	"public.alerts.severity":                 "info",
	"public.certificates.fingerprint_sha256": "%s%s",
	"audit.activity_logs.user_type":          "tenant",
	"audit.activity_logs.event_category":     "system",
}

func TestIntegration_RLS_AppRolePosture(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.EnsureRLSAppRole(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	var user string
	var super, bypass bool
	if err := app.QueryRow(`SELECT current_user, r.rolsuper, r.rolbypassrls
		FROM pg_roles r WHERE r.rolname = current_user`).Scan(&user, &super, &bypass); err != nil {
		t.Fatalf("read role flags: %v", err)
	}
	if user != testdb.RLSAppRole {
		t.Fatalf("connected as %q, want %q", user, testdb.RLSAppRole)
	}
	if super || bypass {
		t.Fatalf("%s has rolsuper=%v rolbypassrls=%v — RLS is NOT enforced for the role services use", user, super, bypass)
	}

	// An owner bypasses RLS unless FORCE is set. The app role must own nothing.
	rows, err := app.Query(`SELECT n.nspname || '.' || c.relname
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r','p') AND n.nspname IN ('public','audit')
		  AND pg_get_userbyid(c.relowner) = current_user`)
	if err != nil {
		t.Fatalf("list owned tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		t.Errorf("%s owns %s — the owner bypasses RLS unless FORCE ROW LEVEL SECURITY is set", user, name)
	}
}

func TestIntegration_RLS_SensitiveTablesIsolateTenants(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	testdb.EnsureRLSAppRole(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	tA := testdb.NewTenant(t, owner)
	tB := testdb.NewTenant(t, owner)

	for _, table := range sensitiveTables {
		table := table
		t.Run(table, func(t *testing.T) {
			if !rlsEnabled(t, owner, table) {
				t.Fatalf("%s has no RLS enabled", table)
			}
			insertA, argsA := probeInsert(t, owner, table, tA)
			insertB, argsB := probeInsert(t, owner, table, tB)
			seedWithoutFKs(t, owner, table, tA, tB, insertA, argsA, insertB, argsB)

			ctx := context.Background()

			// Reads: nothing of B's is visible, and everything visible is A's.
			err := database.WithTenantTx(ctx, app, tA, func(tx *sql.Tx) error {
				var other, total int
				if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, table), tB).Scan(&other); err != nil {
					return fmt.Errorf("filtered read: %w", err)
				}
				if other != 0 {
					t.Errorf("tenant A reads %d of tenant B's rows with an explicit filter", other)
				}
				if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id <> $1`, table), tA).Scan(&other); err != nil {
					return fmt.Errorf("unfiltered read: %w", err)
				}
				if other != 0 {
					t.Errorf("an UNFILTERED read as tenant A returned %d rows belonging to other tenants", other)
				}
				if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, table), tA).Scan(&total); err != nil {
					return err
				}
				if total == 0 {
					t.Errorf("tenant A cannot see its OWN row — the probe proves nothing")
				}
				return nil
			})
			if err != nil {
				t.Fatalf("tenant A reads: %v", err)
			}

			// Writes: B's rows cannot be touched, A's cannot be handed to B.
			err = database.WithTenantTx(ctx, app, tA, func(tx *sql.Tx) error {
				res, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET tenant_id = tenant_id WHERE tenant_id = $1`, table), tB)
				if err != nil {
					return fmt.Errorf("update B's rows: %w", err)
				}
				if n, _ := res.RowsAffected(); n != 0 {
					t.Errorf("tenant A UPDATEd %d of tenant B's rows", n)
				}
				res, err = tx.Exec(fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = $1`, table), tB)
				if err != nil {
					return fmt.Errorf("delete B's rows: %w", err)
				}
				if n, _ := res.RowsAffected(); n != 0 {
					t.Errorf("tenant A DELETEd %d of tenant B's rows", n)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("tenant A cross-tenant writes: %v", err)
			}

			expectRLSDenied(t, app, tA, "re-pointing A's row at B",
				fmt.Sprintf(`UPDATE %s SET tenant_id = $1 WHERE tenant_id = $2`, table), tB, tA)

			// A row carrying B's tenant_id. Fresh values so no unique key collides
			// before the policy is consulted.
			insB2, argsB2 := probeInsert(t, owner, table, tB)
			expectRLSDenied(t, app, tA, "inserting a row for B", insB2, argsB2...)

			// No tenant context: fail closed.
			testdb.AsRoleNoTenant(t, owner, func(tx *sql.Tx) {
				var n int
				if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s`, table)).Scan(&n); err != nil {
					t.Fatalf("no-context read: %v", err)
				}
				if n != 0 {
					t.Errorf("with no app.tenant_id the table returned %d rows, want 0", n)
				}
			})

			// B's row survived all of it (read through the owner).
			var survivors int
			if err := owner.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, table), tB).Scan(&survivors); err != nil {
				t.Fatalf("owner read of B: %v", err)
			}
			if survivors == 0 {
				t.Errorf("tenant B's row is gone after tenant A's attempts to delete it")
			}
		})
	}
}

// expectRLSDenied runs stmt as tenant `as` and requires a row-level-security
// violation (not merely "some error", which a malformed probe would also give).
func expectRLSDenied(t *testing.T, app *sql.DB, as uuid.UUID, what, stmt string, args ...any) {
	t.Helper()
	err := database.WithTenantTx(context.Background(), app, as, func(tx *sql.Tx) error {
		_, e := tx.Exec(stmt, args...)
		return e
	})
	if err == nil {
		t.Errorf("%s succeeded — WITH CHECK is missing or not enforced", what)
		return
	}
	if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
		t.Errorf("%s failed, but not on row-level security (probe malformed?): %v", what, err)
	}
}

func rlsEnabled(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var on bool
	if err := db.QueryRow(`SELECT relrowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&on); err != nil {
		t.Fatalf("relrowsecurity(%s): %v", table, err)
	}
	return on
}

type probeColumn struct {
	name, typ, kind string
	enumFirst       sql.NullString
}

// probeInsert builds an INSERT that supplies only the columns the table cannot
// default, with a value of the right type for each, tenant_id = tenant.
func probeInsert(t *testing.T, db *sql.DB, table string, tenant uuid.UUID) (string, []any) {
	t.Helper()
	rows, err := db.Query(`
		SELECT a.attname, format_type(a.atttypid, a.atttypmod), ty.typtype,
		       (SELECT e.enumlabel FROM pg_enum e WHERE e.enumtypid = a.atttypid ORDER BY e.enumsortorder LIMIT 1)
		  FROM pg_attribute a JOIN pg_type ty ON ty.oid = a.atttypid
		 WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
		   AND a.attnotnull AND NOT a.atthasdef AND a.attgenerated = '' AND a.attidentity = ''
		 ORDER BY a.attnum`, table)
	if err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	var cols []string
	var vals []string
	var args []any
	hasTenant := false
	salt := strings.ReplaceAll(uuid.NewString(), "-", "")
	for rows.Next() {
		var c probeColumn
		if err := rows.Scan(&c.name, &c.typ, &c.kind, &c.enumFirst); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		cols = append(cols, c.name)
		if c.name == "tenant_id" {
			hasTenant = true
			args = append(args, tenant)
			vals = append(vals, fmt.Sprintf("$%d", len(args)))
			continue
		}
		vals = append(vals, fillerFor(table, c, salt))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}
	if !hasTenant {
		// tenant_id has a default (or is nullable) — name it explicitly.
		cols = append(cols, "tenant_id")
		args = append(args, tenant)
		vals = append(vals, fmt.Sprintf("$%d", len(args)))
	}
	return fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, table, strings.Join(cols, ", "), strings.Join(vals, ", ")), args
}

func fillerFor(table string, c probeColumn, salt string) string {
	if o, ok := textOverrides[table+"."+c.name]; ok {
		if n := strings.Count(o, "%s"); n == 2 {
			o = fmt.Sprintf(o, salt, salt) // 64 hex characters
		} else if n == 1 {
			o = fmt.Sprintf(o, salt)
		}
		return "'" + o + "'"
	}
	if c.enumFirst.Valid {
		return "'" + c.enumFirst.String + "'"
	}
	typ := strings.ToLower(c.typ)
	switch {
	case strings.HasSuffix(typ, "[]"):
		return "'{}'"
	case typ == "uuid":
		return "gen_random_uuid()"
	case strings.HasPrefix(typ, "timestamp"):
		return "now()"
	case typ == "date":
		return "current_date"
	case typ == "boolean":
		return "false"
	case strings.HasPrefix(typ, "integer"), strings.HasPrefix(typ, "bigint"), strings.HasPrefix(typ, "smallint"),
		strings.HasPrefix(typ, "numeric"), strings.HasPrefix(typ, "double"), strings.HasPrefix(typ, "real"):
		return "1"
	case typ == "jsonb" || typ == "json":
		return "'{}'"
	case typ == "inet":
		return "'10.9.8.7'"
	case typ == "cidr":
		return "'10.9.8.0/24'"
	case typ == "bytea":
		return `'\x00'`
	case strings.HasPrefix(typ, "interval"):
		return "'1 hour'"
	default:
		// Short: some columns are varchar(20).
		return "'rls-" + salt[:12] + "'"
	}
}

// seedWithoutFKs inserts one probe row per tenant as the owner with foreign-key
// triggers off (session_replication_role = replica), so the probe does not need
// a parent row in every referenced table. RLS is irrelevant to this connection
// (owner); what is under test is how crypto_app sees the rows afterwards. The
// rows are removed again before the tenants are.
func seedWithoutFKs(t *testing.T, owner *sql.DB, table string, tA, tB uuid.UUID, insA string, argsA []any, insB string, argsB []any) {
	t.Helper()
	ctx := context.Background()
	conn, err := owner.Conn(ctx)
	if err != nil {
		t.Fatalf("owner conn: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Skipf("cannot disable FK triggers for the probe (needs a superuser connection): %v", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SET session_replication_role = DEFAULT`) }()
	if _, err := conn.ExecContext(ctx, insA, argsA...); err != nil {
		t.Fatalf("seed %s for A: %v\n%s", table, err, insA)
	}
	if _, err := conn.ExecContext(ctx, insB, argsB...); err != nil {
		t.Fatalf("seed %s for B: %v\n%s", table, err, insB)
	}
	t.Cleanup(func() {
		c, err := owner.Conn(ctx)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.ExecContext(ctx, `SET session_replication_role = replica`)
		_, _ = c.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE tenant_id IN ($1, $2)`, table), tA, tB)
		_, _ = c.ExecContext(ctx, `SET session_replication_role = DEFAULT`)
	})
}

// rlsCoverageExemptions names every tenant-bearing table that is NOT protected
// by an RLS policy of its own, with the reason. The map is checked in BOTH
// directions: an unprotected table missing here fails (the 2026-09 audit found
// alert_framework_score_snapshots had slipped through with nothing to catch
// it), and an entry that no longer matches an unprotected table fails too, so
// an exemption cannot outlive its cause. Keys are "schema.table", or
// "partitions-of:schema.parent" for every partition of a partitioned table.
//
// Entries marked OPEN are known gaps recorded rather than hidden; closing one
// means deleting its line here AND fixing schema.sql in the same change.
var rlsCoverageExemptions = map[string]string{
	"public.license_usage_daily":  "platform-owned licence usage ledger; written and read by operator-side code (admin-service licensing/billing), no tenant-facing reader",
	"public.license_usage_events": "platform-owned licence usage ledger; written and read by operator-side code (admin-service licensing/billing), no tenant-facing reader",
}

// defaultDenyParents are partitioned tables whose partitions deliberately have
// RLS enabled and NO policy (default-deny when a partition is named directly),
// per the hardening block in schema.sql.
var defaultDenyParents = map[string]bool{
	"public.assets":                             true,
	"public.asset_endpoints":                    true,
	"public.crypto_implementations_partitioned": true,
	"public.sensor_discoveries_partitioned":     true,
	// Partitions are created at run time too (create_activity_logs_partition,
	// which enables RLS on each one it makes); TestIntegration_RLS_ActivityLogPartitionsDenyDirectAccess
	// drives a freshly created one.
	"audit.activity_logs": true,
}

// TestIntegration_RLS_EveryTenantTableIsProtected fails when a table carrying a
// tenant_id column has RLS disabled or no policy, unless it is a named,
// justified exemption. Closes the audit gap "no guard asserts every
// tenant-scoped table has RLS" (2026-09 tenancy-rbac Medium).
func TestIntegration_RLS_EveryTenantTableIsProtected(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	rows, err := db.Query(`
		SELECT n.nspname || '.' || c.relname,
		       c.relrowsecurity,
		       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid),
		       COALESCE((SELECT pn.nspname || '.' || pc.relname
		                   FROM pg_inherits i
		                   JOIN pg_class pc ON pc.oid = i.inhparent
		                   JOIN pg_namespace pn ON pn.oid = pc.relnamespace
		                  WHERE i.inhrelid = c.oid AND pc.relkind IN ('r','p')), '')
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relkind IN ('r','p') AND n.nspname IN ('public','audit')
		   AND EXISTS (SELECT 1 FROM pg_attribute a
		                WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
		 ORDER BY 1`)
	if err != nil {
		t.Fatalf("enumerate tenant tables: %v", err)
	}
	defer func() { _ = rows.Close() }()

	used := map[string]bool{}
	checked := 0
	for rows.Next() {
		var name, parent string
		var rls bool
		var policies int
		if err := rows.Scan(&name, &rls, &policies, &parent); err != nil {
			t.Fatalf("scan: %v", err)
		}
		checked++
		if rls && policies > 0 {
			continue
		}
		if parent != "" && rls && policies == 0 && defaultDenyParents[parent] {
			continue // deliberate default-deny partition
		}
		key := name
		if parent != "" {
			key = "partitions-of:" + parent
		}
		if _, ok := rlsCoverageExemptions[key]; ok {
			used[key] = true
			continue
		}
		t.Errorf("%s carries tenant_id but is not protected (rls=%v policies=%d) and is not a listed exemption — "+
			"add ENABLE ROW LEVEL SECURITY and a tenant_isolation policy in schema.sql, or justify it in rlsCoverageExemptions", name, rls, policies)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if checked < 100 {
		t.Fatalf("only %d tenant tables found — the enumeration is broken, not the schema", checked)
	}
	for key := range rlsCoverageExemptions {
		if !used[key] {
			t.Errorf("stale exemption %q: no such unprotected table any more — delete it", key)
		}
	}
}
