package testdb_test

// Purging a tenant is one statement — `DELETE FROM tenants WHERE id = $1`
// (admin-service PurgeTenant, qa-platform DeleteTenant) — so every table that
// holds a tenant's rows must be reachable from `tenants` through ON DELETE
// CASCADE / SET NULL. Fourteen tenant-scoped tables were not, and a purged
// tenant's alerts (some still `active`), scopes, CBOM artifacts, invitations,
// saved views, entitlement overrides, audit rows and terms/privacy acceptances
// outlived it.
//
// Two tests, both written from the catalog so a FUTURE table is covered without
// anyone remembering to add it here:
//
//   - TestIntegration_TenantPurge_EveryTenantTableCascades proves, structurally,
//     that every table with a tenant_id column is reachable from tenants by a
//     cascade chain. A new table created without one fails it.
//   - TestIntegration_TenantPurge_LeavesNoTenantRows writes rows for one tenant
//     into the tables this fix covers, purges the tenant, and then scans EVERY
//     table with a tenant_id column for a surviving row.
//
// Mutation test: `ALTER TABLE scopes DROP CONSTRAINT scopes_tenant_id_fkey` on
// the test database and both tests fail naming public.scopes; restore with a
// schema re-apply and both pass. The same holds for
// legal_acceptances_tenant_id_fkey, naming public.legal_acceptances.

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// purgeRetainedTables are tenant-scoped tables a purge deliberately does NOT
// empty. Each needs a reason; adding a table here is a product decision, not a
// way to make this test pass.
var purgeRetainedTables = map[string]string{
	// The MSP metering ledger keeps no FK on purpose: a purged tenant must
	// still be reported for the month in which it existed (schema.sql,
	// "LICENSING: MSP usage metering").
	"public.license_usage_events": "MSP usage ledger outlives the tenant by design",
	"public.license_usage_daily":  "MSP usage ledger outlives the tenant by design",
	// Not listed, by owner decision: legal_acceptances is purged with its
	// tenant (single-person DSR erasure still retains a person's acceptances;
	// that path deletes no tenant), and api_usage_logs no longer exists.
}

// platformAlertSentinel mirrors events.PlatformAlertTenantID. Platform-track
// alerts are raised under it and it has no tenants row, by design.
const platformAlertSentinel = "11111111-1111-1111-1111-111111111111"

// tenantScopedTables lists every ordinary or partitioned table (not a
// partition) that has a tenant_id column, schema-qualified.
func tenantScopedTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT n.nspname || '.' || c.relname
		  FROM pg_attribute a
		  JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE a.attname = 'tenant_id' AND NOT a.attisdropped
		   AND c.relkind IN ('r', 'p') AND NOT c.relispartition
		   AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'testdb_meta')
		 ORDER BY 1`)
	if err != nil {
		t.Fatalf("list tenant-scoped tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(out) < 50 {
		// A guard against the query silently matching nothing (a renamed
		// schema, a catalog filter gone wrong): this schema has well over a
		// hundred such tables.
		t.Fatalf("found only %d tenant-scoped tables — the catalog query is wrong", len(out))
	}
	return out
}

func TestIntegration_TenantPurge_EveryTenantTableCascades(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	// A table is covered when deleting a tenant reaches its rows:
	//   * an FK straight to tenants with ON DELETE CASCADE or SET NULL
	//     (SET NULL on a nullable tenant_id is the audit-log precedent:
	//     audit.activity_logs keeps the record, detached from the tenant); or
	//   * an ON DELETE CASCADE FK to a covered table whose referencing columns
	//     are all NOT NULL — a nullable one would let a row with no parent
	//     escape the chain.
	// Iterated to a fixpoint, so chains of any depth are found.
	rows, err := db.Query(`
		WITH RECURSIVE covered(relid) AS (
		    SELECT k.conrelid
		      FROM pg_constraint k
		     WHERE k.contype = 'f' AND k.confrelid = 'public.tenants'::regclass
		       AND k.confdeltype IN ('c', 'n')
		  UNION
		    SELECT k.conrelid
		      FROM pg_constraint k
		      JOIN covered p ON p.relid = k.confrelid
		     WHERE k.contype = 'f' AND k.confdeltype = 'c'
		       AND NOT EXISTS (
		             SELECT 1 FROM unnest(k.conkey) col(attnum)
		               JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = col.attnum
		              WHERE NOT a.attnotnull)
		)
		SELECT n.nspname || '.' || c.relname
		  FROM covered JOIN pg_class c ON c.oid = covered.relid
		  JOIN pg_namespace n ON n.oid = c.relnamespace`)
	if err != nil {
		t.Fatalf("compute cascade coverage: %v", err)
	}
	coveredSet := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		coveredSet[name] = true
	}
	_ = rows.Close()

	var uncovered []string
	for _, tbl := range tenantScopedTables(t, db) {
		if coveredSet[tbl] {
			if _, listed := purgeRetainedTables[tbl]; listed {
				t.Errorf("%s now cascades from tenants but is still in purgeRetainedTables — remove it", tbl)
			}
			continue
		}
		if _, listed := purgeRetainedTables[tbl]; listed {
			continue
		}
		uncovered = append(uncovered, tbl)
	}
	if len(uncovered) > 0 {
		t.Fatalf("tenant-scoped tables with no ON DELETE CASCADE/SET NULL path from tenants — "+
			"a purged tenant's rows would survive in them. Add an FK (see schema.sql POST-MIGRATIONS "+
			"\"tenant-scoped tables cascade from tenants\") or, if retention is intended, an entry "+
			"with a reason in purgeRetainedTables:\n  %s", strings.Join(uncovered, "\n  "))
	}
}

func TestIntegration_TenantPurge_LeavesNoTenantRows(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenant := testdb.NewTenant(t, db)
	// A second, surviving tenant: the purge must remove exactly the purged
	// tenant's legal acceptances and none of anyone else's.
	otherTenant, otherUserID := testdb.NewTenant(t, db), uuid.New()
	alertID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	platformAlertID := uuid.New()
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM alerts WHERE id = $1`, platformAlertID)
	})

	// One row per table this fix gave a cascade, plus a platform-track alert
	// (with an event) under the sentinel, which the purge must NOT touch.
	fixtures := []struct {
		table string
		sql   string
		args  []interface{}
	}{
		{"alerts", `INSERT INTO alerts (id, tenant_id, alert_type, source, severity, title) VALUES ($1, $2, 'certificate_expiring', 'it', 'high', 'it')`, []interface{}{alertID, tenant}},
		{"alert_events", `INSERT INTO alert_events (alert_id, tenant_id, event_type) VALUES ($1, $2, 'opened')`, []interface{}{alertID, tenant}},
		{"alerts (platform)", `INSERT INTO alerts (id, tenant_id, alert_type, source, severity, title) VALUES ($1, $2, 'it_platform_probe', 'it', 'low', 'it')`, []interface{}{platformAlertID, platformAlertSentinel}},
		{"alert_events (platform)", `INSERT INTO alert_events (alert_id, tenant_id, event_type) VALUES ($1, $2, 'opened')`, []interface{}{platformAlertID, platformAlertSentinel}},
		{"agent_config_audit", `INSERT INTO agent_config_audit (tenant_id, scope, runtime) VALUES ($1, 'fleet', 'sensor')`, []interface{}{tenant}},
		{"alert_framework_score_snapshots", `INSERT INTO alert_framework_score_snapshots (tenant_id, platform_framework_id, score) VALUES ($1, $2, 50)`, []interface{}{tenant, uuid.New()}},
		{"tenant_alert_settings", `INSERT INTO tenant_alert_settings (tenant_id, alert_type) VALUES ($1, 'certificate_expiring')`, []interface{}{tenant}},
		{"scopes", `INSERT INTO scopes (id, tenant_id, name, created_by, updated_by) VALUES ($1, $2, 'it', $3, $3)`, []interface{}{scopeID, tenant, userID}},
		{"scopes_audit", `INSERT INTO scopes_audit (scope_id, tenant_id, name_before, name_after, query_before, query_after, version_before, version_after) VALUES ($1, $2, 'a', 'b', '', '', 1, 2)`, []interface{}{scopeID, tenant}},
		{"cbom_artifacts", `INSERT INTO cbom_artifacts (tenant_id, scope_id, scope_version, scope_name_snapshot, inline_content, content_hash, size_bytes, component_count, input_data_freshness_at, generated_by) VALUES ($1, $2, 1, 'it', '{}', repeat('0', 64), 2, 0, now(), $3)`, []interface{}{tenant, scopeID, userID}},
		{"cbom_subscriptions", `INSERT INTO cbom_subscriptions (tenant_id, scope_id, name, schedule_cron, delivery, created_by) VALUES ($1, $2, 'it', '0 6 * * MON', '{}', $3)`, []interface{}{tenant, scopeID, userID}},
		{"invitations", `INSERT INTO invitations (tenant_id, email, role, token_hash, expires_at) VALUES ($1, $2, 'viewer', $3, now() + interval '1 day')`, []interface{}{tenant, "it-" + tenant.String()[:8] + "@example.com", strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")[:64]}},
		{"saved_views", `INSERT INTO saved_views (tenant_id, name, owner_user_id) VALUES ($1, 'it', $2)`, []interface{}{tenant, userID}},
		{"tenant_entitlements", `INSERT INTO tenant_entitlements (tenant_id, item_id) SELECT $1, id FROM billable_items ORDER BY key LIMIT 1`, []interface{}{tenant}},
		{"tenant_geographic_data", `INSERT INTO tenant_geographic_data (tenant_id) VALUES ($1)`, []interface{}{tenant}},
		{"notification_digest_queue", `INSERT INTO notification_digest_queue (tenant_id, channel_id, channel_type, alert_source, alert_type, severity, message, flush_after) VALUES ($1, $2, 'email', 'it', 'it', 'low', 'it', now())`, []interface{}{tenant, uuid.New()}},
		{"legal_acceptances", `INSERT INTO legal_acceptances (tenant_id, user_id, doc_type, document_id, version, content_hash) VALUES ($1, $2, 'terms_of_service', $3, 1, repeat('0', 64))`, []interface{}{tenant, userID, uuid.New()}},
		{"legal_acceptances (other tenant)", `INSERT INTO legal_acceptances (tenant_id, user_id, doc_type, document_id, version, content_hash) VALUES ($1, $2, 'terms_of_service', $3, 1, repeat('0', 64))`, []interface{}{otherTenant, otherUserID, uuid.New()}},
	}
	for _, f := range fixtures {
		res, err := db.Exec(f.sql, f.args...)
		if err != nil {
			t.Fatalf("seed %s: %v", f.table, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("seed %s: inserted %d rows, want 1", f.table, n)
		}
	}

	// A row for a tenant that does not exist is refused: the cascade is a real
	// FK, not a cleanup that orphans can slip past.
	if _, err := db.Exec(`INSERT INTO scopes (tenant_id, name, created_by, updated_by) VALUES ($1, 'it', $2, $2)`,
		uuid.New(), userID); err == nil || !strings.Contains(err.Error(), "scopes_tenant_id_fkey") {
		t.Fatalf("insert for a nonexistent tenant: got err=%v, want a scopes_tenant_id_fkey violation", err)
	}
	if _, err := db.Exec(`INSERT INTO legal_acceptances (tenant_id, user_id, doc_type, document_id, version, content_hash) VALUES ($1, $2, 'terms_of_service', $3, 1, repeat('0', 64))`,
		uuid.New(), uuid.New(), uuid.New()); err == nil || !strings.Contains(err.Error(), "legal_acceptances_tenant_id_fkey") {
		t.Fatalf("legal acceptance for a nonexistent tenant: got err=%v, want a legal_acceptances_tenant_id_fkey violation", err)
	}

	if _, err := db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant); err != nil {
		t.Fatalf("purge tenant: %v", err)
	}

	survivors := map[string]int{}
	for _, tbl := range tenantScopedTables(t, db) {
		if _, retained := purgeRetainedTables[tbl]; retained {
			continue
		}
		var n int
		if err := db.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, tbl), tenant).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if n > 0 {
			survivors[tbl] = n
		}
	}
	if len(survivors) > 0 {
		var lines []string
		for tbl, n := range survivors {
			lines = append(lines, fmt.Sprintf("%s: %d row(s)", tbl, n))
		}
		sort.Strings(lines)
		t.Fatalf("purged tenant still has rows in:\n  %s", strings.Join(lines, "\n  "))
	}

	// The platform-track alert and its event are not the purged tenant's and
	// must survive.
	var platformRows int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM alerts WHERE id = $1) + (SELECT count(*) FROM alert_events WHERE alert_id = $1)`,
		platformAlertID).Scan(&platformRows); err != nil {
		t.Fatalf("count platform alert: %v", err)
	}
	if platformRows != 2 {
		t.Fatalf("platform-track alert + event: %d rows after the purge, want 2", platformRows)
	}

	// The other tenant's acceptance is not the purged tenant's and must survive.
	var otherAcceptances int
	if err := db.QueryRow(`SELECT count(*) FROM legal_acceptances WHERE tenant_id = $1 AND user_id = $2`,
		otherTenant, otherUserID).Scan(&otherAcceptances); err != nil {
		t.Fatalf("count the surviving tenant's legal acceptances: %v", err)
	}
	if otherAcceptances != 1 {
		t.Fatalf("surviving tenant's legal acceptances: %d after another tenant's purge, want 1", otherAcceptances)
	}
}
