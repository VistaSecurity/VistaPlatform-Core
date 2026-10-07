package services

// Upgrade-path half of "tenant-scoped tables cascade from tenants" (schema.sql
// POST-MIGRATIONS). Every prior release let a tenant purge leave rows behind in
// fourteen tables that had no FK to tenants, so every database that ever purged
// a tenant carries orphans there (legal_acceptances included, which gained its
// cascade by a later owner decision) — and the FK this release adds is exactly the
// kind of ADD CONSTRAINT that existing rows violate. A populated double-apply of
// TODAY's schema cannot see that: both passes already have the FK, so no
// orphan can ever be written between them. Only an old release's schema can
// hold them, which is why this lives in TestIntegration_Schema_UpgradesFromPriorReleases.
//
// seedOrphanTenantRows writes, under the OLD schema, one row per table for the
// surviving test tenant, one for a tenant that is then purged (the way the
// orphans really arise), and a platform-track alert under the sentinel tenant.
// assertOrphanTenantRowsRemoved checks, after the CURRENT schema is applied,
// that the purged tenant's rows are gone, the live tenant's and the platform
// alert are untouched, and every FK is present and validated. The same fixture
// writes api_usage_logs rows under the old schema; the upgrade must drop that
// table and its only reader, get_api_usage_stats().
//
// Mutation test: delete the orphan DELETE from one table's POST-MIGRATIONS
// block and the upgrade apply fails with "violates foreign key constraint" on
// that table's VALIDATE; remove that table's ADD CONSTRAINT instead and
// assertOrphanTenantRowsRemoved fails naming it.

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

// orphanFixtureSentinel mirrors events.PlatformAlertTenantID.
const orphanFixtureSentinel = "11111111-1111-1111-1111-111111111111"

// orphanCascadeFKs maps each table to the FK the upgrade must leave on it.
var orphanCascadeFKs = map[string]string{
	"alerts":                          "alerts_tenant_ref_id_fkey",
	"agent_config_audit":              "agent_config_audit_tenant_id_fkey",
	"alert_framework_score_snapshots": "alert_framework_score_snapshots_tenant_id_fkey",
	"cbom_artifacts":                  "cbom_artifacts_tenant_id_fkey",
	"cbom_subscriptions":              "cbom_subscriptions_tenant_id_fkey",
	"invitations":                     "invitations_tenant_id_fkey",
	"legal_acceptances":               "legal_acceptances_tenant_id_fkey",
	"notification_digest_queue":       "notification_digest_queue_tenant_id_fkey",
	"saved_views":                     "saved_views_tenant_id_fkey",
	"scopes":                          "scopes_tenant_id_fkey",
	"scopes_audit":                    "scopes_audit_tenant_id_fkey",
	"tenant_alert_settings":           "tenant_alert_settings_tenant_id_fkey",
	"tenant_entitlements":             "tenant_entitlements_tenant_id_fkey",
	"tenant_geographic_data":          "tenant_geographic_data_tenant_id_fkey",
}

type orphanFixture struct {
	purged uuid.UUID
	// seeded[table] is true when the old release could take the row; a table
	// it lacks (or whose shape differs) is logged and not asserted.
	seeded         map[string]bool
	platformAlert  uuid.UUID
	platformSeeded bool
	// apiUsageSeeded is true when the old release had api_usage_logs and took
	// rows in it; the upgrade must drop the table, rows and all.
	apiUsageSeeded bool
}

func seedOrphanTenantRows(t *testing.T, db *sql.DB, live uuid.UUID) orphanFixture {
	t.Helper()
	f := orphanFixture{purged: uuid.New(), seeded: map[string]bool{}, platformAlert: uuid.New()}
	slug := "up-purged-" + f.purged.String()[:8]
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, f.purged, "Purged "+slug, slug); err != nil {
		t.Fatalf("seed the to-be-purged tenant: %v", err)
	}

	for _, tenant := range []uuid.UUID{live, f.purged} {
		alertID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
		rows := []struct {
			table, q string
			args     []interface{}
		}{
			{"alerts", `INSERT INTO alerts (id, tenant_id, alert_type, source, severity, title, status) VALUES ($1, $2, 'certificate_expiring', 'upgrade', 'high', 'upgrade', 'active')`, []interface{}{alertID, tenant}},
			{"alert_events", `INSERT INTO alert_events (alert_id, tenant_id, event_type) VALUES ($1, $2, 'opened')`, []interface{}{alertID, tenant}},
			{"agent_config_audit", `INSERT INTO agent_config_audit (tenant_id, scope, runtime) VALUES ($1, 'fleet', 'sensor')`, []interface{}{tenant}},
			{"alert_framework_score_snapshots", `INSERT INTO alert_framework_score_snapshots (tenant_id, platform_framework_id, score) VALUES ($1, $2, 50)`, []interface{}{tenant, uuid.New()}},
			{"tenant_alert_settings", `INSERT INTO tenant_alert_settings (tenant_id, alert_type) VALUES ($1, 'certificate_expiring')`, []interface{}{tenant}},
			{"scopes", `INSERT INTO scopes (id, tenant_id, name, created_by, updated_by) VALUES ($1, $2, 'upgrade', $3, $3)`, []interface{}{scopeID, tenant, userID}},
			{"scopes_audit", `INSERT INTO scopes_audit (scope_id, tenant_id, name_before, name_after, query_before, query_after, version_before, version_after) VALUES ($1, $2, 'a', 'b', '', '', 1, 2)`, []interface{}{scopeID, tenant}},
			{"cbom_artifacts", `INSERT INTO cbom_artifacts (tenant_id, scope_id, scope_version, scope_name_snapshot, inline_content, content_hash, size_bytes, component_count, input_data_freshness_at, generated_by) VALUES ($1, $2, 1, 'upgrade', '{}', repeat('0', 64), 2, 0, now(), $3)`, []interface{}{tenant, scopeID, userID}},
			{"cbom_subscriptions", `INSERT INTO cbom_subscriptions (tenant_id, scope_id, name, schedule_cron, delivery, created_by) VALUES ($1, $2, 'upgrade', '0 6 * * MON', '{}', $3)`, []interface{}{tenant, scopeID, userID}},
			{"invitations", `INSERT INTO invitations (tenant_id, email, role, token_hash, expires_at) VALUES ($1, $2, 'viewer', $3, now() + interval '1 day')`, []interface{}{tenant, "up-" + tenant.String()[:8] + "@schema-upgrade.example.test", tenant.String()}},
			{"saved_views", `INSERT INTO saved_views (tenant_id, name, owner_user_id) VALUES ($1, 'upgrade', $2)`, []interface{}{tenant, userID}},
			{"tenant_entitlements", `INSERT INTO tenant_entitlements (tenant_id, item_id) SELECT $1, id FROM billable_items ORDER BY key LIMIT 1`, []interface{}{tenant}},
			{"tenant_geographic_data", `INSERT INTO tenant_geographic_data (tenant_id) VALUES ($1)`, []interface{}{tenant}},
			{"notification_digest_queue", `INSERT INTO notification_digest_queue (tenant_id, channel_id, channel_type, alert_source, alert_type, severity, message, flush_after) VALUES ($1, $2, 'email', 'upgrade', 'upgrade', 'low', 'upgrade', now())`, []interface{}{tenant, uuid.New()}},
			{"legal_acceptances", `INSERT INTO legal_acceptances (tenant_id, user_id, doc_type, document_id, version, content_hash) VALUES ($1, $2, 'terms_of_service', $3, 1, repeat('0', 64))`, []interface{}{tenant, userID, uuid.New()}},
		}
		for _, r := range rows {
			if _, err := db.Exec(r.q, r.args...); err != nil {
				t.Logf("orphan fixture: skipped %s (not in this release's shape): %v", r.table, err)
				f.seeded[r.table] = false
				continue
			}
			if _, already := f.seeded[r.table]; !already {
				f.seeded[r.table] = true
			}
		}
	}

	if _, err := db.Exec(`INSERT INTO alerts (id, tenant_id, alert_type, source, severity, title) VALUES ($1, $2, 'service_down', 'monitoring', 'critical', 'Service down: upgrade')`,
		f.platformAlert, orphanFixtureSentinel); err == nil {
		f.platformSeeded = true
	} else {
		t.Logf("orphan fixture: skipped the platform alert: %v", err)
	}

	// api_usage_logs, dropped by this release. Rows for both tenants, so the
	// DROP runs over a populated table that also holds a soon-orphaned row.
	if _, err := db.Exec(`INSERT INTO api_usage_logs (endpoint, method, status_code, response_time_ms, user_id, tenant_id, ip_address, user_agent)
		VALUES ('/api/v1/upgrade', 'GET', 200, 5, $1, $2, '127.0.0.1', 'upgrade'),
		       ('/api/v1/upgrade', 'GET', 500, 5, $1, $3, '127.0.0.1', 'upgrade')`, uuid.New(), live, f.purged); err == nil {
		f.apiUsageSeeded = true
	} else {
		t.Logf("orphan fixture: skipped api_usage_logs (not in this release's shape): %v", err)
	}

	// The purge, exactly as admin-service runs it. Under the old schema this
	// is where the orphans are born.
	if _, err := db.Exec(`DELETE FROM tenants WHERE id = $1`, f.purged); err != nil {
		t.Fatalf("purge the fixture tenant under the old schema: %v", err)
	}
	var orphans int
	for table, ok := range f.seeded {
		if !ok {
			continue
		}
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, f.purged).Scan(&n); err != nil {
			t.Fatalf("count orphans in %s: %v", table, err)
		}
		orphans += n
	}
	if orphans == 0 {
		// A release that already cascades tenant purges (4.4.0 onward) cannot
		// leave orphans, so there is nothing for this upgrade to clean up and
		// assertOrphanTenantRowsRemoved still checks every FK survives. Only an
		// old release WITHOUT the cascade FKs that still left no orphans means
		// the fixture is broken.
		if missing := missingCascadeFKs(t, db, f); len(missing) > 0 {
			t.Fatalf("the old release left no orphan rows after a purge, yet lacks the cascade FK on %v — the fixture is not exercising the upgrade", missing)
		}
		t.Logf("old release already cascades tenant purges on every seeded table; no orphans to clean up")
		return f
	}
	t.Logf("old release left %d orphan row(s) behind after the purge", orphans)
	return f
}

// missingCascadeFKs lists the seeded tables whose ON DELETE CASCADE FK to
// tenants is absent from the database as it stands (the OLD schema, when called
// from seedOrphanTenantRows).
func missingCascadeFKs(t *testing.T, db *sql.DB, f orphanFixture) []string {
	t.Helper()
	var missing []string
	for table, ok := range f.seeded {
		if !ok {
			continue
		}
		// A table outside orphanCascadeFKs cascades through its parent row
		// (alert_events through alerts), not through a tenant FK of its own.
		fk, tenantFK := orphanCascadeFKs[table]
		if !tenantFK {
			continue
		}
		var present bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_constraint
			WHERE conname = $1 AND conrelid = to_regclass('public.' || $2) AND confdeltype = 'c')`,
			fk, table).Scan(&present); err != nil {
			t.Fatalf("look up the cascade FK on %s: %v", table, err)
		}
		if !present {
			missing = append(missing, table)
		}
	}
	return missing
}

func assertOrphanTenantRowsRemoved(t *testing.T, db *sql.DB, live uuid.UUID, f orphanFixture, tag string) {
	t.Helper()
	for table, ok := range f.seeded {
		if !ok {
			continue
		}
		var purged, kept int
		if err := db.QueryRow(`SELECT count(*) FILTER (WHERE tenant_id = $1), count(*) FILTER (WHERE tenant_id = $2) FROM `+table,
			f.purged, live).Scan(&purged, &kept); err != nil {
			t.Fatalf("count %s after upgrading from %s: %v", table, tag, err)
		}
		if purged != 0 {
			t.Errorf("after upgrading from %s: %s still holds %d row(s) of a purged tenant", tag, table, purged)
		}
		if kept != 1 {
			t.Errorf("after upgrading from %s: %s holds %d row(s) of the live tenant, want 1 — the cleanup reached too far", tag, table, kept)
		}
	}
	for table, fk := range orphanCascadeFKs {
		var validated bool
		err := db.QueryRow(`SELECT convalidated FROM pg_constraint
			WHERE conname = $1 AND conrelid = to_regclass('public.' || $2) AND confdeltype = 'c'`, fk, table).Scan(&validated)
		if err == sql.ErrNoRows {
			t.Errorf("after upgrading from %s: %s has no ON DELETE CASCADE constraint %s", tag, table, fk)
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", fk, err)
		}
		if !validated {
			t.Errorf("after upgrading from %s: %s is still NOT VALID", tag, fk)
		}
	}
	// api_usage_logs and its only reader are gone, whether or not the old
	// release took rows (asserted unconditionally: a fresh table would be just
	// as wrong).
	var apiUsageTable, apiUsageFunc sql.NullString
	if err := db.QueryRow(`SELECT to_regclass('public.api_usage_logs')::text,
		to_regprocedure('public.get_api_usage_stats(timestamp with time zone, timestamp with time zone)')::text`).
		Scan(&apiUsageTable, &apiUsageFunc); err != nil {
		t.Fatalf("look up api_usage_logs: %v", err)
	}
	if apiUsageTable.Valid || apiUsageFunc.Valid {
		t.Errorf("after upgrading from %s: api_usage_logs (%v) / get_api_usage_stats (%v) still exist, want both dropped (rows seeded: %v)",
			tag, apiUsageTable.String, apiUsageFunc.String, f.apiUsageSeeded)
	}
	if f.platformSeeded {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM alerts WHERE id = $1`, f.platformAlert).Scan(&n); err != nil {
			t.Fatalf("count platform alert: %v", err)
		}
		if n != 1 {
			t.Errorf("after upgrading from %s: the platform-track alert under the sentinel tenant is gone — "+
				"it has no tenants row by design and must not be treated as an orphan", tag)
		}
	}
}
