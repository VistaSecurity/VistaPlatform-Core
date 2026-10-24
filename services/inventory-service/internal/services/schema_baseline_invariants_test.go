package services

// Current-shape invariants of scripts/database/schema.sql that a text read can
// check without a database: what the 5.0.0 baseline must keep true, as opposed
// to the old->new transitions the per-feature upgrade tests used to pin (those
// were retired with the migration block, asset-inventory ADR-0010 D11).

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestSchemaDeclaresAssetsPrimaryKeyBeforeItsCompositeFKs is the successor to
// the network_assets_partitioned pkey-repair guard.
//
// The property is unchanged and is what the old guard was really about: a
// composite foreign key can only reference a unique key that already exists and
// is VALID. On the old table that took a repair block, because an earlier
// release had created the parent pkey with `ALTER TABLE ONLY` — invalid, with no
// attached partition indexes, and therefore not a usable FK target.
//
// `assets` cannot land in that state: its PRIMARY KEY (tenant_id, id) is
// declared IN the CREATE TABLE, which is recursive by construction. What still
// has to hold is the ORDER — the table, with its key, before anything
// references it — so that is what this asserts. The old table, its partitions
// and the repair block are gone (phase 1, ADR-0007 D2).
func TestSchemaDeclaresAssetsPrimaryKeyBeforeItsCompositeFKs(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	const pkey = "CONSTRAINT assets_pkey PRIMARY KEY (tenant_id, id)"
	const compositeFK = "REFERENCES public.assets(tenant_id, id)"
	const retired = "network_assets_partitioned("

	for _, rel := range []string{
		"scripts/database/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			pkeyIdx := strings.Index(sql, pkey)
			if pkeyIdx < 0 {
				t.Fatalf("missing composite primary key on assets in %s — without it no child table can reference an asset", rel)
			}
			fkIdx := strings.Index(sql, compositeFK)
			if fkIdx < 0 {
				t.Fatalf("nothing references assets(tenant_id, id) in %s: the child tables lost their asset link", rel)
			}
			if pkeyIdx > fkIdx {
				t.Fatalf("assets must be created with its composite primary key BEFORE anything references it in %s", rel)
			}
			// The old table is gone; no foreign key may reference it.
			if strings.Contains(sql, "REFERENCES public."+retired) {
				t.Fatalf("%s still has a foreign key referencing network_assets_partitioned, which phase 1 drops", rel)
			}
		})
	}
}

// TestSchemaNamesNoRetiredTable: the tables and functions retired for having
// neither reader nor writer are gone from the baseline, and no executable
// statement may name one again — not a view reading it, not a foreign key, not
// a DROP (the 5.0.0 baseline is a fresh install, so there is nothing to drop).
// Comments may name them; that is how the file records why something is gone.
func TestSchemaNamesNoRetiredTable(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	retiredTables := []string{
		"audit.audit_logs",
		"audit.alert_instances",
		"audit.retention_jobs",
		"public.access_pattern_analysis",
		"public.agent_ca_certificates",
		"public.ai_analysis_results",
		"public.ai_models",
		"public.api_format_preferences",
		"public.api_security_monitoring",
		"public.ci_relationships",
		"public.compliance_checks",
		"public.compliance_framework_status",
		"public.compliance_reports",
		"public.compliance_requirements",
		"public.dashboard_cache",
		"public.dashboard_metrics",
		"public.discovery_approval_queue",
		"public.feature_adoption_metrics",
		"public.feature_usage_events",
		"public.health_insights",
		"public.identity_link_requests",
		"public.pending_sensors",
		"public.platform_integration_secrets",
		"public.resource_permissions",
		"public.resource_tracking_config",
		"public.security_events",
		"public.sync_outbox",
		"public.system_health_metrics",
		"public.tenant_cost_analysis",
		"public.tenant_usage_tracking",
		"public.threat_detection_rules",
	}

	retiredFunctions := []string{
		"public.calculate_tenant_cost",
		"public.cleanup_expired_dashboard_cache",
		"public.get_system_health_summary",
		"public.update_tenant_usage",
	}

	for _, rel := range []string{
		"scripts/database/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			code := stripSQLLineComments(sql)

			for _, name := range append(append([]string{}, retiredTables...), retiredFunctions...) {
				for _, stmt := range executableSQLStatementsReferencing(code, name) {
					t.Errorf("%s names retired %s in an executable statement: %s", rel, name, stmt)
				}
			}
			// The matcher must be live: the same scan over a statement that DOES
			// name one finds it, so an empty result above means something.
			if len(executableSQLStatementsReferencing("DROP TABLE IF EXISTS public.sync_outbox CASCADE;", "public.sync_outbox")) != 1 {
				t.Fatal("executableSQLStatementsReferencing no longer matches a statement naming a relation")
			}
		})
	}
}

func stripSQLLineComments(sql string) string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if before, _, ok := strings.Cut(line, "--"); ok {
			line = before
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func executableSQLStatementsReferencing(sql, relation string) []string {
	parts := strings.Split(relation, ".")
	name := parts[len(parts)-1]
	qualifier := ""
	if len(parts) > 1 {
		qualifier = `(?:` + regexp.QuoteMeta(parts[0]) + `\.)?`
	}
	reference := regexp.MustCompile(`(?i)(?:\b|")` + qualifier + regexp.QuoteMeta(name) + `(?:\b|")`)
	statements := strings.Split(sql, ";")
	matches := make([]string, 0)
	for _, stmt := range statements {
		stmt = strings.Join(strings.Fields(stmt), " ")
		if stmt == "" {
			continue
		}
		stmt += ";"
		if reference.MatchString(stmt) {
			matches = append(matches, stmt)
		}
	}
	return matches
}
