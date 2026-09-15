package services

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestSchemaClaimedAtAlterPrecedesSensorDiscoveriesView(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	const alter = "ALTER TABLE IF EXISTS public.sensor_discoveries_partitioned\n    ADD COLUMN IF NOT EXISTS claimed_at timestamp with time zone;"
	const view = "CREATE OR REPLACE VIEW public.sensor_discoveries AS"

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			alterIdx := strings.Index(sql, alter)
			if alterIdx < 0 {
				t.Fatalf("missing upgrade-safe claimed_at ALTER in %s", rel)
			}
			viewIdx := strings.Index(sql, view)
			if viewIdx < 0 {
				t.Fatalf("missing sensor_discoveries view in %s", rel)
			}
			if alterIdx > viewIdx {
				t.Fatalf("claimed_at ALTER must run before the sensor_discoveries view is recreated in %s", rel)
			}
		})
	}
}

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
		"charts/vistaplatform/files/schema/schema.sql",
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
			// The old table is dropped in POST-MIGRATIONS, so the name may
			// still appear there; what must not survive is a REFERENCE to it.
			if strings.Contains(sql, "REFERENCES public."+retired) {
				t.Fatalf("%s still has a foreign key referencing network_assets_partitioned, which phase 1 drops", rel)
			}
		})
	}
}

func TestSchemaAddsServiceAccountTokenLookupBeforeIndex(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	const alter = "ALTER TABLE IF EXISTS public.service_accounts\n    ADD COLUMN IF NOT EXISTS token_lookup text;"
	const index = "CREATE INDEX IF NOT EXISTS idx_service_accounts_token_lookup"

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			alterIdx := strings.Index(sql, alter)
			if alterIdx < 0 {
				t.Fatalf("missing upgrade-safe service_accounts.token_lookup ALTER in %s", rel)
			}
			indexIdx := strings.Index(sql, index)
			if indexIdx < 0 {
				t.Fatalf("missing service_accounts.token_lookup index in %s", rel)
			}
			if alterIdx > indexIdx {
				t.Fatalf("service_accounts.token_lookup ALTER must run before its index in %s", rel)
			}
		})
	}
}

func TestSchemaKeepsLateUpgradeRepairsForLegacyResidue(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	required := []string{
		"DROP TABLE IF EXISTS public.crypto_configurations CASCADE;",
		"DROP FUNCTION IF EXISTS public.update_crypto_configurations_updated_at();",
		"ALTER TABLE IF EXISTS public.crypto_implementation_certificates\n  DROP CONSTRAINT IF EXISTS valid_certificate_role;",
		"CHECK (certificate_role IN ('leaf', 'primary', 'additional', 'intermediate', 'root'))",
	}

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			for _, want := range required {
				if !strings.Contains(sql, want) {
					t.Fatalf("missing late upgrade repair %q in %s", want, rel)
				}
			}
		})
	}
}

func TestSchemaKeepsDeadTableRetirementContract(t *testing.T) {
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
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			code := stripSQLLineComments(sql)

			for _, table := range retiredTables {
				drop := "DROP TABLE IF EXISTS " + table + " CASCADE;"
				if !strings.Contains(sql, drop) {
					t.Fatalf("missing retirement drop %q in %s", drop, rel)
				}

				references := executableSQLStatementsReferencing(code, table)
				if len(references) == 0 {
					t.Fatalf("expected to see the retirement drop for %s in %s", table, rel)
				}
				for _, stmt := range references {
					if stmt != drop {
						t.Fatalf("%s still references retired table %s outside its drop: %s", rel, table, stmt)
					}
				}
			}

			for _, fn := range retiredFunctions {
				drop := "DROP FUNCTION IF EXISTS " + fn + " CASCADE;"
				if !strings.Contains(sql, drop) {
					t.Fatalf("missing retirement drop %q in %s", drop, rel)
				}

				references := executableSQLStatementsReferencing(code, fn)
				if len(references) == 0 {
					t.Fatalf("expected to see the retirement drop for %s in %s", fn, rel)
				}
				for _, stmt := range references {
					if stmt != drop {
						t.Fatalf("%s still references retired function %s outside its drop: %s", rel, fn, stmt)
					}
				}
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
