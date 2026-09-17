package services

import (
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Immutable snapshots of revision 32f4a259fa85897c2a64ab8d4c9f162857cfbbdf.
// Public Core has rewritten Git history, so replay must never use git show.
// Hashes cover the exact decompressed bytes; fixture provenance lives beside
// the snapshots. The release-tag matrix remains independently disarmed.
const complianceSeverityFixtureDir = "services/inventory-service/internal/services/testdata/compliance-severity-pre-adr16"
const complianceSeverityEEPath = "services/compliance-engine/ee/content/frameworks-regulated.sql"
const complianceSeverityEEFixture = "services/compliance-engine/ee/content/testdata/compliance-severity-pre-adr16/frameworks-regulated.sql.gz"

func readComplianceSeverityFixture(t *testing.T, root, path, wantHash string) string {
	t.Helper()
	file, err := os.Open(filepath.Join(root, path))
	if err != nil {
		t.Fatalf("required pre-ADR0016 fixture %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close fixture file %s: %v", path, err)
		}
	})
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("pre-ADR0016 fixture %s gzip: %v", path, err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("close fixture gzip reader %s: %v", path, err)
		}
	})
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("pre-ADR0016 fixture %s read: %v", path, err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wantHash {
		t.Fatalf("pre-ADR0016 fixture %s checksum = %s, want %s", path, got, wantHash)
	}
	return string(data)
}

func complianceSeverityPriorFixtures(t *testing.T, root string) (schema, coreSeed, eeSeed string) {
	t.Helper()
	schema = readComplianceSeverityFixture(t, root, complianceSeverityFixtureDir+"/schema.sql.gz", "8896bf72a09c932708a363614db199f171b2323327323c8bfab053e9090899c9")
	coreSeed = readComplianceSeverityFixture(t, root, complianceSeverityFixtureDir+"/seed.sql.gz", "ff6b93fc765c6288eebaa4475e6f2c4c23fe120be6a8b4d641ea364664c06f76")
	_, currentErr := os.Stat(filepath.Join(root, complianceSeverityEEPath))
	_, fixtureErr := os.Stat(filepath.Join(root, complianceSeverityEEFixture))
	if os.IsNotExist(currentErr) && os.IsNotExist(fixtureErr) {
		// A public Core export removes the entire ee directory. Core replay is
		// still mandatory; only the absent edition's seed is inapplicable.
		return schema, coreSeed, ""
	}
	if currentErr != nil || fixtureErr != nil {
		t.Fatalf("Enterprise seed/fixture presence must agree: current=%v fixture=%v", currentErr, fixtureErr)
	}
	eeSeed = readComplianceSeverityFixture(t, root, complianceSeverityEEFixture, "332424026300d2db66d2942bcd50bf6be214988f835903485b1e91d699248cf0")
	return schema, coreSeed, eeSeed
}

// Always runs, including without PostgreSQL or private Git objects. A missing,
// corrupt or replaced mandatory snapshot is a test failure, never a skip.
func TestComplianceSeverityPriorFixtureIntegrity(t *testing.T) {
	complianceSeverityPriorFixtures(t, testdb.RepoRoot(t))
}

func TestIntegration_Schema_UpgradesFromPriorReleases_ComplianceSeverity(t *testing.T) {
	root := testdb.RepoRoot(t)
	priorSchema, priorCoreSeed, priorEESeed := complianceSeverityPriorFixtures(t, root)
	admin := testdb.Connect(t)
	db := newScratchDB(t, admin)
	mustApply(t, db, priorSchema, "pre-ADR0016 schema")
	mustApply(t, db, priorCoreSeed, "pre-ADR0016 Core seed")
	if priorEESeed != "" {
		mustApply(t, db, priorEESeed, "pre-ADR0016 Enterprise seed")
	}
	tenant := testdb.NewTenant(t, db)
	user, tenantFramework := uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("fixture statement: %v\n%s", err, q)
		}
	}
	exec("INSERT INTO users (id,tenant_id,email) VALUES ($1,$2,'severity-upgrade@example.test')", user, tenant)
	exec("INSERT INTO tenant_frameworks (id,tenant_id,name,version,created_by) VALUES ($1,$2,'Severity upgrade','1',$3)", tenantFramework, tenant, user)
	var framework, measurementType uuid.UUID
	if err := db.QueryRow("SELECT id FROM platform_frameworks WHERE code='best-practices'").Scan(&framework); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT id FROM measurement_types ORDER BY code LIMIT 1").Scan(&measurementType); err != nil {
		t.Fatal(err)
	}
	type row struct {
		table, column string
		id            uuid.UUID
		want          string
	}
	var rows []row
	legacy := []string{"Low", "Med", "High", "Critical"}
	canonical := []string{"low", "medium", "high", "critical"}
	history := uuid.New()
	for i, old := range legacy {
		platformControl, tenantControl, measurement, threshold, override, finding := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
		exec("INSERT INTO platform_framework_controls (id,framework_id,control_id,title,baseline_severity) VALUES ($1,$2,$3,'Upgrade control',$4)", platformControl, framework, fmt.Sprintf("ADR16-%d", i), old)
		exec("INSERT INTO tenant_framework_controls (id,framework_id,control_id,title,baseline_severity) VALUES ($1,$2,$3,'Upgrade control',$4)", tenantControl, tenantFramework, fmt.Sprintf("ADR16-%d", i), old)
		exec("INSERT INTO control_measurements (id,control_id,framework_type,measurement_type_id,rule_type,predicate,severity_override) VALUES ($1,$2,'platform',$3,'presence','{\"exists\":true}',$4)", measurement, platformControl, measurementType, old)
		exec("INSERT INTO tenant_measurement_overrides (id,tenant_id,control_measurement_id,predicate_override,severity_override,rationale,created_by) VALUES ($1,$2,$3,'{}',$4,'preserve rationale',$5)", threshold, tenant, measurement, old, user)
		exec("INSERT INTO compliance_overrides (id,tenant_id,control_id,override_type,severity_from,severity_to,rationale,created_by) VALUES ($1,$2,$3,'severity',$4,$4,'preserve rationale',$5)", override, tenant, platformControl, old, user)
		rows = append(rows, []row{{"platform_framework_controls", "baseline_severity", platformControl, canonical[i]}, {"tenant_framework_controls", "baseline_severity", tenantControl, canonical[i]}, {"control_measurements", "severity_override", measurement, canonical[i]}, {"tenant_measurement_overrides", "severity_override", threshold, canonical[i]}, {"compliance_overrides", "severity_from", override, canonical[i]}, {"compliance_overrides", "severity_to", override, canonical[i]}}...)
		if i == 0 {
			exec("INSERT INTO findings (id,tenant_id,producer,kind,control_id,subject_type,subject_id,severity,score,summary) VALUES ($1,$2,'compliance','control_noncompliant',$3,'asset',$4,'low',0,'unchanged finding')", finding, tenant, platformControl, uuid.New())
			exec("INSERT INTO compliance_finding_history (id,finding_id,field_name,old_value,new_value,change_reason,changed_by,changed_at) VALUES ($1,$2,'severity','Med','Critical','historical reason',$3,'2026-09-01T00:00:00Z')", history, finding, user)
		}
	}
	snapshot := uuid.New()
	exec("INSERT INTO platform_framework_versions (id,framework_id,version,snapshot,change_summary) VALUES ($1,$2,'adr16-fixture','{\"controls\":[{\"baseline_severity\":\"Med\"}]}','frozen before migration')", snapshot, framework)
	var frozen string
	if err := db.QueryRow("SELECT snapshot::text FROM platform_framework_versions WHERE id=$1", snapshot).Scan(&frozen); err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy deployment default too: new writers must require a grade.
	exec("ALTER TABLE platform_framework_controls ALTER COLUMN baseline_severity SET DEFAULT 'Med'")
	schema := mustReadFile(t, filepath.Join(root, "scripts/database/schema.sql"))
	seed := mustReadFile(t, filepath.Join(root, "scripts/database/seed.sql"))
	for pass := 0; pass < 2; pass++ {
		mustApply(t, db, schema, "current schema, upgrade/reapply")
		mustApply(t, db, seed, "current Core seed/reseed")
		if priorEESeed != "" {
			mustApply(t, db, mustReadFile(t, filepath.Join(root, complianceSeverityEEPath)), "current Enterprise seed/reseed")
		}
		for _, r := range rows {
			var got string
			if err := db.QueryRow(fmt.Sprintf("SELECT %s FROM %s WHERE id=$1", r.column, r.table), r.id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != r.want {
				t.Fatalf("pass%d %s.%s=%q want %q", pass, r.table, r.column, got, r.want)
			}
			for _, bad := range []string{"Med", "info", "invalid"} {
				if _, err := db.Exec(fmt.Sprintf("UPDATE %s SET %s=$1 WHERE id=$2", r.table, r.column), bad, r.id); err == nil {
					t.Fatalf("%s.%s accepted %q", r.table, r.column, bad)
				}
			}
		}
		var old, new, reason, changed string
		if err := db.QueryRow("SELECT old_value,new_value,change_reason,changed_at::date::text FROM compliance_finding_history WHERE id=$1", history).Scan(&old, &new, &reason, &changed); err != nil {
			t.Fatal(err)
		}
		if old != "medium" || new != "critical" || reason != "historical reason" || changed != "2026-09-01" {
			t.Fatal(old, new, reason, changed)
		}
		var after string
		if err := db.QueryRow("SELECT snapshot::text FROM platform_framework_versions WHERE id=$1", snapshot).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != frozen {
			t.Fatal("frozen framework snapshot was rewritten")
		}
		var defaultValue sql.NullString
		if err := db.QueryRow("SELECT column_default FROM information_schema.columns WHERE table_schema='public' AND table_name='platform_framework_controls' AND column_name='baseline_severity'").Scan(&defaultValue); err != nil {
			t.Fatal(err)
		}
		if defaultValue.Valid {
			t.Fatal("legacy default survived", defaultValue.String)
		}
	}
	// An authentic old Enterprise bundle is still authentic historical content,
	// but cannot write obsolete grades into the upgraded live catalogue. The
	// loader must receive the newly signed canonical bundle with this schema.
	if priorEESeed != "" {
		if _, err := db.Exec(priorEESeed); err == nil {
			t.Fatal("legacy Enterprise bundle was accepted by the canonical schema")
		}
	}
	// Every seeded control/rule must obey the new vocabulary after both editions.
	for _, table := range []string{"platform_framework_controls", "tenant_framework_controls", "control_measurements", "tenant_measurement_overrides"} {
		column := "severity_override"
		if strings.HasSuffix(table, "controls") {
			column = "baseline_severity"
		}
		var count int
		if err := db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s WHERE %s NOT IN ('low','medium','high','critical')", table, column)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal(table, "contains legacy severities", count)
		}
	}
}
