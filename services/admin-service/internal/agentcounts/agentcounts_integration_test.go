package agentcounts

// The platform-managed predicate, arm by arm, against a real Postgres.
//
// The trigger-created platform rows carry BOTH markers (platform = 'platform'
// and the 'system' tag), so a test built only from them cannot tell whether
// either arm of the OR is doing anything. This fixture has one row per case:
//
//	platform marker only      → platform-managed
//	'system' tag only         → platform-managed
//	customer, tags NULL       → customer (the COALESCE case)
//	customer, other tags      → customer
//	customer, soft-deleted    → nowhere
//	device agent              → device agents
//	device agent, deleted     → nowhere
//
// It also pins that ForTenant sees only its tenant, and that Totals and the
// PerTenantSQL join agree with ForTenant.
//
// Mutations run (each red, then restored green):
//   - drop `s.platform = 'platform' OR` → the platform-only row turns customer.
//   - drop `OR 'system' = ANY(...)` → the tag-only row turns customer.
//   - drop the COALESCE → the NULL-tags customer row drops out of both buckets.
//   - drop `s.deleted_at IS NULL` / `d.deleted_at IS NULL` → deleted rows count.
//   - drop the `AND s.tenant_id = $1` narrowing → ForTenant counts the other
//     tenant's rows.
//
// Needs TEST_DATABASE_URL (skips otherwise).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func seedPredicateArms(t *testing.T, db *sql.DB, tenant uuid.UUID) {
	t.Helper()
	// The trigger's two rows would make every platform assertion pass without
	// the arms under test; remove them so this tenant holds only the fixture.
	if _, err := db.Exec(`DELETE FROM sensors WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("clear trigger rows: %v", err)
	}
	rows := []struct {
		name, platform string
		tags           any // nil → SQL NULL
		deleted        bool
	}{
		{"platform-marker-only", "platform", "{discovery}", false},
		{"system-tag-only", "linux", "{system}", false},
		{"customer-null-tags", "linux", nil, false},
		{"customer-other-tags", "windows", "{edge,lab}", false},
		{"customer-deleted", "linux", nil, true},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO sensors (tenant_id, name, platform, version, profile, status, tags, deleted_at)
			VALUES ($1, $2, $3, '1.0.0', 'discovery', 'active', $4::text[], CASE WHEN $5 THEN NOW() END)`,
			tenant, r.name, r.platform, r.tags, r.deleted); err != nil {
			t.Fatalf("insert sensor %s: %v", r.name, err)
		}
	}
	for _, deleted := range []bool{false, true} {
		if _, err := db.Exec(`INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, deleted_at)
			VALUES ($1, $2, 'agent', 'linux', '1.0.0', CASE WHEN $3 THEN NOW() END)`,
			tenant, "reg-"+uuid.NewString(), deleted); err != nil {
			t.Fatalf("insert device agent: %v", err)
		}
	}
}

func TestIntegration_AgentCounts_PredicateArms(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	other := testdb.NewTenant(t, db) // keeps its 2 trigger rows: must not leak into tenant's counts
	seedPredicateArms(t, db, tenant)
	ctx := context.Background()

	want := Counts{CustomerSensors: 2, DeviceAgents: 1, PlatformManaged: 2}
	got, err := ForTenant(ctx, db, tenant.String())
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	if got != want {
		t.Fatalf("ForTenant = %+v, want %+v", got, want)
	}
	if got.CustomerAgents() != 3 {
		t.Fatalf("CustomerAgents = %d, want 3 (2 sensors + 1 discovery agent)", got.CustomerAgents())
	}

	otherGot, err := ForTenant(ctx, db, other.String())
	if err != nil {
		t.Fatalf("ForTenant(other): %v", err)
	}
	if otherWant := (Counts{PlatformManaged: 2}); otherGot != otherWant {
		t.Fatalf("ForTenant(other) = %+v, want %+v", otherGot, otherWant)
	}

	// The derived table the rollups LEFT JOIN agrees with ForTenant.
	var viaJoin Counts
	if err := db.QueryRowContext(ctx, `SELECT c.customer_sensors, c.device_agents, c.platform_managed
		FROM (`+PerTenantSQL+`) c WHERE c.tenant_id = $1`, tenant).
		Scan(&viaJoin.CustomerSensors, &viaJoin.DeviceAgents, &viaJoin.PlatformManaged); err != nil {
		t.Fatalf("PerTenantSQL: %v", err)
	}
	if viaJoin != want {
		t.Fatalf("PerTenantSQL row = %+v, want %+v", viaJoin, want)
	}

	// Totals is the sum over every tenant; it must include this tenant's split.
	// Other test binaries share this database, so compare against an
	// independent longhand count rather than a literal.
	var longhand Counts
	if err := db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM sensors WHERE deleted_at IS NULL AND platform <> 'platform'
		   AND NOT ('system' = ANY(COALESCE(tags, '{}'::text[])))),
		(SELECT COUNT(*) FROM device_agents WHERE deleted_at IS NULL),
		(SELECT COUNT(*) FROM sensors WHERE deleted_at IS NULL AND (platform = 'platform'
		   OR 'system' = ANY(COALESCE(tags, '{}'::text[]))))`).
		Scan(&longhand.CustomerSensors, &longhand.DeviceAgents, &longhand.PlatformManaged); err != nil {
		t.Fatalf("longhand: %v", err)
	}
	totals, err := Totals(ctx, db)
	if err != nil {
		t.Fatalf("Totals: %v", err)
	}
	if totals != longhand {
		// A concurrent binary can insert between the two reads; re-read once.
		if err := db.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM sensors WHERE deleted_at IS NULL AND platform <> 'platform'
			   AND NOT ('system' = ANY(COALESCE(tags, '{}'::text[])))),
			(SELECT COUNT(*) FROM device_agents WHERE deleted_at IS NULL),
			(SELECT COUNT(*) FROM sensors WHERE deleted_at IS NULL AND (platform = 'platform'
			   OR 'system' = ANY(COALESCE(tags, '{}'::text[]))))`).
			Scan(&longhand.CustomerSensors, &longhand.DeviceAgents, &longhand.PlatformManaged); err != nil {
			t.Fatalf("longhand: %v", err)
		}
		if totals, err = Totals(ctx, db); err != nil || totals != longhand {
			t.Fatalf("Totals = %+v (err %v), want the longhand count %+v", totals, err, longhand)
		}
	}
}
