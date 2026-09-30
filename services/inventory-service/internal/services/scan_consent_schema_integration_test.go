package services

// schema.sql's per-source scan consent table (source_scan_consents, platform
// ADR-0002 D10) re-applies over a POPULATED database — the chart's
// schema-migration Job re-runs the whole file on every helm upgrade — and a
// single fresh apply gives the app role what it needs to write it under RLS.
// The upgrade path from prior releases is
// TestIntegration_Schema_UpgradesFromPriorReleases.
//
// MUTATION (goes red): drop IF NOT EXISTS from the CREATE TABLE; drop the
// policy's DROP POLICY IF EXISTS; move the CREATE TABLE below the ROLE GRANTS
// block (crypto_app then has no privilege on a single apply).

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Schema_ReappliesOverPopulatedScanConsents(t *testing.T) {
	raw := testdb.ScratchDatabase(t)
	tenant := testdb.NewTenant(t, raw)

	var granted bool
	if err := raw.QueryRow(`SELECT has_table_privilege('crypto_app', 'public.source_scan_consents', 'INSERT')
		AND has_table_privilege('crypto_app', 'public.source_scan_consents', 'UPDATE')`).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Fatal("after a single fresh apply crypto_app cannot write source_scan_consents")
	}

	for _, row := range []struct {
		ref   string
		allow bool
	}{{"cmdb:reapply-on", true}, {"netbox:reapply-off", false}} {
		if _, err := raw.Exec(`INSERT INTO source_scan_consents (tenant_id, source_ref, allow_active_scan) VALUES ($1, $2, $3)`,
			tenant, row.ref, row.allow); err != nil {
			t.Fatal(err)
		}
	}

	testdb.ForceApplySchema(t, raw)
	testdb.ForceApplySchema(t, raw)

	var n, on int
	var rls bool
	if err := raw.QueryRow(`SELECT count(*), count(*) FILTER (WHERE allow_active_scan) FROM source_scan_consents WHERE tenant_id = $1`, tenant).Scan(&n, &on); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT relrowsecurity FROM pg_class WHERE oid = 'public.source_scan_consents'::regclass`).Scan(&rls); err != nil {
		t.Fatal(err)
	}
	if n != 2 || on != 1 || !rls {
		t.Errorf("after two re-applies: %d rows (want 2), %d on (want 1), row-level security %v", n, on, rls)
	}
	// The key still holds on the re-applied table.
	if _, err := raw.Exec(`INSERT INTO source_scan_consents (tenant_id, source_ref) VALUES ($1, 'cmdb:reapply-on')`, tenant); err == nil {
		t.Error("a second row for one source was accepted")
	}
}
