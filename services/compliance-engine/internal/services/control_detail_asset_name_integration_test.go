package services

// Phase 1 (workstream 1.5): GetControlDetails names each finding's asset.
//
// The lookup behind FindingSummary.Asset read `SELECT hostname, ip_address FROM
// assets`. `assets` has no `ip_address` column — it carries `primary_address`,
// and ports moved to `asset_endpoints` — so the statement failed for every
// finding on every call. The failure was invisible because the result was
// assigned to `_`: hostname and address stayed invalid, the fallback ran, and
// the whole control-detail view rendered "Unknown Asset" inside a 200.
//
// This is B-41's shape in a different service — a query that cannot run,
// reporting a plausible-looking answer — so the test asserts the NAME, not
// merely the absence of an error. Asserting "no error" would have passed
// against the broken query, since no error was ever surfaced to assert on.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// TestIntegration_GetControlDetails_NamesTheAssetByHostname is the primary
// case: an asset with a hostname must be named by it.
func TestIntegration_GetControlDetails_NamesTheAssetByHostname(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	controlID := f.newControl(t, "CDN-1", "high")
	f.seedMeasurementRow(t, controlID)
	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())

	const hostname = "named-host.example.test"
	var asset uuid.UUID
	if err := f.db.QueryRow(`
		INSERT INTO assets (tenant_id, class_key, class_path, hostname, primary_address, asset_status)
		VALUES ($1, 'server', 'hardware.computer.server', $2, '192.0.2.20'::inet, 'monitoring')
		RETURNING id`, f.tenant, hostname).Scan(&asset); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO findings
			(id, tenant_id, producer, kind, control_id, subject_id, subject_type, severity, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'compliance', 'control_noncompliant', $3, $4, 'asset', 'high', 'TLS 1.0 offered', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, controlID, asset); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	details, err := NewEvaluationService(f.db).GetControlDetails(
		f.tenant, controlID, nil, models.ScenarioFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("GetControlDetails: %v", err)
	}
	if len(details.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(details.Findings))
	}
	if got := details.Findings[0].Asset; got != hostname {
		t.Fatalf("asset = %q, want %q. %q means the naming query did not resolve the "+
			"asset — most likely it named a column `assets` does not have, and the "+
			"error was discarded rather than surfaced",
			got, hostname, got)
	}
}

// TestIntegration_GetControlDetails_FallsBackToTheAssetAddress covers the
// hostname-less asset: the fallback is the asset's own primary_address, which
// has to be rendered as an address and not as inet's CIDR text.
func TestIntegration_GetControlDetails_FallsBackToTheAssetAddress(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	controlID := f.newControl(t, "CDN-2", "high")
	f.seedMeasurementRow(t, controlID)
	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())

	const address = "192.0.2.21"
	var asset uuid.UUID
	if err := f.db.QueryRow(`
		INSERT INTO assets (tenant_id, class_key, class_path, primary_address, asset_status)
		VALUES ($1, 'unknown_host', 'unknown_host', $2::inet, 'monitoring')
		RETURNING id`, f.tenant, address).Scan(&asset); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO findings
			(id, tenant_id, producer, kind, control_id, subject_id, subject_type, severity, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'compliance', 'control_noncompliant', $3, $4, 'asset', 'high', 'TLS 1.0 offered', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, controlID, asset); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	details, err := NewEvaluationService(f.db).GetControlDetails(
		f.tenant, controlID, nil, models.ScenarioFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("GetControlDetails: %v", err)
	}
	if len(details.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(details.Findings))
	}
	if got := details.Findings[0].Asset; got != address {
		t.Fatalf("asset = %q, want %q — \"Unknown Asset\" means the lookup did not "+
			"resolve, and a value carrying a /prefix means primary_address reached "+
			"the response without host()", got, address)
	}
}
