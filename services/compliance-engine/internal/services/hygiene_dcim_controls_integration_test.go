package services

// The DCIM half of Inventory Hygiene (DCIM gap 6): the seeded IH-007 to IH-015
// controls, through the real EvaluateFramework().
//
// Each control counts one of the hygiene producer's DCIM finding kinds per
// asset (standards/measurement-types.yaml, `finding` shape). What this file
// pins is the evaluator path and its three values, against the SEEDED rows:
//
//   - FAIL on the asset carrying the open finding, and on that asset only —
//     its compliant twin, assessed and in scope, is not a violation;
//   - PASS when every in-scope asset was assessed and carries none;
//   - NOT ASSESSED when the assets are outside the control's population (no
//     rack, no warranty date, no end of support recorded, no cable, no
//     address) even though the producer evaluated them — unknown is not
//     compliant — and when the producer has never run at all.
//
// The producer half (that the findings land on the right assets from real
// DCIM rows) is inventory-service's hygiene_dcim_integration_test.go.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// dcimControls is each DCIM control and the hygiene kind it counts.
var dcimControls = []struct{ control, kind string }{
	{"IH-007", "not_racked"},
	{"IH-008", "no_rack_position"},
	{"IH-009", "planned_cable_stale"},
	{"IH-010", "cable_unconfirmed"},
	{"IH-011", "interface_no_type"},
	{"IH-012", "duplicate_address"},
	{"IH-013", "warranty_expired"},
	{"IH-014", "past_end_of_support"},
	{"IH-015", "end_of_support_soon"},
}

type dcimControlsFixture struct {
	*inventoryFrameworkFixture
	frameworkID uuid.UUID
	deviceType  uuid.UUID
	site        any
}

func newDCIMControlsFixture(t *testing.T) *dcimControlsFixture {
	t.Helper()
	f := &dcimControlsFixture{inventoryFrameworkFixture: newInventoryFrameworkFixture(t)}
	if err := f.db.Get(&f.frameworkID, `SELECT id FROM platform_frameworks WHERE code = 'inventory-hygiene'`); err != nil {
		t.Fatalf("seeded inventory-hygiene framework: %v", err)
	}
	return f
}

// newTenant is a tenant that has activated Inventory Hygiene, with a device
// type (end of support five years out) and a rack of its own.
func (f *dcimControlsFixture) newTenant(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenant := f.tenant(t)
	f.mustExec(t, `INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
	               VALUES ($1, $2, 'active')`, tenant, f.frameworkID)
	sfx := uuid.NewString()[:8]
	mfr := uuid.New()
	f.mustExec(t, `INSERT INTO manufacturers (id, tenant_id, name, slug) VALUES ($1, $2, $3, $4)`, mfr, tenant, "M "+sfx, "m-"+sfx)
	f.deviceType = uuid.New()
	f.mustExec(t, `INSERT INTO device_types (id, tenant_id, manufacturer_id, model, slug, u_height, end_of_support)
	               VALUES ($1, $2, $3, 'R1', $4, 1, $5)`, f.deviceType, tenant, mfr, "r1-"+sfx, time.Now().AddDate(5, 0, 0))
	f.site = testdb.EnsureSite(t, f.db, tenant, "DC-"+sfx)
	rack := uuid.New()
	f.mustExec(t, `INSERT INTO racks (id, tenant_id, name, site_id) VALUES ($1, $2, 'R-01', $3)`, rack, tenant, f.site)
	return tenant, rack
}

func (f *dcimControlsFixture) mustExec(t *testing.T, q string, args ...any) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		_, err := f.db.Exec(q, args...)
		return err
	})
}

// inScopeAsset is a monitored hardware asset in EVERY DCIM control's
// population: a device type with an end of support, a rack and a position, a
// warranty date, a connected and a planned cable, and an address. Assessed by
// the hygiene producer when assessed is true.
func (f *dcimControlsFixture) inScopeAsset(t *testing.T, tenant, rack uuid.UUID, name string, position int, assessed bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	f.mustExec(t, `INSERT INTO assets (id, tenant_id, class_key, class_path, hostname, display_name, asset_status,
	                   last_seen_at, owner_email, site_id, device_type_id, rack_id, position, face, warranty_end)
	               VALUES ($1, $2, 'switch', 'hardware.network_device.switch', $3, $3, 'monitoring', now(),
	                   'ops@example.com', $4, $5, $6, $7, 'front', $8)`,
		id, tenant, name, f.site, f.deviceType, rack, position, time.Now().AddDate(1, 0, 0))
	var ifaces [3]uuid.UUID
	for i := range ifaces {
		ifaces[i] = uuid.New()
		f.mustExec(t, `INSERT INTO interfaces (id, tenant_id, asset_id, name, type) VALUES ($1, $2, $3, $4, '1000base-t')`,
			ifaces[i], tenant, id, "eth"+string(rune('0'+i)))
	}
	for i, status := range []string{"connected", "planned"} {
		cable := uuid.New()
		f.mustExec(t, `INSERT INTO cables (id, tenant_id, operational_status) VALUES ($1, $2, $3)`, cable, tenant, status)
		f.mustExec(t, `INSERT INTO cable_terminations (tenant_id, cable_id, cable_end, termination_kind, termination_id, asset_id)
		               VALUES ($1, $2, 'A', 'interface', $3, $4)`, tenant, cable, ifaces[i], id)
	}
	f.mustExec(t, `INSERT INTO ip_addresses (tenant_id, address, assigned_kind, assigned_id) VALUES ($1, $2, 'interface', $3)`,
		tenant, "10.9.8."+string(rune('0'+position))+"/24", ifaces[2])
	if assessed {
		f.mustExec(t, `INSERT INTO producer_assessments (tenant_id, asset_id, producer) VALUES ($1, $2, 'hygiene')`, tenant, id)
	}
	return id
}

// statuses runs EvaluateFramework and returns each DCIM control's effective
// status.
func (f *dcimControlsFixture) statuses(t *testing.T, tenant uuid.UUID) map[string]ControlSummary {
	t.Helper()
	summary, err := NewEvaluationService(f.db, f.eval).EvaluateFramework(tenant, f.frameworkID, "1.0", models.ScenarioFilters{}, nil)
	if err != nil {
		t.Fatalf("EvaluateFramework: %v", err)
	}
	out := map[string]ControlSummary{}
	for _, c := range summary.Controls {
		out[c.ControlID] = c
	}
	for _, dc := range dcimControls {
		if _, ok := out[dc.control]; !ok {
			t.Fatalf("EvaluateFramework did not list %s — the seed lost the control", dc.control)
		}
	}
	return out
}

func TestIntegration_InventoryHygiene_DCIMControlsFailOnTheViolatingAsset(t *testing.T) {
	f := newDCIMControlsFixture(t)
	tenant, rack := f.newTenant(t)
	bad := f.inScopeAsset(t, tenant, rack, "bad-1", 1, true)
	good := f.inScopeAsset(t, tenant, rack, "good-1", 3, true)
	for _, dc := range dcimControls {
		f.finding(t, tenant, bad, "asset", "hygiene", dc.kind)
	}

	got := f.statuses(t, tenant)
	for _, dc := range dcimControls {
		if s := got[dc.control].StatusEffective; s != statusFail {
			t.Errorf("%s (%s): status %s, want FAIL", dc.control, dc.kind, s)
		}
		// The per-control result names the violating asset and not its twin.
		res := f.evaluate(t, tenant, "inventory-hygiene", dc.control)
		if len(res.Findings) != 1 || res.Findings[0].SubjectID != bad {
			ids := make([]uuid.UUID, 0, len(res.Findings))
			for _, fi := range res.Findings {
				ids = append(ids, fi.SubjectID)
			}
			t.Errorf("%s: violations on %v, want exactly [%s] (not the compliant %s)", dc.control, ids, bad, good)
		}
	}
}

func TestIntegration_InventoryHygiene_DCIMControlsPassWhenAssessedAndClean(t *testing.T) {
	f := newDCIMControlsFixture(t)
	tenant, rack := f.newTenant(t)
	f.inScopeAsset(t, tenant, rack, "good-1", 1, true)
	f.inScopeAsset(t, tenant, rack, "good-2", 3, true)
	// A hygiene finding of another kind, and a DCIM-kind finding from a
	// different producer, must not fail these controls.
	other := f.inScopeAsset(t, tenant, rack, "good-3", 5, true)
	f.finding(t, tenant, other, "asset", "hygiene", "no_owner")
	f.finding(t, tenant, other, "asset", "topology", "cable_drift")

	got := f.statuses(t, tenant)
	for _, dc := range dcimControls {
		if s := got[dc.control].StatusEffective; s != statusPass {
			t.Errorf("%s (%s): status %s (%s), want PASS", dc.control, dc.kind, s, got[dc.control].NotAssessedReason)
		}
	}
}

func TestIntegration_InventoryHygiene_DCIMControlsNotAssessedOutsideTheirPopulation(t *testing.T) {
	f := newDCIMControlsFixture(t)

	t.Run("assessed, but nothing recorded to judge", func(t *testing.T) {
		tenant, _ := f.newTenant(t)
		// A monitored server the producer evaluated, with no device type, no
		// rack, no cable, no address, no warranty and no end of support.
		f.asset(t, tenant, assetSpec{hostname: "bare-1", owner: "ops@example.com", site: "DC1", assessedBy: []string{"hygiene"}})
		got := f.statuses(t, tenant)
		for _, dc := range dcimControls {
			want := statusNotAssessed
			if dc.control == "IH-011" {
				// Every monitored asset is in IH-011's population: an asset
				// with no interfaces has none untyped.
				want = statusPass
			}
			if s := got[dc.control].StatusEffective; s != want {
				t.Errorf("%s (%s): status %s, want %s — an asset with nothing recorded is unknown, not compliant",
					dc.control, dc.kind, s, want)
			}
		}
	})

	t.Run("in scope, but the producer never ran", func(t *testing.T) {
		tenant, rack := f.newTenant(t)
		f.inScopeAsset(t, tenant, rack, "unassessed-1", 1, false)
		got := f.statuses(t, tenant)
		for _, dc := range dcimControls {
			if s := got[dc.control].StatusEffective; s != statusNotAssessed {
				t.Errorf("%s (%s): status %s, want NOT_ASSESSED — zero findings from a producer that never ran is not clean",
					dc.control, dc.kind, s)
			}
		}
	})
}
