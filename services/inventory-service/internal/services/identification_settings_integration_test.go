package services

// The tenant auto-accept threshold, against a real Postgres (workstream 4.6).
//
// Two things no unit test can assert: it is RLS-isolated per tenant, and it
// survives beside the OTHER keys in `tenant_admin_settings.config` (a
// read-modify-write that clobbered `capability_policy` would be invisible until
// somebody's active scanning quietly turned itself back on).
//
// The third — that the value the ENGINE reads on an observation is the one the
// tenant stored — is not here, and saying it was is how it came to be untested.
// It lives in auto_accept_wiring_integration_test.go, which drives the conflict
// path; nothing in THIS file resolves an observation at all.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newIdentificationSettingsFixture(t *testing.T) (*IdentificationSettingsService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return NewIdentificationSettingsService(db), db, testdb.NewTenant(t, raw)
}

func TestIntegration_IdentificationSettings_DefaultsToNever(t *testing.T) {
	svc, _, tenant := newIdentificationSettingsFixture(t)

	got, err := svc.Get(context.Background(), tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AutoAcceptThreshold != DefaultAutoAcceptThreshold {
		t.Errorf("threshold = %v, want %v: a tenant with no settings row has not asked for auto-merge",
			got.AutoAcceptThreshold, DefaultAutoAcceptThreshold)
	}
}

func TestIntegration_IdentificationSettings_RoundTrips(t *testing.T) {
	svc, _, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	saved, err := svc.Set(ctx, tenant, uuid.Nil, 0.9)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if saved.AutoAcceptThreshold != 0.9 || saved.Version < 1 {
		t.Fatalf("Set returned %+v, want 0.9 at version >= 1", saved)
	}

	got, err := svc.Get(ctx, tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AutoAcceptThreshold != 0.9 {
		t.Errorf("threshold = %v after a write of 0.9", got.AutoAcceptThreshold)
	}

	// And back to zero. Turning auto-accept OFF is the write that matters most
	// and the one a "0 means unset" bug would silently drop.
	if _, err := svc.Set(ctx, tenant, uuid.Nil, 0); err != nil {
		t.Fatalf("Set 0: %v", err)
	}
	got, err = svc.Get(ctx, tenant)
	if err != nil {
		t.Fatalf("Get after 0: %v", err)
	}
	if got.AutoAcceptThreshold != 0 {
		t.Errorf("threshold = %v after being turned off", got.AutoAcceptThreshold)
	}
}

// The settings row is one jsonb document several features share. A write of the
// threshold must leave the others alone — a read-modify-write that round-tripped
// the whole document in Go would drop whatever changed in between, and the
// symptom would be somebody's capability policy quietly reverting.
func TestIntegration_IdentificationSettings_PreserveOtherKeys(t *testing.T) {
	svc, db, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
		_, e := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
			VALUES ($1, $2::jsonb, 1, NOW(), NOW())`,
			tenant, `{"discovery_auto_scan":{"enabled":false},"onboarding_required":true}`)
		return e
	})
	if err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	if _, err := svc.Set(ctx, tenant, uuid.Nil, 0.85); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var raw []byte
	err = database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenant).Scan(&raw)
	})
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	policy, ok := config["discovery_auto_scan"].(map[string]any)
	if !ok || policy["enabled"] != false {
		t.Errorf("discovery_auto_scan was clobbered by the threshold write: %s", raw)
	}
	if config["onboarding_required"] != true {
		t.Errorf("onboarding_required was clobbered by the threshold write: %s", raw)
	}
	identity, ok := config["identity"].(map[string]any)
	if !ok || identity["auto_accept_threshold"] != 0.85 {
		t.Errorf("the threshold did not land: %s", raw)
	}
}

// RLS: one tenant's threshold is invisible to another, and writing one does not
// touch the other's.
//
// This is the assertion that matters most on this particular setting. A leak
// here would not merely disclose a number — it would apply one tenant's
// permission to auto-merge to another tenant's inventory.
func TestIntegration_IdentificationSettings_RLSIsolation(t *testing.T) {
	svc, db, tenantA := newIdentificationSettingsFixture(t)
	ctx := context.Background()
	tenantB := testdb.NewTenant(t, db.DB.DB)

	if _, err := svc.Set(ctx, tenantA, uuid.Nil, 0.95); err != nil {
		t.Fatalf("Set A: %v", err)
	}

	gotB, err := svc.Get(ctx, tenantB)
	if err != nil {
		t.Fatalf("Get B: %v", err)
	}
	if gotB.AutoAcceptThreshold != 0 {
		t.Fatalf("tenant B reads %v, want 0: tenant A's auto-merge permission reached another tenant",
			gotB.AutoAcceptThreshold)
	}

	if _, err := svc.Set(ctx, tenantB, uuid.Nil, 0.5); err != nil {
		t.Fatalf("Set B: %v", err)
	}
	gotA, err := svc.Get(ctx, tenantA)
	if err != nil {
		t.Fatalf("Get A: %v", err)
	}
	if gotA.AutoAcceptThreshold != 0.95 {
		t.Errorf("tenant A's threshold changed to %v when tenant B wrote theirs", gotA.AutoAcceptThreshold)
	}
}

// The FIRST save is audited.
//
// `log_tenant_admin_settings_change` is an AFTER **UPDATE** trigger reading
// OLD.config/OLD.version (and `tenant_admin_settings_audit.version_before` is
// NOT NULL), so it cannot fire on an INSERT — a plain
// `INSERT … ON CONFLICT DO UPDATE` therefore records NOTHING for a tenant who
// has never opened a settings page. That is exactly the save worth recording
// here: it is the one that first grants the platform permission to merge two
// assets unasked, and "nothing was recorded" and "nobody changed it" would look
// identical in the audit trail afterwards. Same gap, same fix as's
// SetTenantAIControls: seed the row, then UPDATE.
//
// Both saves are asserted. A fix that audited only the second would pass a
// second-save assertion on its own.
func TestIntegration_IdentificationSettings_FirstSaveIsAudited(t *testing.T) {
	svc, db, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	auditRows := func() int {
		t.Helper()
		var n int
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
			return tx.QueryRowContext(ctx,
				`SELECT count(*) FROM tenant_admin_settings_audit WHERE tenant_id = $1`, tenant).Scan(&n)
		})
		if err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		return n
	}

	if got := auditRows(); got != 0 {
		t.Fatalf("the fixture already has %d audit rows", got)
	}

	// The first save, on a tenant with no settings row at all.
	if _, err := svc.Set(ctx, tenant, uuid.Nil, 0.9); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if got := auditRows(); got != 1 {
		t.Errorf("the first save wrote %d audit rows, want 1: first granting auto-merge went unrecorded", got)
	}

	// And the second still is.
	if _, err := svc.Set(ctx, tenant, uuid.Nil, 0); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if got := auditRows(); got != 2 {
		t.Errorf("after two saves there are %d audit rows, want 2", got)
	}
}

func TestIntegration_IdentificationSettings_RefusesOutOfRange(t *testing.T) {
	svc, _, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	for _, bad := range []float64{-0.01, 1.01, 42} {
		if _, err := svc.Set(ctx, tenant, uuid.Nil, bad); err == nil {
			t.Errorf("Set(%v) was accepted; out of range must be refused, not clamped", bad)
		}
	}
	got, err := svc.Get(ctx, tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AutoAcceptThreshold != 0 {
		t.Errorf("a refused write still moved the threshold to %v", got.AutoAcceptThreshold)
	}
}

// A value the database holds that is not a usable threshold reads as ZERO, not
// as whatever it says.
//
// Someone can write `tenant_admin_settings.config` by hand — it is one jsonb
// column with several writers — and the only safe reading of a threshold nobody
// can account for is the one that merges nothing.
func TestIntegration_IdentificationSettings_CorruptValueReadsAsNever(t *testing.T) {
	svc, db, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	for _, corrupt := range []string{
		`{"identity":{"auto_accept_threshold":"very"}}`,
		`{"identity":{"auto_accept_threshold":1.7}}`,
		`{"identity":{"auto_accept_threshold":-3}}`,
		`{"identity":{}}`,
		`{}`,
	} {
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
			_, e := tx.ExecContext(ctx, `
				INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
				VALUES ($1, $2::jsonb, 1, NOW(), NOW())
				ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config`,
				tenant, corrupt)
			return e
		})
		if err != nil {
			t.Fatalf("seed %s: %v", corrupt, err)
		}
		got, err := svc.Get(ctx, tenant)
		if err != nil {
			t.Fatalf("Get after %s: %v", corrupt, err)
		}
		if got.AutoAcceptThreshold != 0 {
			t.Errorf("%s read as %v, want 0", corrupt, got.AutoAcceptThreshold)
		}
	}
}
