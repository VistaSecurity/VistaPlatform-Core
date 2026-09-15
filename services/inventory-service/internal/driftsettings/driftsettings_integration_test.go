package driftsettings

// The tenant drift baseline window, against a real Postgres (workstream 4.7).
//
// Three things no unit test can assert: it is RLS-isolated per tenant, it
// survives beside the OTHER keys in `tenant_admin_settings.config`, and the
// FIRST save is audited — the trigger on that table is AFTER UPDATE only, so an
// upsert records nothing for a tenant who has never opened a settings page.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newFixture(t *testing.T) (*Service, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return NewService(db), db, testdb.NewTenant(t, raw)
}

func TestIntegration_DriftSettings_DefaultsToThirtyDays(t *testing.T) {
	svc, _, tenant := newFixture(t)

	got, err := svc.Get(context.Background(), tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.BaselineDays != DefaultBaselineDays {
		t.Errorf("baseline_days = %d, want %d for a tenant with no settings row", got.BaselineDays, DefaultBaselineDays)
	}
}

func TestIntegration_DriftSettings_RoundTrips(t *testing.T) {
	svc, _, tenant := newFixture(t)
	ctx := context.Background()

	saved, err := svc.Set(ctx, tenant, uuid.Nil, 90)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if saved.BaselineDays != 90 || saved.Version < 1 {
		t.Fatalf("Set returned %+v, want 90 at version >= 1", saved)
	}
	got, err := svc.Get(ctx, tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.BaselineDays != 90 {
		t.Errorf("baseline_days = %d after a write of 90", got.BaselineDays)
	}
}

// Refused, not clamped, at BOTH ends — and a rejected write must leave the
// stored value alone rather than half-applying.
func TestIntegration_DriftSettings_OutOfBoundsIsRefused(t *testing.T) {
	svc, _, tenant := newFixture(t)
	ctx := context.Background()

	if _, err := svc.Set(ctx, tenant, uuid.Nil, 45); err != nil {
		t.Fatalf("Set 45: %v", err)
	}
	for _, days := range []int{0, -1, MinBaselineDays - 1, MaxBaselineDays + 1, 100000} {
		if _, err := svc.Set(ctx, tenant, uuid.Nil, days); !errors.Is(err, ErrInvalidBaselineDays) {
			t.Errorf("Set(%d) returned %v, want ErrInvalidBaselineDays — clamping would store a window nobody asked for", days, err)
		}
	}
	got, err := svc.Get(ctx, tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.BaselineDays != 45 {
		t.Errorf("baseline_days = %d after five refused writes, want the stored 45", got.BaselineDays)
	}
	// Both bounds are reachable.
	for _, days := range []int{MinBaselineDays, MaxBaselineDays} {
		if _, err := svc.Set(ctx, tenant, uuid.Nil, days); err != nil {
			t.Errorf("Set(%d) at the bound returned %v; the bounds are inclusive", days, err)
		}
	}
}

// A value nobody could have written through Set — hand-edited, or left by a
// future version — must read as the DEFAULT, not as a one-day window that
// reports the whole inventory as drift.
func TestIntegration_DriftSettings_CorruptValueReadsAsTheDefault(t *testing.T) {
	svc, db, tenant := newFixture(t)
	ctx := context.Background()

	for _, raw := range []string{`1`, `"thirty"`, `null`, `{"days":30}`, `-5`, `100000`} {
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
			_, e := tx.ExecContext(ctx, `
				INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
				VALUES ($1, jsonb_build_object('drift', jsonb_build_object('baseline_days', $2::jsonb)), 1, NOW(), NOW())
				ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config`, tenant, raw)
			return e
		})
		if err != nil {
			t.Fatalf("seed %s: %v", raw, err)
		}
		got, err := svc.Get(ctx, tenant)
		if err != nil {
			t.Fatalf("Get with %s stored: %v", raw, err)
		}
		if got.BaselineDays != DefaultBaselineDays {
			t.Errorf("a stored value of %s read as %d, want the default %d", raw, got.BaselineDays, DefaultBaselineDays)
		}
	}
}

// The settings row is one jsonb document several features share. Writing the
// window must leave the others alone — and it must land even when the `drift`
// key does not exist yet, which is the `jsonb_set` no-op the concatenation is
// there to prevent.
func TestIntegration_DriftSettings_PreserveOtherKeys(t *testing.T) {
	svc, db, tenant := newFixture(t)
	ctx := context.Background()

	err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
		_, e := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
			VALUES ($1, $2::jsonb, 1, NOW(), NOW())`,
			tenant, `{"capability_policy":{"active_scanning":false},"identity":{"auto_accept_threshold":0.9}}`)
		return e
	})
	if err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	if _, err := svc.Set(ctx, tenant, uuid.Nil, 60); err != nil {
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
	policy, ok := config["capability_policy"].(map[string]any)
	if !ok || policy["active_scanning"] != false {
		t.Errorf("capability_policy was clobbered by the window write: %s", raw)
	}
	identity, ok := config["identity"].(map[string]any)
	if !ok || identity["auto_accept_threshold"] != 0.9 {
		t.Errorf("the identity block was clobbered by the window write: %s", raw)
	}
	drift, ok := config["drift"].(map[string]any)
	if !ok || drift["baseline_days"] != float64(60) {
		t.Errorf("the window did not land — the jsonb_set was a silent no-op: %s", raw)
	}
}

// RLS: one tenant's window is invisible to another.
func TestIntegration_DriftSettings_RLSIsolation(t *testing.T) {
	svc, db, tenantA := newFixture(t)
	ctx := context.Background()
	tenantB := testdb.NewTenant(t, db.DB.DB)

	if _, err := svc.Set(ctx, tenantA, uuid.Nil, 120); err != nil {
		t.Fatalf("Set A: %v", err)
	}
	gotB, err := svc.Get(ctx, tenantB)
	if err != nil {
		t.Fatalf("Get B: %v", err)
	}
	if gotB.BaselineDays != DefaultBaselineDays {
		t.Fatalf("tenant B reads %d, want the default: tenant A's window reached another tenant", gotB.BaselineDays)
	}

	if _, err := svc.Set(ctx, tenantB, uuid.Nil, 14); err != nil {
		t.Fatalf("Set B: %v", err)
	}
	gotA, err := svc.Get(ctx, tenantA)
	if err != nil {
		t.Fatalf("Get A: %v", err)
	}
	if gotA.BaselineDays != 120 {
		t.Errorf("tenant A's window changed to %d when tenant B wrote theirs", gotA.BaselineDays)
	}
}

// The FIRST save is audited.
//
// `log_tenant_admin_settings_change` is an AFTER **UPDATE** trigger reading
// OLD.config/OLD.version, so it cannot fire on an INSERT — a plain
// `INSERT … ON CONFLICT DO UPDATE` records NOTHING for a tenant who has never
// opened a settings page, and "nothing was recorded" and "nobody changed it"
// look identical afterwards.
//
// Both saves are asserted: a fix that audited only the second would pass a
// second-save assertion on its own.
func TestIntegration_DriftSettings_FirstSaveIsAudited(t *testing.T) {
	svc, db, tenant := newFixture(t)
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
	if _, err := svc.Set(ctx, tenant, uuid.Nil, 60); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if got := auditRows(); got != 1 {
		t.Fatalf("%d audit rows after the FIRST save, want 1", got)
	}
	if _, err := svc.Set(ctx, tenant, uuid.Nil, 90); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if got := auditRows(); got != 2 {
		t.Errorf("%d audit rows after the second save, want 2", got)
	}
}

// The producer and the settings page read the window through the SAME function,
// so the pass cannot use one value while the page shows another.
func TestIntegration_DriftSettings_ReadBaselineDaysTxAgreesWithGet(t *testing.T) {
	svc, db, tenant := newFixture(t)
	ctx := context.Background()

	if _, err := svc.Set(ctx, tenant, uuid.Nil, 75); err != nil {
		t.Fatalf("Set: %v", err)
	}
	var direct int
	err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
		var e error
		direct, e = ReadBaselineDaysTx(ctx, tx, tenant)
		return e
	})
	if err != nil {
		t.Fatalf("ReadBaselineDaysTx: %v", err)
	}
	got, err := svc.Get(ctx, tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if direct != got.BaselineDays || direct != 75 {
		t.Errorf("ReadBaselineDaysTx = %d, Get = %d, want 75 from both", direct, got.BaselineDays)
	}
}
