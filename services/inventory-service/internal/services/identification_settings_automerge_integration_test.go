package services

// The rule-merge switch on the identification settings ( Phase 4, owner
// decision D1), against a real Postgres.
//
// What a unit test cannot say: that the switch DEFAULTS ON for a tenant with no
// row, that writing ONE of the two settings leaves the other alone (in both
// directions), that the first save is audited, and that it survives beside the
// other keys in the shared `tenant_admin_settings.config` document.
//
// MUTATIONS (recorded in the PR):
//   - build the identity patch with the threshold ALWAYS (a nil becomes 0): the
//     toggle-only test fails, because flipping the switch zeroes auto-accept;
//   - build it with the switch ALWAYS (a nil becomes false): the
//     threshold-only test fails, because moving the threshold turns the rule off;
//   - flip DefaultAutoMergeExisting to false: the default test fails;
//   - replace the two-statement seed+UPDATE with a bare upsert: the first-save
//     audit test fails.
//
// Skips without TEST_DATABASE_URL.

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

func floatPtr(f float64) *float64 { return &f }

func newTenantFor(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	return testdb.NewTenant(t, db.DB.DB)
}

func storedConfig(t *testing.T, db *database.DB, tenant uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(context.Background(),
			`SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenant).Scan(&raw)
	})
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("decode config %s: %v", raw, err)
	}
	return config
}

func TestIntegration_IdentificationSettings_AutoMergeDefaultsOn(t *testing.T) {
	svc, _, tenant := newIdentificationSettingsFixture(t)

	got, err := svc.Get(context.Background(), tenant)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.AutoMergeExisting {
		t.Error("a tenant with no settings row reads auto_merge_existing = false: owner decision D1 is default ON")
	}
	// And the threshold's default is the OPPOSITE one, on the same read.
	if got.AutoAcceptThreshold != 0 {
		t.Errorf("threshold = %v, want 0 (never)", got.AutoAcceptThreshold)
	}
}

func TestIntegration_IdentificationSettings_AutoMergeRoundTrips(t *testing.T) {
	svc, _, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	off, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(false)})
	if err != nil {
		t.Fatalf("Update off: %v", err)
	}
	if off.AutoMergeExisting || off.Version < 1 {
		t.Fatalf("Update returned %+v, want the switch OFF at version >= 1", off)
	}
	if got, _ := svc.Get(ctx, tenant); got.AutoMergeExisting {
		t.Error("Get reads the switch ON after it was turned off")
	}

	on, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(true)})
	if err != nil {
		t.Fatalf("Update on: %v", err)
	}
	if !on.AutoMergeExisting {
		t.Fatalf("Update returned %+v, want the switch ON", on)
	}
	if got, _ := svc.Get(ctx, tenant); !got.AutoMergeExisting {
		t.Error("Get reads the switch OFF after it was turned back on")
	}
}

// Direction one: flipping the toggle must not touch the threshold.
func TestIntegration_IdentificationSettings_ToggleOnlyLeavesTheThreshold(t *testing.T) {
	svc, db, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	if _, err := svc.Set(ctx, tenant, uuid.Nil, 0.9); err != nil {
		t.Fatalf("Set: %v", err)
	}
	out, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(false)})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if out.AutoAcceptThreshold != 0.9 {
		t.Errorf("the response says threshold = %v after a toggle-only write, want the stored 0.9", out.AutoAcceptThreshold)
	}
	got, _ := svc.Get(ctx, tenant)
	if got.AutoAcceptThreshold != 0.9 || got.AutoMergeExisting {
		t.Errorf("Get = %+v, want threshold 0.9 and the switch off", got)
	}
	identity, _ := storedConfig(t, db, tenant)["identity"].(map[string]any)
	if identity["auto_accept_threshold"] != 0.9 || identity["auto_merge_existing"] != false {
		t.Errorf("stored identity block = %v, want both keys", identity)
	}
}

// Direction two: moving the threshold must not touch the toggle — including
// when the toggle is OFF, which is the state a stray write would silently undo.
func TestIntegration_IdentificationSettings_ThresholdOnlyLeavesTheToggle(t *testing.T) {
	svc, _, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	if _, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(false)}); err != nil {
		t.Fatalf("Update off: %v", err)
	}
	out, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoAcceptThreshold: floatPtr(0.8)})
	if err != nil {
		t.Fatalf("Update threshold: %v", err)
	}
	if out.AutoMergeExisting {
		t.Error("moving the threshold turned the rule merge back on")
	}
	// The legacy wrapper is threshold-only too.
	if _, err := svc.Set(ctx, tenant, uuid.Nil, 0.95); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, _ := svc.Get(ctx, tenant)
	if got.AutoMergeExisting || got.AutoAcceptThreshold != 0.95 {
		t.Errorf("Get = %+v, want the switch still off and threshold 0.95", got)
	}
}

// The other way round, and the one that matters MOST for a default-ON switch:
// a tenant who has only ever touched the threshold must still have the rule
// merge ON afterwards — and the key must stay ABSENT, so a later change to the
// default reaches them. A write that stored `false` for "not sent" would
// silently switch the rule off for every tenant who moves the threshold.
func TestIntegration_IdentificationSettings_ThresholdWriteDoesNotTouchAnAbsentSwitch(t *testing.T) {
	svc, db, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	out, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoAcceptThreshold: floatPtr(0.9)})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !out.AutoMergeExisting {
		t.Error("moving the threshold turned the default-ON rule merge OFF")
	}
	identity, _ := storedConfig(t, db, tenant)["identity"].(map[string]any)
	if _, written := identity["auto_merge_existing"]; written {
		t.Errorf("a threshold-only write stored auto_merge_existing = %v; an unsent field must stay absent", identity["auto_merge_existing"])
	}
	if got, _ := svc.Get(ctx, tenant); !got.AutoMergeExisting || got.AutoAcceptThreshold != 0.9 {
		t.Errorf("Get = %+v, want the switch on and threshold 0.9", got)
	}
}

// Both in one write is one version bump, and an explicit zero/false is honoured.
func TestIntegration_IdentificationSettings_BothFieldsInOneWrite(t *testing.T) {
	svc, _, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	first, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{
		AutoAcceptThreshold: floatPtr(0.7), AutoMergeExisting: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{
		AutoAcceptThreshold: floatPtr(0), AutoMergeExisting: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != first.Version+1 {
		t.Errorf("versions %d -> %d; one write must be one bump", first.Version, second.Version)
	}
	if second.AutoAcceptThreshold != 0 || second.AutoMergeExisting {
		t.Errorf("explicit 0/false were not honoured: %+v", second)
	}
}

func TestIntegration_IdentificationSettings_EmptyUpdateIsRefused(t *testing.T) {
	svc, db, tenant := newIdentificationSettingsFixture(t)
	if _, err := svc.Update(context.Background(), tenant, uuid.Nil, IdentificationSettingsUpdate{}); !errors.Is(err, ErrEmptyIdentificationUpdate) {
		t.Fatalf("an update naming no field returned %v, want ErrEmptyIdentificationUpdate", err)
	}
	// Refused BEFORE it wrote anything: no row, so nothing to audit or bump.
	var n int
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(context.Background(), `SELECT count(*) FROM tenant_admin_settings WHERE tenant_id = $1`, tenant).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a refused update still created %d settings rows", n)
	}
}

// The toggle sits beside the other keys of the shared config document, and
// beside an `identity` value that is not even an object.
func TestIntegration_IdentificationSettings_AutoMergePreservesOtherKeys(t *testing.T) {
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
	if _, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(false)}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	config := storedConfig(t, db, tenant)
	if policy, ok := config["discovery_auto_scan"].(map[string]any); !ok || policy["enabled"] != false {
		t.Errorf("discovery_auto_scan was clobbered by the toggle write: %v", config)
	}
	if config["onboarding_required"] != true {
		t.Errorf("onboarding_required was clobbered by the toggle write: %v", config)
	}
	if identity, ok := config["identity"].(map[string]any); !ok || identity["auto_merge_existing"] != false {
		t.Errorf("the toggle did not land (jsonb_set's silent no-op on a missing parent): %v", config)
	}

	// An `identity` that is not an object is replaced by one, not concatenated
	// into an array.
	tenant2 := newTenantFor(t, db)
	err = database.WithTenantTx(ctx, db, tenant2, func(tx *sqlx.Tx) error {
		_, e := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
			VALUES ($1, '{"identity":"junk"}'::jsonb, 1, NOW(), NOW())`, tenant2)
		return e
	})
	if err != nil {
		t.Fatalf("seed junk identity: %v", err)
	}
	if _, err := svc.Update(ctx, tenant2, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(false)}); err != nil {
		t.Fatalf("Update over a non-object identity: %v", err)
	}
	if identity, ok := storedConfig(t, db, tenant2)["identity"].(map[string]any); !ok || identity["auto_merge_existing"] != false {
		t.Errorf("a non-object identity value was not replaced by an object")
	}
}

// RLS: one tenant turning the rule OFF must not turn it off for another.
func TestIntegration_IdentificationSettings_AutoMergeIsPerTenant(t *testing.T) {
	svc, db, tenantA := newIdentificationSettingsFixture(t)
	ctx := context.Background()
	tenantB := newTenantFor(t, db)

	if _, err := svc.Update(ctx, tenantA, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.Get(ctx, tenantB); !got.AutoMergeExisting {
		t.Error("tenant B reads the rule merge OFF because tenant A turned it off")
	}
	if got, _ := svc.Get(ctx, tenantA); got.AutoMergeExisting {
		t.Error("tenant A reads it ON after turning it off")
	}
}

// The FIRST save is audited when it writes the toggle — the save that switches
// an unattended act OFF (or, first, back to its default) is exactly one a
// reviewer will want to find. Both saves are asserted, and the audit row's
// after-image carries the key.
func TestIntegration_IdentificationSettings_AutoMergeSaveIsAudited(t *testing.T) {
	svc, db, tenant := newIdentificationSettingsFixture(t)
	ctx := context.Background()

	type auditRow struct {
		before, after []byte
		vBefore, vAft int
	}
	rows := func() []auditRow {
		t.Helper()
		var out []auditRow
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
			rs, err := tx.QueryContext(ctx, `
				SELECT COALESCE(config_before,'{}'::jsonb), config_after, version_before, version_after
				FROM tenant_admin_settings_audit WHERE tenant_id = $1 ORDER BY created_at, version_after`, tenant)
			if err != nil {
				return err
			}
			defer func() { _ = rs.Close() }()
			for rs.Next() {
				var r auditRow
				if err := rs.Scan(&r.before, &r.after, &r.vBefore, &r.vAft); err != nil {
					return err
				}
				out = append(out, r)
			}
			return rs.Err()
		})
		if err != nil {
			t.Fatalf("read audit rows: %v", err)
		}
		return out
	}

	if _, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(false)}); err != nil {
		t.Fatalf("first Update: %v", err)
	}
	got := rows()
	if len(got) != 1 {
		t.Fatalf("the first toggle save wrote %d audit rows, want 1", len(got))
	}
	var after map[string]map[string]any
	if err := json.Unmarshal(got[0].after, &after); err != nil {
		t.Fatalf("decode config_after %s: %v", got[0].after, err)
	}
	if after["identity"]["auto_merge_existing"] != false {
		t.Errorf("config_after = %s; the audit trail does not record the switch going off", got[0].after)
	}
	var before map[string]any
	_ = json.Unmarshal(got[0].before, &before)
	if _, had := before["identity"]; had {
		t.Errorf("config_before = %s; a tenant with no settings row honestly had no identity block", got[0].before)
	}

	if _, err := svc.Update(ctx, tenant, uuid.Nil, IdentificationSettingsUpdate{AutoMergeExisting: boolPtr(true)}); err != nil {
		t.Fatalf("second Update: %v", err)
	}
	if got := rows(); len(got) != 2 {
		t.Errorf("after two toggle saves there are %d audit rows, want 2", len(got))
	}
}
