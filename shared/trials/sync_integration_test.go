package trials_test

// SyncPaymentStatus derives tenants.payment_status 'trial' from the one trial
// store (owner decision 6) against a real Postgres, as the application role
// inside a tenant-scoped transaction (billing_trial_tracking is RLS-policied):
//
//   - a live trial row on an is_trial plan makes an 'active' tenant 'trial';
//   - no row, a converted row, or a row on a plan that is not a trial plan
//     makes a 'trial' tenant 'active';
//   - suspended / canceled / past_due tenants are never touched.
//
// Mutation-checked: dropping the is_trial predicate or the converted_to_paid
// predicate from liveTrialExistsSQL, or the status guard, turns a case red.
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/trials"
)

func TestIntegration_SyncPaymentStatus_DerivesTrialFromTheTrialStore(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx := context.Background()

	mkTier := func(isTrial bool) uuid.UUID {
		var id uuid.UUID
		if err := owner.QueryRow(`INSERT INTO subscription_tiers (name, display_name, is_active, is_trial, trial_days_full, trial_days_soft)
			VALUES ($1, 'IT sync', true, $2, 14, 14) RETURNING id`, "it-sync-"+uuid.NewString()[:8], isTrial).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM subscription_tiers WHERE id = $1`, id) })
		return id
	}
	trialTier, paidTier := mkTier(true), mkTier(false)

	for _, tc := range []struct {
		name      string
		tier      uuid.UUID
		status    string
		row       bool
		converted bool
		want      string
	}{
		{"live trial on a trial plan", trialTier, "active", true, false, "trial"},
		{"already derived", trialTier, "trial", true, false, "trial"},
		{"no trial row", trialTier, "trial", false, false, "active"},
		{"converted trial", trialTier, "trial", true, true, "active"},
		{"row left on a paid plan", paidTier, "trial", true, false, "active"},
		{"row on a paid plan never makes a trial", paidTier, "active", true, false, "active"},
		{"suspended trialling tenant untouched", trialTier, "suspended", true, false, "suspended"},
		{"canceled tenant untouched", trialTier, "canceled", false, false, "canceled"},
		{"past_due tenant untouched", trialTier, "past_due", true, false, "past_due"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant := testdb.NewTenant(t, owner)
			if _, err := owner.Exec(`UPDATE tenants SET subscription_tier_id = $1, payment_status = $2 WHERE id = $3`, tc.tier, tc.status, tenant); err != nil {
				t.Fatal(err)
			}
			if tc.row {
				if _, err := owner.Exec(`INSERT INTO billing_trial_tracking (tenant_id, trial_start, trial_end, converted_to_paid)
					VALUES ($1, now(), now() + interval '28 days', $2)`, tenant, tc.converted); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM billing_trial_tracking WHERE tenant_id = $1`, tenant) })
			}
			if err := shareddatabase.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
				return trials.SyncPaymentStatus(ctx, tx, tenant)
			}); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := owner.QueryRow(`SELECT payment_status FROM tenants WHERE id = $1`, tenant).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("payment_status = %q, want %q", got, tc.want)
			}
		})
	}
}
