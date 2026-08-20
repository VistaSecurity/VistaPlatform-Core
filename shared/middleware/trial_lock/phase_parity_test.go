package trial_lock_test

// B-16: the middleware's phase resolver read only four of the six columns the
// trial system needs — it omitted st.is_trial and btt.trial_end — so it locked
// tenants the /tenant/trial-status endpoint reported as phase "none".
//
// The two cases below are the exact production shapes that broke, and they are
// blind to the old bug in the existing tests because those always set
// trial_end = trial_start + 28d on a trial tier.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestPaidTierWithOrphanTrialRowIsNotLocked pins the "Assign plan" path: a
// tenant moved onto Pro through admin-ui (no Stripe webhook, so
// billing_trial_tracking is never cleaned up) whose old trial row is long past
// its lock date. Pro has is_trial = false and NULL trial_days_*, which the old
// resolver read as 0/0 — meaning ANY past trial_start resolved to PhaseLocked
// and every write returned 423.
func TestPaidTierWithOrphanTrialRowIsNotLocked(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	tenant := mkTenant(t, db, "pro")
	mkTrial(t, db, tenant, 60) // an ancient trial row that survived the tier change

	r := newRouter(db, tenant, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Fatalf("paid tenant with a stale trial row was locked out: got %d, want 200 "+
			"(the resolver must read st.is_trial)", w.Code)
	}
}

// TestNonTrialTierWithFreshTrialRowIsNotLocked is the POC-grant shape: an
// admin grants a trial row on a tier that is not configured as a trial. With
// trial_days_* NULL the tenant was locked the instant the row appeared.
func TestNonTrialTierWithFreshTrialRowIsNotLocked(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	tenant := mkTenant(t, db, "enterprise")
	mkTrial(t, db, tenant, 0) // granted just now

	r := newRouter(db, tenant, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Fatalf("non-trial tier locked on the day its trial was granted: got %d, want 200", w.Code)
	}
}

// TestExtendedTrialEndDelaysTheLock pins the extension path.
// TrialManager.ExtendTrial writes ONLY billing_trial_tracking.trial_end, so a
// resolver that never selects that column keeps 423-ing a tenant whose trial
// was extended and confirmed.
func TestExtendedTrialEndDelaysTheLock(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	tenant := mkTenant(t, db, "free") // is_trial, 14 full + 14 soft = locks at day 28
	mkTrial(t, db, tenant, 40)        // well past the tier-derived lock

	// Sanity: without the extension this tenant is locked.
	if w := do(newRouter(db, tenant, nil), http.MethodPost, "/api/v2/inventory-service/assets"); w.Code != http.StatusLocked {
		t.Fatalf("precondition: day-40 trial tenant should be locked, got %d", w.Code)
	}

	// An admin extends the trial another 10 days.
	extendTrialEnd(t, db, tenant, time.Now().Add(10*24*time.Hour))

	w := do(newRouter(db, tenant, nil), http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Fatalf("extended trial still locked: got %d, want 200 "+
			"(the resolver must read btt.trial_end)", w.Code)
	}
}

// extendTrialEnd mirrors what TrialManager.ExtendTrial writes: trial_end ONLY.
func extendTrialEnd(t *testing.T, db *sql.DB, tenantID uuid.UUID, newEnd time.Time) {
	t.Helper()
	if _, err := db.Exec(`UPDATE billing_trial_tracking SET trial_end = $2 WHERE tenant_id = $1`, tenantID, newEnd); err != nil {
		t.Fatalf("extend trial: %v", err)
	}
}
