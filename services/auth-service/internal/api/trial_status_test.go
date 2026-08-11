package api

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/trials"
)

// Integration tests for the trial-status resolver. They prove that the
// joined SQL query against tenants + subscription_tiers +
// billing_trial_tracking lines up with the shared/trials.Compute
// contract. Skips when TEST_DATABASE_URL isn't set so `make test-unit`
// stays green without docker.

const trialStatusSkip = "TEST_DATABASE_URL not set; skipping DB-backed trial-status tests"

func openTrialStatusDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip(trialStatusSkip)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test db: %v", err)
	}
	return db
}

// applyTrialSchemaAndSeed delegates to the shared harness (advisory-lock
// serialized — concurrent appliers hit "tuple concurrently updated").
func applyTrialSchemaAndSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	testdb.ApplySchemaAndSeed(t, db)
}

// mkTenantOnTier inserts a tenant assigned to the named tier and
// returns its UUID. Slugs follow the lowercase-hyphen CHECK on tenants.
func mkTenantOnTier(t *testing.T, db *sql.DB, tier string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "ts-" + id.String()[:8]
	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name=$4), NOW(), NOW())
	`, id, slug, slug, tier)
	if err != nil {
		t.Fatalf("create tenant on %s: %v", tier, err)
	}
	return id
}

// mkTrialRow inserts a billing_trial_tracking row anchored at the
// given trial_start. trialEnd is computed from totalDays so the
// existing day-7/day-1 nudge logic has a plausible target.
func mkTrialRow(t *testing.T, db *sql.DB, tenantID uuid.UUID, trialStart time.Time, totalDays int) {
	t.Helper()
	trialEnd := trialStart.Add(time.Duration(totalDays) * 24 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO billing_trial_tracking (tenant_id, trial_start, trial_end, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, tenantID, trialStart, trialEnd)
	if err != nil {
		t.Fatalf("insert trial: %v", err)
	}
}

func TestResolveTrialStatus_FreeTierFullPhase(t *testing.T) {
	db := openTrialStatusDB(t)
	applyTrialSchemaAndSeed(t, db)

	tenant := mkTenantOnTier(t, db, "free")
	trialStart := time.Now().Add(-3 * 24 * time.Hour) // day 3 of trial
	mkTrialRow(t, db, tenant, trialStart, 28)

	resp := resolveTrialStatus(db, tenant, time.Now())
	if resp.Phase != trials.PhaseFull {
		t.Errorf("Phase = %s, want %s", resp.Phase, trials.PhaseFull)
	}
	if resp.DaysRemaining != 10 {
		// day 3 of 14-day full → 10 floor (with sub-day clock skew)
		t.Logf("DaysRemaining = %d (expected ~10–11 depending on second-level clock drift)", resp.DaysRemaining)
		if resp.DaysRemaining < 9 || resp.DaysRemaining > 11 {
			t.Errorf("DaysRemaining = %d, want 9-11", resp.DaysRemaining)
		}
	}
	if resp.TrialStart == nil {
		t.Error("TrialStart should be populated")
	}
	if resp.TrialDaysFull == nil || *resp.TrialDaysFull != 14 {
		t.Errorf("TrialDaysFull = %v, want 14", resp.TrialDaysFull)
	}
}

func TestResolveTrialStatus_FreeTierSoftPromptPhase(t *testing.T) {
	db := openTrialStatusDB(t)
	applyTrialSchemaAndSeed(t, db)

	tenant := mkTenantOnTier(t, db, "free")
	trialStart := time.Now().Add(-20 * 24 * time.Hour) // day 20 → soft_prompt
	mkTrialRow(t, db, tenant, trialStart, 28)

	resp := resolveTrialStatus(db, tenant, time.Now())
	if resp.Phase != trials.PhaseSoftPrompt {
		t.Errorf("Phase = %s, want %s", resp.Phase, trials.PhaseSoftPrompt)
	}
}

func TestResolveTrialStatus_FreeTierLockedPhase(t *testing.T) {
	db := openTrialStatusDB(t)
	applyTrialSchemaAndSeed(t, db)

	tenant := mkTenantOnTier(t, db, "free")
	trialStart := time.Now().Add(-30 * 24 * time.Hour) // day 30 → locked
	mkTrialRow(t, db, tenant, trialStart, 28)

	resp := resolveTrialStatus(db, tenant, time.Now())
	if resp.Phase != trials.PhaseLocked {
		t.Errorf("Phase = %s, want %s", resp.Phase, trials.PhaseLocked)
	}
	if resp.DaysRemaining != 0 {
		t.Errorf("DaysRemaining = %d, want 0 in locked phase", resp.DaysRemaining)
	}
}

func TestResolveTrialStatus_PaidTierIsNone(t *testing.T) {
	db := openTrialStatusDB(t)
	applyTrialSchemaAndSeed(t, db)

	// Pro tenants don't have trial rows (BootstrapTrialIfApplicable
	// skips them). The resolver should report PhaseNone.
	tenant := mkTenantOnTier(t, db, "pro")

	resp := resolveTrialStatus(db, tenant, time.Now())
	if resp.Phase != trials.PhaseNone {
		t.Errorf("Phase = %s, want %s for Pro tenant with no trial row", resp.Phase, trials.PhaseNone)
	}
}

func TestResolveTrialStatus_PaidTierOrphanTrialRowIsNone(t *testing.T) {
	db := openTrialStatusDB(t)
	applyTrialSchemaAndSeed(t, db)

	tenant := mkTenantOnTier(t, db, "pro")
	trialStart := time.Now().Add(-60 * 24 * time.Hour)
	mkTrialRow(t, db, tenant, trialStart, 28)

	resp := resolveTrialStatus(db, tenant, time.Now())
	if resp.Phase != trials.PhaseNone {
		t.Errorf("Phase = %s, want none for paying tenant with stray trial row", resp.Phase)
	}
	if resp.DaysRemaining != 0 {
		t.Errorf("DaysRemaining = %d, want 0", resp.DaysRemaining)
	}
}

func TestResolveTrialStatus_ExtendedTrialEndDelaysHardLock(t *testing.T) {
	db := openTrialStatusDB(t)
	applyTrialSchemaAndSeed(t, db)

	tenant := mkTenantOnTier(t, db, "free")
	trialStart := time.Now().Add(-29 * 24 * time.Hour) // calendar past tier-derived lock ...
	mkTrialRow(t, db, tenant, trialStart, 28)

	extEnd := time.Now().Add(10 * 24 * time.Hour)
	_, err := db.Exec(`
		UPDATE billing_trial_tracking
		SET trial_end = $2, updated_at = NOW()
		WHERE tenant_id = $1
	`, tenant, extEnd)
	if err != nil {
		t.Fatalf("extend trial_end: %v", err)
	}

	resp := resolveTrialStatus(db, tenant, time.Now())
	if resp.Phase != trials.PhaseSoftPrompt {
		t.Errorf("Phase = %s, want soft_prompt when trial_end was extended past tier lock", resp.Phase)
	}
}

func TestResolveTrialStatus_ConvertedTrumpsClock(t *testing.T) {
	db := openTrialStatusDB(t)
	applyTrialSchemaAndSeed(t, db)

	tenant := mkTenantOnTier(t, db, "free")
	trialStart := time.Now().Add(-20 * 24 * time.Hour)
	mkTrialRow(t, db, tenant, trialStart, 28)

	_, err := db.Exec(`
		UPDATE billing_trial_tracking
		SET converted_to_paid = true, converted_at = NOW()
		WHERE tenant_id = $1
	`, tenant)
	if err != nil {
		t.Fatalf("mark converted: %v", err)
	}

	resp := resolveTrialStatus(db, tenant, time.Now())
	if resp.Phase != trials.PhaseConverted {
		t.Errorf("Phase = %s, want %s for converted trial", resp.Phase, trials.PhaseConverted)
	}
}
