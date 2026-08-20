package services

// B-15(c): getSubscriptionInfo selected `st.tier` and
// `st.compliance_framework_limit` from subscription_tiers. NEITHER COLUMN
// EXISTS. Postgres errored on every call, the error was swallowed by a
// "default to free tier" branch, and every tenant on every plan was reported as
// tier "free" with a framework limit of 1 — Enterprise included.
//
// The regression test that matters is the first one: it asserts the tier NAME
// comes back, which is impossible if the query still names a column that does
// not exist.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type subInfoFixture struct {
	svc    *FrameworkContextService
	raw    *sqlx.DB
	tenant uuid.UUID
}

func newSubInfoFixture(t *testing.T) subInfoFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	return subInfoFixture{
		svc:    &FrameworkContextService{db: db},
		raw:    db,
		tenant: testdb.NewTenant(t, raw),
	}
}

// onTierWithFrameworkCap puts the fixture tenant on a fresh tier whose
// compliance_frameworks_max entitlement is `cap` (nil = unlimited).
func (f subInfoFixture) onTierWithFrameworkCap(t *testing.T, tierName string, cap *int) {
	t.Helper()
	tierID := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO subscription_tiers (id, name, display_name)
	                         VALUES ($1,$2,'Subscription Info Test Tier')`, tierID, tierName); err != nil {
		t.Fatalf("insert tier: %v", err)
	}
	value := `{"quantity": null}`
	if cap != nil {
		value = `{"quantity": ` + strconv.Itoa(*cap) + `}`
	}
	if _, err := f.raw.Exec(`INSERT INTO tier_entitlements (tier_id, item_id, included_value)
	                         SELECT $1, id, $2::jsonb FROM billable_items WHERE key = 'compliance_frameworks_max'`,
		tierID, value); err != nil {
		t.Fatalf("insert tier entitlement: %v", err)
	}
	if _, err := f.raw.Exec(`UPDATE tenants SET subscription_tier_id = $1 WHERE id = $2`, tierID, f.tenant); err != nil {
		t.Fatalf("assign tier: %v", err)
	}
}

func TestIntegration_GetSubscriptionInfo_ReportsTheRealTierAndCap(t *testing.T) {
	f := newSubInfoFixture(t)
	tierName := "sit-" + uuid.NewString()[:8]
	cap := 7
	f.onTierWithFrameworkCap(t, tierName, &cap)

	got := f.svc.getSubscriptionInfo(f.tenant, 3)

	if got.Tier != tierName {
		t.Errorf("tier = %q, want %q — reporting \"free\" for every tenant means the query "+
			"is erroring and the error is being swallowed", got.Tier, tierName)
	}
	if got.FrameworkLimit != cap {
		t.Errorf("framework_limit = %d, want %d (the enforced cap), not the hardcoded 1", got.FrameworkLimit, cap)
	}
	if !got.CanAddMore {
		t.Error("can_add_more = false with 0 of 7 chargeable frameworks used")
	}
}

func TestIntegration_GetSubscriptionInfo_UnlimitedCapIsNotOne(t *testing.T) {
	f := newSubInfoFixture(t)
	f.onTierWithFrameworkCap(t, "sit-"+uuid.NewString()[:8], nil) // unlimited

	got := f.svc.getSubscriptionInfo(f.tenant, 3)

	if got.FrameworkLimit != unlimitedFrameworkLimit {
		t.Errorf("framework_limit = %d, want %d (unlimited) — an Enterprise tenant was told "+
			"their limit was 1", got.FrameworkLimit, unlimitedFrameworkLimit)
	}
	if !got.CanAddMore {
		t.Error("can_add_more = false on an unlimited plan")
	}
}

func TestIntegration_GetSubscriptionInfo_ZeroCapCannotAddMore(t *testing.T) {
	f := newSubInfoFixture(t)
	zero := 0
	f.onTierWithFrameworkCap(t, "sit-"+uuid.NewString()[:8], &zero)

	got := f.svc.getSubscriptionInfo(f.tenant, 1)

	if got.FrameworkLimit != 0 {
		t.Errorf("framework_limit = %d, want 0", got.FrameworkLimit)
	}
	if got.CanAddMore {
		t.Error("can_add_more = true on a zero-cap plan — this disagrees with the 402 the " +
			"tenant would actually get")
	}
}
