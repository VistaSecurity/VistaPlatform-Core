package auth

// Database-integration tests for the default tier a self-signup tenant lands
// on. Skips unless TEST_DATABASE_URL is set (see shared/testdb); run with
// `make test-integration-db`.
//
// These need a real Postgres because the whole defect lived in the interaction
// between three real things: the tenants row auth-service writes, the seeded
// subscription_tiers / tier_entitlements / billable_items catalog, and the
// resolver SQL that COALESCEs override → tier → default. A mocked test would
// have asserted whatever shape we believed, which is exactly what shipped: a
// tenant created with subscription_tier_id NULL resolved max_sensors to the
// catalog default of 0, so `POST /sensors/register` answered
// 402 "Sensor limit exceeded: 0/0" and a fresh Core install could not collect
// any data at all.

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newSignupTenant runs the real tenant-creation path a self-signup takes
// (Register → createTenant, and CreateTenantPublic for social signup) and
// returns the new tenant id.
func newSignupTenant(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	auth := makeAuthForTest(db)
	tenant, err := auth.createTenant("Signup Co " + uuid.NewString()[:8])
	if err != nil {
		t.Fatalf("createTenant: %v", err)
	}
	return tenant.ID
}

func tierNameOf(t *testing.T, db *sql.DB, tenantID uuid.UUID) string {
	t.Helper()
	var name sql.NullString
	err := db.QueryRow(`
		SELECT st.name
		FROM tenants t
		LEFT JOIN subscription_tiers st ON st.id = t.subscription_tier_id
		WHERE t.id = $1
	`, tenantID).Scan(&name)
	if err != nil {
		t.Fatalf("look up tenant tier: %v", err)
	}
	if !name.Valid {
		return ""
	}
	return name.String
}

// The regression the launch blocker asked for: a freshly signed-up tenant must
// be able to register a sensor. Sensors are the primary collection path, so
// this failing means the product does not work out of the box.
func TestIntegration_SelfSignupTenant_CanRegisterSensor(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenantID := newSignupTenant(t, db)

	if got := tierNameOf(t, db, tenantID); got != DefaultSignupTierName {
		t.Fatalf("new signup tenant is on tier %q, want %q", got, DefaultSignupTierName)
	}

	limits := sharedservices.NewLimitEnforcementService(db)
	result, err := limits.CheckSensorLimit(tenantID)
	if err != nil {
		t.Fatalf("CheckSensorLimit: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("fresh signup tenant cannot register a sensor: %s (limit=%v)", result.Message, result.Limit)
	}
}

// The 402 path is shared across capacity gates, so the same NULL-tier state
// broke assets and users too. Assert every cap a new tenant needs on day one.
func TestIntegration_SelfSignupTenant_CapacityLimitsUsable(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenantID := newSignupTenant(t, db)
	limits := sharedservices.NewLimitEnforcementService(db)

	assets, err := limits.CheckAssetLimit(tenantID, 1)
	if err != nil {
		t.Fatalf("CheckAssetLimit: %v", err)
	}
	if !assets.Allowed {
		t.Errorf("fresh signup tenant cannot add an asset: %s", assets.Message)
	}

	// Bulk import is a separate call site with its own additionalCount.
	bulk, err := limits.CheckAssetLimit(tenantID, 500)
	if err != nil {
		t.Fatalf("CheckAssetLimit(500): %v", err)
	}
	if !bulk.Allowed {
		t.Errorf("fresh signup tenant cannot bulk-import 500 assets: %s", bulk.Message)
	}

	users, err := limits.CheckUserLimit(tenantID)
	if err != nil {
		t.Fatalf("CheckUserLimit: %v", err)
	}
	if !users.Allowed {
		t.Errorf("fresh signup tenant cannot invite a user: %s", users.Message)
	}
}

// DEFAULT_SIGNUP_TIER is the escape hatch for a commercial multi-tenant SaaS,
// which wants signups on the trial tier rather than the community floor.
func TestIntegration_DefaultSignupTierEnvOverride(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	t.Setenv("DEFAULT_SIGNUP_TIER", "free")
	tenantID := newSignupTenant(t, db)

	if got := tierNameOf(t, db, tenantID); got != "free" {
		t.Fatalf("with DEFAULT_SIGNUP_TIER=free, tenant is on tier %q, want \"free\"", got)
	}

	// And the free tier's caps really do bite — proving the override selects a
	// different plan rather than being cosmetic.
	limits := sharedservices.NewLimitEnforcementService(db)
	result, err := limits.CheckAssetLimit(tenantID, 5000)
	if err != nil {
		t.Fatalf("CheckAssetLimit: %v", err)
	}
	if result.Allowed {
		t.Error("free tier allowed 5000 assets; expected the tier cap to deny")
	}
}

// An unknown DEFAULT_SIGNUP_TIER must not fail signup — a typo in one env var
// should not make the platform unable to create accounts. The tenant lands
// tier-less (the pre-fix state), which the deny message now names explicitly.
func TestIntegration_UnknownDefaultSignupTier_DoesNotFailSignup(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	t.Setenv("DEFAULT_SIGNUP_TIER", "no-such-tier")
	tenantID := newSignupTenant(t, db)

	if got := tierNameOf(t, db, tenantID); got != "" {
		t.Fatalf("tenant is on tier %q, want none", got)
	}

	limits := sharedservices.NewLimitEnforcementService(db)
	result, err := limits.CheckSensorLimit(tenantID)
	if err != nil {
		t.Fatalf("CheckSensorLimit: %v", err)
	}
	if result.Allowed {
		t.Fatal("tier-less tenant was allowed a sensor; capacity caps must fail closed")
	}
	if want := "no subscription tier assigned"; !strings.Contains(result.Message, want) {
		t.Errorf("denial message = %q, want it to mention %q", result.Message, want)
	}
}

// Tenants created before the fix are already sitting at NULL, and no signup
// path revisits them — seed.sql's backfill is the only thing that repairs an
// existing install on the next helm upgrade. Asserts it fills NULLs and, just
// as importantly, does not move a tenant off a tier someone chose.
func TestIntegration_SeedBackfillsTierLessTenants(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tierLess := testdb.NewTenant(t, db)
	if _, err := db.Exec(`UPDATE tenants SET subscription_tier_id = NULL WHERE id = $1`, tierLess); err != nil {
		t.Fatalf("clear tier: %v", err)
	}
	onPro := testdb.NewTenant(t, db)
	if _, err := db.Exec(`
		UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'pro') WHERE id = $1
	`, onPro); err != nil {
		t.Fatalf("assign pro tier: %v", err)
	}

	testdb.ApplySchemaAndSeed(t, db)

	if got := tierNameOf(t, db, tierLess); got != "community" {
		t.Errorf("tier-less tenant after seed = %q, want \"community\"", got)
	}
	if got := tierNameOf(t, db, onPro); got != "pro" {
		t.Errorf("seed moved a tenant off its tier: %q, want \"pro\"", got)
	}
}

// Guard against the env var leaking between packages in a shared test process.
func TestMain(m *testing.M) {
	if err := os.Unsetenv("DEFAULT_SIGNUP_TIER"); err != nil {
		panic("unset DEFAULT_SIGNUP_TIER: " + err.Error())
	}
	os.Exit(m.Run())
}
