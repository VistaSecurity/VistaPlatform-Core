package api

// Contract test for the billing usage read (Settings → Billing / usage widget).
// Extends the auth-service spec-first contract (ADR-0001) and reuses the shared
// harness (loadSpec / assertConforms / do / aTenantID) from
// cross_cutter_contract_test.go.
//
// GetCurrentUsage was refactored onto the billingUsageStore interface via the
// GetCurrentUsageWithStore variant, so this test drives the real handler with an
// in-memory stub — no database.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

type stubBillingUsageStore struct {
	usage      UsageMetrics
	usageFound bool
	usageErr   error
	rtSensors  int
	rtAssets   int
	rtUsers    int
	apiCalls   int64
	limitsJSON []byte
	maxSensors sql.NullInt64
	maxAssets  sql.NullInt64
	maxUsers   sql.NullInt64
	limitsErr  error
	// resolvedLimits is what the entitlements resolver reports for
	// max_sensors / max_assets / max_users. A present key with a nil value is
	// "unlimited". nil map = resolver returned nothing.
	resolvedLimits    map[string]*int
	resolvedLimitsErr error
}

func (s *stubBillingUsageStore) GetTenantUsageRecord(_ context.Context, _ uuid.UUID, _, _ time.Time) (UsageMetrics, bool, error) {
	return s.usage, s.usageFound, s.usageErr
}

func (s *stubBillingUsageStore) GetRealtimeCounts(_ context.Context, _ uuid.UUID) (int, int, int) {
	return s.rtSensors, s.rtAssets, s.rtUsers
}

func (s *stubBillingUsageStore) GetCurrentMonthAPICalls(_ context.Context, _ uuid.UUID, _, _ time.Time) int64 {
	return s.apiCalls
}

func (s *stubBillingUsageStore) GetTenantTierLimits(_ context.Context, _ uuid.UUID) ([]byte, sql.NullInt64, sql.NullInt64, sql.NullInt64, error) {
	return s.limitsJSON, s.maxSensors, s.maxAssets, s.maxUsers, s.limitsErr
}

func (s *stubBillingUsageStore) ResolveNumericLimits(_ context.Context, _ uuid.UUID) (map[string]*int, error) {
	return s.resolvedLimits, s.resolvedLimitsErr
}

func newBillingEngine(store billingUsageStore, authenticated bool, tenantID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubBillingUsageStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", tenantID)
		}
		c.Next()
	})
	grp.GET("/billing/usage/current", GetCurrentUsageWithStore(store))
	grp.POST("/billing/check-limits", CheckLimitsWithStore(store))
	return r
}

func TestContract_GetCurrentUsage_200_recorded(t *testing.T) {
	sv := loadSpec(t)
	store := &stubBillingUsageStore{
		usage:      UsageMetrics{APIRequests: 100, StorageBytes: 2048, AssetsCount: 5, SensorsCount: 2, UsersCount: 3},
		usageFound: true,
		limitsJSON: []byte(`{"api_requests":1000,"storage_bytes":100000}`),
		maxSensors: sql.NullInt64{Int64: 10, Valid: true},
		maxAssets:  sql.NullInt64{Int64: 100, Valid: true},
		maxUsers:   sql.NullInt64{Int64: 20, Valid: true},
	}
	eng := newBillingEngine(store, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/billing/usage/current", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UsageInfo", w.Body.Bytes())
}

// No usage record -> realtime counts path; still a valid UsageInfo body.
func TestContract_GetCurrentUsage_200_realtime(t *testing.T) {
	sv := loadSpec(t)
	store := &stubBillingUsageStore{
		usageFound: false,
		rtSensors:  1, rtAssets: 4, rtUsers: 2,
		maxSensors: sql.NullInt64{Int64: 10, Valid: true},
	}
	eng := newBillingEngine(store, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/billing/usage/current", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UsageInfo", w.Body.Bytes())
}

func TestContract_GetCurrentUsage_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newBillingEngine(&stubBillingUsageStore{}, false, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/billing/usage/current", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCurrentUsage_500_usage(t *testing.T) {
	sv := loadSpec(t)
	eng := newBillingEngine(&stubBillingUsageStore{usageErr: errors.New("db down")}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/billing/usage/current", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCurrentUsage_500_limits(t *testing.T) {
	sv := loadSpec(t)
	eng := newBillingEngine(&stubBillingUsageStore{usageFound: true, limitsErr: errors.New("db down")}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/billing/usage/current", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- GET /tenant/billing ----------------------------------------------------

type stubTenantBillingStore struct {
	row     *tenantBillingRow
	err     error
	plan    *entitlements.Plan // nil = Core
	planErr error
}

func (s *stubTenantBillingStore) GetTenantBillingRow(_ context.Context, _ uuid.UUID) (*tenantBillingRow, error) {
	return s.row, s.err
}

func (s *stubTenantBillingStore) TenantPlan(context.Context, uuid.UUID) (entitlements.Plan, error) {
	if s.planErr != nil {
		return entitlements.Plan{}, s.planErr
	}
	if s.plan != nil {
		return *s.plan, nil
	}
	return entitlements.PlanFor(nil, time.Now(), entitlements.TenantPlanFacts{}), nil
}

func newTenantBillingEngine(store tenantBillingStore, authenticated bool, tenantID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubTenantBillingStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", tenantID)
		}
		c.Next()
	})
	grp.GET("/tenant/billing", GetTenantBillingWithStore(store, nil))
	return r
}

func sampleBillingRow() *tenantBillingRow {
	return &tenantBillingRow{
		TierID:             sql.NullString{String: uuid.NewString(), Valid: true},
		TierName:           sql.NullString{String: "pro", Valid: true},
		DisplayName:        sql.NullString{String: "Pro", Valid: true},
		PriceCents:         sql.NullInt64{Int64: 5000, Valid: true},
		BillingInterval:    sql.NullString{String: "month", Valid: true},
		FeaturesJSON:       []byte(`{"sso":true}`),
		LimitsJSON:         []byte(`{"max_assets":1000}`),
		SubscriptionStatus: sql.NullString{String: "active", Valid: true},
		CurrentPeriodStart: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		CurrentPeriodEnd:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
		CancelAtPeriodEnd:  sql.NullBool{Bool: false, Valid: true},
	}
}

func TestContract_GetTenantBilling_200_withTier(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantBillingEngine(&stubTenantBillingStore{row: sampleBillingRow()}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantBillingResponse", w.Body.Bytes())
}

// All-null row (onboarding, no tier) -> no `tier` key, default subscription.
func TestContract_GetTenantBilling_200_noTier(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantBillingEngine(&stubTenantBillingStore{row: &tenantBillingRow{}}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantBillingResponse", w.Body.Bytes())
}

// On Enterprise the tenant-facing billing read-out carries neither the
// placeholder tier's name nor a trial: the copy guard, for /tenant/billing.
func TestContract_GetTenantBilling_EnterpriseHidesTierAndTrial(t *testing.T) {
	sv := loadSpec(t)
	row := sampleBillingRow()
	row.TierName = sql.NullString{String: "community", Valid: true}
	row.DisplayName = sql.NullString{String: "Community", Valid: true}
	row.SubscriptionStatus = sql.NullString{String: "trialing", Valid: true}
	lic := &entitlements.License{Edition: entitlements.EditionEnterprise, Licensee: "Acme Corp", ExpiresAt: time.Now().Add(90 * 24 * time.Hour)}
	plan := entitlements.PlanFor(lic, time.Now(), entitlements.TenantPlanFacts{})
	eng := newTenantBillingEngine(&stubTenantBillingStore{row: row, plan: &plan}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantBillingResponse", w.Body.Bytes())
	lower := strings.ToLower(w.Body.String())
	for _, word := range []string{"community", "trial"} {
		if strings.Contains(lower, word) {
			t.Errorf("Enterprise /tenant/billing contains %q: %s", word, w.Body.String())
		}
	}
	if !strings.Contains(w.Body.String(), entitlements.PlanDisplayNameEnterprise) {
		t.Errorf("Enterprise /tenant/billing lacks the plan display name: %s", w.Body.String())
	}

	// MSP (and Core) keep the tier: it IS the plan there.
	mspLic := &entitlements.License{Edition: entitlements.EditionMSP, ExpiresAt: time.Now().Add(90 * 24 * time.Hour)}
	mspPlan := entitlements.PlanFor(mspLic, time.Now(), entitlements.TenantPlanFacts{TierDisplayName: "Pro"})
	w = do(newTenantBillingEngine(&stubTenantBillingStore{row: sampleBillingRow(), plan: &mspPlan}, true, aTenantID), http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"tier_name":"pro"`) {
		t.Errorf("MSP /tenant/billing = %d %s, want the tier name", w.Code, w.Body.String())
	}

	// An unreadable plan fails closed rather than falling back to the row.
	w = do(newTenantBillingEngine(&stubTenantBillingStore{row: row, planErr: context.DeadlineExceeded}, true, aTenantID), http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusInternalServerError || strings.Contains(strings.ToLower(w.Body.String()), "community") {
		t.Errorf("plan error: %d %s, want 500 without the row", w.Code, w.Body.String())
	}
}

func TestContract_GetTenantBilling_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantBillingEngine(&stubTenantBillingStore{}, false, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantBilling_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantBillingEngine(&stubTenantBillingStore{err: sql.ErrNoRows}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantBilling_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantBillingEngine(&stubTenantBillingStore{err: errors.New("db down")}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/billing", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- GET /tiers (public) ----------------------------------------------------

type stubTierStore struct {
	tiers   []tierRow
	err     error
	edition entitlements.Edition // "" = core
}

func (s *stubTierStore) ListActiveTiers(_ context.Context) ([]tierRow, error) {
	return s.tiers, s.err
}

func (s *stubTierStore) LicenseEdition(context.Context) (entitlements.Edition, error) {
	if s.edition == "" {
		return entitlements.EditionCore, nil
	}
	return s.edition, nil
}

func newTiersEngine(store tierStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubTierStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.GET("/tiers", getPublicTiersHandlerWithStore(store))
	return r
}

func TestContract_GetPublicTiers_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubTierStore{tiers: []tierRow{
		{ID: uuid.New(), Name: "free", DisplayName: "Free", BillingInterval: "month", PriceCents: sql.NullInt64{Int64: 0, Valid: true}, AnnualPriceCents: 0, IsActive: true},
		{ID: uuid.New(), Name: "pro", DisplayName: "Pro", BillingInterval: "month", PriceCents: sql.NullInt64{Int64: 5000, Valid: true}, AnnualPriceCents: 50000, IsActive: true, MaxSensors: sql.NullInt64{Int64: 10, Valid: true}, FeaturesJSON: []byte(`{"sso":true}`), LimitsJSON: []byte(`{"max_assets":1000}`)},
	}}
	eng := newTiersEngine(store)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tiers", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PublicTiersResponse", w.Body.Bytes())
}

func TestContract_GetPublicTiers_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newTiersEngine(&stubTierStore{})
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tiers", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PublicTiersResponse", w.Body.Bytes())
}

func TestContract_GetPublicTiers_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newTiersEngine(&stubTierStore{err: errors.New("db down")})
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tiers", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
