package api

// The plan block on GET /tenant/features and the Enterprise presentation of
// the other tenant-facing plan surfaces (edition-licensing spec PR 2), over
// stubs so they run on every PR. The DB-backed half — the real resolver,
// licence row and switched-off override — is
// tenant_features_plan_integration_test.go.
//
// Mutations run against these tests (each turns one red):
//   - drop resp["plan"] from newTenantFeaturesHandler      → plan cases
//   - GetMe serialises the raw models.Tenant again         → /auth/me copy guard
//   - drop resp["plan"] from GetMe                         → /auth/me plan cases
//   - GetFeatureAvailability keeps the tier name on Enterprise → availability case
//   - /tiers ignores the licence edition                    → catalogue case

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

func stubPlan(p entitlements.Plan) tenantPlanResolver {
	return func(context.Context, uuid.UUID) (entitlements.Plan, error) { return p, nil }
}

func enterprisePlan() entitlements.Plan {
	licensee := "Acme Corp"
	exp := time.Now().Add(100 * 24 * time.Hour)
	return entitlements.Plan{Edition: entitlements.EditionEnterprise, DisplayName: entitlements.PlanDisplayNameEnterprise, Licensee: &licensee, ExpiresAt: &exp}
}

func TestContract_TenantFeatures_PlanBlock(t *testing.T) {
	sv := loadSpec(t)
	ends := time.Now().Add(7 * 24 * time.Hour)
	for _, tc := range []struct {
		name string
		plan entitlements.Plan
	}{
		{"core", entitlements.Plan{Edition: entitlements.EditionCore, DisplayName: entitlements.PlanDisplayNameCore}},
		{"enterprise", enterprisePlan()},
		{"msp trial", entitlements.Plan{Edition: entitlements.EditionMSP, DisplayName: "Starter", Trial: &entitlements.PlanTrial{EndsAt: ends}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := crossCutterEngineWithPlan(stubPlan(tc.plan))
			w := do(eng, "GET", "/api/v1/auth-service/tenant/features", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "FeaturesResponse", w.Body.Bytes())
			var resp struct {
				Plan *entitlements.Plan `json:"plan"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp.Plan == nil || resp.Plan.DisplayName != tc.plan.DisplayName || (resp.Plan.Trial != nil) != (tc.plan.Trial != nil) {
				t.Fatalf("plan = %+v, want %+v", resp.Plan, tc.plan)
			}
			if tc.plan.Edition == entitlements.EditionEnterprise {
				lower := strings.ToLower(w.Body.String())
				for _, word := range []string{"community", "trial"} {
					if strings.Contains(lower, word) {
						t.Errorf("Enterprise /tenant/features contains %q: %s", word, w.Body.String())
					}
				}
			}
		})
	}

	// A failed plan lookup omits the block; the flags still answer.
	eng := crossCutterEngineWithPlan(func(context.Context, uuid.UUID) (entitlements.Plan, error) {
		return entitlements.Plan{}, errors.New("db down")
	})
	w := do(eng, "GET", "/api/v1/auth-service/tenant/features", nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"plan"`) {
		t.Fatalf("plan failure = %d %s, want 200 without a plan key", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FeaturesResponse", w.Body.Bytes())
}

func crossCutterEngineWithPlan(plans tenantPlanResolver) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("userID", uuid.NewString())
		c.Set("tenantID", uuid.NewString())
		c.Next()
	})
	grp.GET("/tenant/features", newTenantFeaturesHandler(&stubLimitChecker{}, plans))
	return r
}

func TestFeatureAvailability_EnterpriseHidesTheTier(t *testing.T) {
	store := &stubFeatureAvailabilityStore{tier: "community", caps: map[string]*int{}, plan: enterprisePlan()}
	w := do(featureAvailabilityEngine(store, &stubFeatureChecker{}, true), "GET", "/api/v1/auth-service/features/availability", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "community") {
		t.Errorf("Enterprise availability names the tier: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), entitlements.PlanDisplayNameEnterprise) {
		t.Errorf("availability tier = %s, want the plan display name", w.Body.String())
	}
	// Core keeps the tier name, unchanged.
	store.plan = entitlements.Plan{}
	w = do(featureAvailabilityEngine(store, &stubFeatureChecker{}, true), "GET", "/api/v1/auth-service/features/availability", nil)
	if !strings.Contains(w.Body.String(), `"tier":"community"`) {
		t.Errorf("Core availability = %s, want the tier name", w.Body.String())
	}
}

func TestContract_PublicTiers_EnterpriseHasNoCatalogue(t *testing.T) {
	sv := loadSpec(t)
	store := &stubTierStore{tiers: []tierRow{
		{ID: uuid.New(), Name: "free", DisplayName: "Free", BillingInterval: "month", PriceCents: sql.NullInt64{Valid: true}, IsActive: true},
	}}
	w := do(newTiersEngine(store), "GET", "/api/v1/auth-service/tiers", nil)
	if !strings.Contains(w.Body.String(), `"free"`) {
		t.Fatalf("Core catalogue = %s, want the tier listed", w.Body.String())
	}
	store.edition = entitlements.EditionEnterprise
	w = do(newTiersEngine(store), "GET", "/api/v1/auth-service/tiers", nil)
	if w.Code != http.StatusOK || w.Body.String() != `{"tiers":[]}` {
		t.Fatalf("Enterprise catalogue = %d %s, want an empty list", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PublicTiersResponse", w.Body.Bytes())
}

// The production repository really implements the licence read the handlers
// branch on (a stub-only method would make the Enterprise branch dead code).
var (
	_ tierStore                = (*billingRepository)(nil)
	_ featureAvailabilityStore = (*billingRepository)(nil)
)

// GET /auth/me presents the tenant through the plan block, not the raw
// billing columns: on an Enterprise install a tenant row still reading
// payment_status 'trial' with a trial_ends_at (what signup used to write, and
// what the reconciler corrects only on its next pass) must not surface as a
// trial. The copy guard, extended to /auth/me.
func TestContract_GetMe_PlanBlockAndCopyGuard(t *testing.T) {
	sv := loadSpec(t)
	uid, tid := uuid.MustParse(aUserID), uuid.MustParse(aTenantID)
	ends := time.Now().Add(7 * 24 * time.Hour)
	for _, tc := range []struct {
		name string
		plan entitlements.Plan
	}{
		{"core", entitlements.Plan{Edition: entitlements.EditionCore, DisplayName: entitlements.PlanDisplayNameCore}},
		{"enterprise", enterprisePlan()},
		{"msp trial", entitlements.Plan{Edition: entitlements.EditionMSP, DisplayName: "Starter", Trial: &entitlements.PlanTrial{EndsAt: ends}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant := sampleTenant(tid)
			tenant.PaymentStatus = "trial"
			tenant.TrialEndsAt = &ends
			eng := meEngine(&stubAuthServiceStore{userResult: sampleUser(uid, tid), tenantResult: tenant}, stubPlan(tc.plan))
			w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "MeResponse", w.Body.Bytes())
			var resp struct {
				Tenant map[string]any     `json:"tenant"`
				Plan   *entitlements.Plan `json:"plan"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Plan == nil || resp.Plan.DisplayName != tc.plan.DisplayName || (resp.Plan.Trial != nil) != (tc.plan.Trial != nil) {
				t.Fatalf("plan = %+v, want %+v", resp.Plan, tc.plan)
			}
			for _, raw := range []string{"payment_status", "trial_ends_at"} {
				if _, ok := resp.Tenant[raw]; ok {
					t.Errorf("tenant carries the raw billing column %q: %s", raw, w.Body.String())
				}
			}
			if resp.Tenant["name"] != tenant.Name || resp.Tenant["billing_email"] != tenant.BillingEmail {
				t.Errorf("tenant lost its own details: %v", resp.Tenant)
			}
			if tc.plan.Edition == entitlements.EditionEnterprise {
				lower := strings.ToLower(w.Body.String())
				for _, word := range []string{"community", "trial"} {
					if strings.Contains(lower, word) {
						t.Errorf("Enterprise /auth/me contains %q: %s", word, w.Body.String())
					}
				}
			}
		})
	}

	// A failed plan lookup omits the block; user and tenant still answer.
	eng := meEngine(&stubAuthServiceStore{userResult: sampleUser(uid, tid), tenantResult: sampleTenant(tid)},
		func(context.Context, uuid.UUID) (entitlements.Plan, error) {
			return entitlements.Plan{}, errors.New("db down")
		})
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me", nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"plan"`) || !strings.Contains(w.Body.String(), `"tenant"`) {
		t.Fatalf("plan failure = %d %s, want 200 with a tenant and without a plan key", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MeResponse", w.Body.Bytes())
}

func meEngine(store *stubAuthServiceStore, plans tenantPlanResolver) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("userID", aUserID)
		c.Set("tenantID", aTenantID)
		c.Next()
	})
	h := &AuthHandlers{authService: store, plans: plans}
	grp.GET("/auth/me", h.GetMe)
	return r
}
