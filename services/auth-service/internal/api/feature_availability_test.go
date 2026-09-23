package api

// GET /features/availability used to read the legacy subscription_tiers
// features / limits / max_* columns — the mirror the plan editor never writes
// and enforcement stopped consulting. These pin that it now answers from the
// same two sources every gate uses: CheckFeatureAccess for features and the
// entitlement resolver for caps.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

type stubFeatureAvailabilityStore struct {
	tier     string
	tierErr  error
	caps     map[string]*int
	capsErr  error
	askedFor []string
	plan     entitlements.Plan // zero = Core
}

func (s *stubFeatureAvailabilityStore) TenantPlan(context.Context, uuid.UUID) (entitlements.Plan, error) {
	if s.plan.Edition == "" {
		return entitlements.Plan{Edition: entitlements.EditionCore, DisplayName: entitlements.PlanDisplayNameCore}, nil
	}
	return s.plan, nil
}

func (s *stubFeatureAvailabilityStore) GetTenantTierName(context.Context, uuid.UUID) (string, error) {
	return s.tier, s.tierErr
}
func (s *stubFeatureAvailabilityStore) ResolveCaps(_ context.Context, _ uuid.UUID, keys []string) (map[string]*int, error) {
	s.askedFor = keys
	return s.caps, s.capsErr
}

type stubFeatureChecker struct {
	enabled map[string]bool
	err     error
}

func (s *stubFeatureChecker) CheckFeatureAccess(_ uuid.UUID, feature string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.enabled[feature], nil
}
func (s *stubFeatureChecker) GetComplianceFrameworkUsage(uuid.UUID) (int, *int, error) {
	return 0, nil, nil
}

func featureAvailabilityEngine(store featureAvailabilityStore, checker limitChecker, authenticated bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", aTenantID)
		}
		c.Next()
	})
	grp.GET("/features/availability", GetFeatureAvailabilityWithDeps(store, checker))
	return r
}

func TestGetFeatureAvailability_AnswersFromResolverAndFeatureGate(t *testing.T) {
	store := &stubFeatureAvailabilityStore{
		tier: "pro",
		caps: map[string]*int{
			"max_sensors":    intp(25),
			"max_assets":     nil, // unlimited
			"retention_days": intp(365),
		},
	}
	checker := &stubFeatureChecker{enabled: map[string]bool{"custom_policies": true, "sso_saml": true}}
	w := do(featureAvailabilityEngine(store, checker, true), http.MethodGet, "/api/v1/auth-service/features/availability", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got FeatureAvailability
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Tier != "pro" {
		t.Errorf("tier = %q, want pro", got.Tier)
	}
	// Every known feature is present, and only the ones the gate allows are true.
	if len(got.Features) != len(knownFeatures) {
		t.Errorf("features has %d keys, want %d (one per knownFeatures entry)", len(got.Features), len(knownFeatures))
	}
	if got.Features["custom_policies"] != true || got.Features["sso_saml"] != true {
		t.Errorf("gate-enabled features not reported true: %v", got.Features)
	}
	if got.Features["cbom_signing"] != false {
		t.Errorf("cbom_signing = %v, want false (gate did not allow it)", got.Features["cbom_signing"])
	}
	// Caps come from the resolver, -1 meaning unlimited (this endpoint's
	// long-standing convention), and nothing is invented for unresolved keys.
	if got.Limits["max_sensors"] != float64(25) {
		t.Errorf("max_sensors = %v, want 25", got.Limits["max_sensors"])
	}
	if got.Limits["max_assets"] != float64(-1) {
		t.Errorf("max_assets = %v, want -1 (unlimited)", got.Limits["max_assets"])
	}
	if _, present := got.Limits["max_users"]; present {
		t.Errorf("max_users reported as %v though the resolver did not answer for it", got.Limits["max_users"])
	}
	// It asks the resolver for the full cap set, not just the three usage keys.
	want := map[string]bool{}
	for _, k := range featureAvailabilityCapKeys {
		want[k] = true
	}
	for _, k := range []string{"max_sensors", "max_assets", "max_users", "retention_days", "compliance_frameworks_max", "integrations_max"} {
		if !want[k] {
			t.Errorf("featureAvailabilityCapKeys does not include %s", k)
		}
	}
	if len(store.askedFor) != len(featureAvailabilityCapKeys) {
		t.Errorf("resolver asked for %v, want %v", store.askedFor, featureAvailabilityCapKeys)
	}
}

func TestGetFeatureAvailability_FeatureCheckErrorReadsAsDisabled(t *testing.T) {
	store := &stubFeatureAvailabilityStore{tier: "pro", caps: map[string]*int{}}
	checker := &stubFeatureChecker{err: errors.New("resolver down")}
	w := do(featureAvailabilityEngine(store, checker, true), http.MethodGet, "/api/v1/auth-service/features/availability", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got FeatureAvailability
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	for k, v := range got.Features {
		if v != false {
			t.Errorf("feature %s = %v on gate error, want false (fail closed)", k, v)
		}
	}
}

func TestGetFeatureAvailability_404WhenNoTier(t *testing.T) {
	store := &stubFeatureAvailabilityStore{tierErr: sql.ErrNoRows}
	w := do(featureAvailabilityEngine(store, &stubFeatureChecker{}, true), http.MethodGet, "/api/v1/auth-service/features/availability", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestGetFeatureAvailability_500WhenCapsUnresolvable(t *testing.T) {
	store := &stubFeatureAvailabilityStore{tier: "pro", capsErr: errors.New("db down")}
	w := do(featureAvailabilityEngine(store, &stubFeatureChecker{}, true), http.MethodGet, "/api/v1/auth-service/features/availability", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestGetFeatureAvailability_401Unauthenticated(t *testing.T) {
	w := do(featureAvailabilityEngine(&stubFeatureAvailabilityStore{}, &stubFeatureChecker{}, false), http.MethodGet, "/api/v1/auth-service/features/availability", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}
