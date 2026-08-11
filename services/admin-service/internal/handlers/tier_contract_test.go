package handlers

// Contract test for the subscription tier HTTP surface (admin-ui Tiers page):
// /admin/tiers CRUD + history.
//
// These handlers used a package-global *services.TierService; this slice
// introduces a tierManager interface (the global→injected-interface refactor —
// *services.TierService satisfies it) for the CRUD+history handlers, so the real
// gin handlers run over httptest with an in-memory stub — no DB — and their
// bodies are asserted against api/openapi/admin-service.openapi.yaml.
// (TierImpactAnalysis + GetEffectiveLimits still use the global and are out of
// scope for this slice — they query the DB inline.)
//
// The spec-loading / assertConforms / doRequest harness and apiBase const
// are shared with tenant_billing_contract_test.go (same package, same spec) and
// reused here rather than redefined.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/models"
)

var errTierFail = errors.New("tier failure")

// --- in-memory stub tierManager ---------------------------------------------

type stubTierManager struct {
	tiers        []models.SubscriptionTier
	tiersErr     error
	tier         *models.SubscriptionTier
	tierErr      error
	createErr    error
	updateErr    error
	deprecateErr error
	history      []models.TierHistory
	historyErr   error
}

func (s *stubTierManager) ListTiers(bool) ([]models.SubscriptionTier, error) {
	return s.tiers, s.tiersErr
}
func (s *stubTierManager) GetTier(uuid.UUID) (*models.SubscriptionTier, error) {
	return s.tier, s.tierErr
}
func (s *stubTierManager) CreateTier(models.TierCreateRequest) (*models.SubscriptionTier, error) {
	return s.tier, s.createErr
}
func (s *stubTierManager) UpdateTier(uuid.UUID, models.TierUpdateRequest, uuid.UUID) (*models.SubscriptionTier, error) {
	return s.tier, s.updateErr
}
func (s *stubTierManager) DeprecateTier(uuid.UUID, uuid.UUID) error { return s.deprecateErr }
func (s *stubTierManager) GetTierHistory(uuid.UUID) ([]models.TierHistory, error) {
	return s.history, s.historyErr
}

// --- engine -----------------------------------------------------------------

func tierEngine(mgr tierManager, withUser bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	if withUser {
		grp.Use(func(c *gin.Context) {
			c.Set("user_id", uuid.New())
			c.Next()
		})
	}
	grp.GET("/admin/tiers", ListTiers(mgr))
	grp.POST("/admin/tiers", CreateTier(mgr))
	grp.GET("/admin/tiers/:id", GetTier(mgr))
	grp.PUT("/admin/tiers/:id", UpdateTier(mgr))
	grp.DELETE("/admin/tiers/:id", DeprecateTier(mgr))
	grp.GET("/admin/tiers/:id/history", GetTierHistory(mgr))
	return r
}

const tierBase = apiBase + "/admin/tiers"

// --- sample data ------------------------------------------------------------

func sampleTier() models.SubscriptionTier {
	now := time.Now().UTC()
	ms := 50
	return models.SubscriptionTier{
		ID:              uuid.New(),
		Name:            "pro",
		DisplayName:     "Pro",
		MaxSensors:      &ms,
		MaxAssets:       &ms,
		MaxUsers:        &ms,
		RetentionDays:   90,
		PriceCents:      9900,
		BillingInterval: "monthly",
		Features:        map[string]interface{}{"sso": true},
		Limits:          map[string]interface{}{"seats": 10},
		AddonPricing:    map[string]interface{}{},
		Metadata:        map[string]interface{}{},
		IsActive:        true,
		IsCustom:        false,
		DisplayOrder:    1,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// minimalTier leaves the nullable *int + jsonb maps + deprecated_at unset (→ null).
func minimalTier() models.SubscriptionTier {
	now := time.Now().UTC()
	return models.SubscriptionTier{
		ID:              uuid.New(),
		Name:            "free",
		DisplayName:     "Free",
		RetentionDays:   7,
		PriceCents:      0,
		BillingInterval: "monthly",
		IsActive:        true,
		DisplayOrder:    0,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func sampleTierHistory() models.TierHistory {
	now := time.Now().UTC()
	by := uuid.New()
	notes := "bumped price"
	return models.TierHistory{
		ID:         uuid.New(),
		TierID:     uuid.New(),
		ChangeType: "updated",
		Changes:    map[string]interface{}{"price_cents": []int{9900, 10900}},
		ChangedBy:  &by,
		ChangedAt:  now,
		Notes:      &notes,
	}
}

const validTierBody = `{"name":"pro","display_name":"Pro","billing_interval":"monthly"}`

// --- list / get -------------------------------------------------------------

func TestContract_ListTiers_200(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{tiers: []models.SubscriptionTier{sampleTier(), minimalTier()}}, false)
	w := doRequest(eng, http.MethodGet, tierBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierListResponse", w.Body.Bytes())
}

func TestContract_ListTiers_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{tiers: nil}, false)
	w := doRequest(eng, http.MethodGet, tierBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierListResponse", w.Body.Bytes())
}

func TestContract_GetTier_200(t *testing.T) {
	sv := loadSpec(t)
	tr := sampleTier()
	eng := tierEngine(&stubTierManager{tier: &tr}, false)
	w := doRequest(eng, http.MethodGet, tierBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SubscriptionTier", w.Body.Bytes())
}

func TestContract_GetTier_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{}, false)
	w := doRequest(eng, http.MethodGet, tierBase+"/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTier_404(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{tierErr: errTierFail}, false)
	w := doRequest(eng, http.MethodGet, tierBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- create -----------------------------------------------------------------

func TestContract_CreateTier_201(t *testing.T) {
	sv := loadSpec(t)
	tr := sampleTier()
	eng := tierEngine(&stubTierManager{tier: &tr}, false)
	w := doRequest(eng, http.MethodPost, tierBase, strings.NewReader(validTierBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SubscriptionTier", w.Body.Bytes())
}

func TestContract_CreateTier_400(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{}, false)
	w := doRequest(eng, http.MethodPost, tierBase, strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- update -----------------------------------------------------------------

func TestContract_UpdateTier_200(t *testing.T) {
	sv := loadSpec(t)
	tr := sampleTier()
	eng := tierEngine(&stubTierManager{tier: &tr}, true)
	w := doRequest(eng, http.MethodPut, tierBase+"/"+uuid.New().String(), strings.NewReader(`{"price_cents":10900}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierUpdateResponse", w.Body.Bytes())
}

// No user_id in context → 401.
func TestContract_UpdateTier_401(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{}, false)
	w := doRequest(eng, http.MethodPut, tierBase+"/"+uuid.New().String(), strings.NewReader(`{"price_cents":10900}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTier_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{}, true)
	w := doRequest(eng, http.MethodPut, tierBase+"/not-a-uuid", strings.NewReader(`{"price_cents":1}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- deprecate --------------------------------------------------------------

func TestContract_DeprecateTier_200(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{}, true)
	w := doRequest(eng, http.MethodDelete, tierBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_DeprecateTier_401(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{}, false)
	w := doRequest(eng, http.MethodDelete, tierBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- history ----------------------------------------------------------------

func TestContract_GetTierHistory_200(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{history: []models.TierHistory{sampleTierHistory()}}, false)
	w := doRequest(eng, http.MethodGet, tierBase+"/"+uuid.New().String()+"/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierHistoryResponse", w.Body.Bytes())
}

func TestContract_GetTierHistory_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{history: nil}, false)
	w := doRequest(eng, http.MethodGet, tierBase+"/"+uuid.New().String()+"/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierHistoryResponse", w.Body.Bytes())
}

func TestContract_GetTierHistory_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEngine(&stubTierManager{}, false)
	w := doRequest(eng, http.MethodGet, tierBase+"/not-a-uuid/history", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guards -----------------------------------------------------------

func TestContract_SubscriptionTier_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/SubscriptionTier")
	if err != nil {
		t.Fatalf("compile SubscriptionTier: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted SubscriptionTier, but it passed — the guardrail is not actually checking")
	}
}

func TestContract_TierHistory_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/TierHistory")
	if err != nil {
		t.Fatalf("compile TierHistory: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted TierHistory, but it passed — the guardrail is not actually checking")
	}
}
