package handlers

// Contract test for the tier-entitlements composition surface
// (`/admin/tiers/:id/entitlements`) — admin-ui tier-composer, which calls these
// INLINE (not via a service-layer client), so they were missed by the original
// service-layer sweep ().
//
// The public handlers delegate to *WithService variants taking the narrow
// tierEntitlementsProvider interface (the concrete *services.EntitlementsService
// satisfies it; no global-type change), so the real handlers run over an
// in-memory stub. Reuses loadSpec / doRequest / apiBase.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/services"
)

type stubTierEntitlements struct {
	ents       []services.TierEntitlement
	getErr     error
	replaceErr error
}

func (s *stubTierEntitlements) GetTierEntitlements(uuid.UUID) ([]services.TierEntitlement, error) {
	return s.ents, s.getErr
}
func (s *stubTierEntitlements) ReplaceTierEntitlements(uuid.UUID, []services.TierEntitlementInput) error {
	return s.replaceErr
}

func tierEntitlementsEngine(svc tierEntitlementsProvider) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group(apiBase)
	g.GET("/admin/tiers/:id/entitlements", func(c *gin.Context) { getTierEntitlementsWithService(c, svc) })
	g.PUT("/admin/tiers/:id/entitlements", func(c *gin.Context) { updateTierEntitlementsWithService(c, svc) })
	return r
}

func sampleTierEntitlement() services.TierEntitlement {
	unit := "sensors"
	cents := 500
	size := 1
	return services.TierEntitlement{
		ItemID:            uuid.New(),
		ItemKey:           "max_sensors",
		ItemDisplayName:   "Max Sensors",
		ItemCategory:      "capacity",
		ItemKind:          "limit",
		ItemUnit:          &unit,
		IncludedValue:     json.RawMessage(`10`),
		OveragePriceCents: &cents,
		OverageUnitSize:   &size,
	}
}

const tierEntsBase = "/admin/tiers/11111111-1111-1111-1111-111111111111/entitlements"
const validTierEntsBody = `{"entitlements":[{"item_key":"max_sensors","included_value":10}]}`

func TestContract_GetTierEntitlements_200(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{ents: []services.TierEntitlement{sampleTierEntitlement()}})
	w := doRequest(eng, http.MethodGet, apiBase+tierEntsBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierEntitlementsResponse", w.Body.Bytes())
}

func TestContract_GetTierEntitlements_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{ents: nil})
	w := doRequest(eng, http.MethodGet, apiBase+tierEntsBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierEntitlementsResponse", w.Body.Bytes())
}

func TestContract_GetTierEntitlements_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{})
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/tiers/not-a-uuid/entitlements", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTierEntitlements_500(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{getErr: context.DeadlineExceeded})
	w := doRequest(eng, http.MethodGet, apiBase+tierEntsBase, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTierEntitlements_200(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{ents: []services.TierEntitlement{sampleTierEntitlement()}})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierEntitlementsResponse", w.Body.Bytes())
}

func TestContract_UpdateTierEntitlements_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{})
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/tiers/not-a-uuid/entitlements", strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Missing entitlements field → binding 400.
func TestContract_UpdateTierEntitlements_400_body(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Unknown item_key → 400 with item_key in the body (LegacyError allows extra keys).
func TestContract_UpdateTierEntitlements_400_unknownKey(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{replaceErr: &services.UnknownItemKeyError{Key: "bogus_key"}})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTierEntitlements_500(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{replaceErr: context.DeadlineExceeded})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
