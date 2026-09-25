package handlers

// Contract test for the tier-entitlements composition surface
// (`/admin/tiers/:id/entitlements` and `/admin/tiers/:id/entitlements/:key`) —
// admin-ui Plans & Pricing (matrix + plan builder), which calls these INLINE
// (not via a service-layer client), so they were missed by the original
// service-layer sweep ().
//
// The public handlers delegate to *WithService variants taking the narrow
// tierEntitlementsProvider interface (the concrete *services.EntitlementsService
// satisfies it; no global-type change), so the real handlers run over an
// in-memory stub. Reuses loadSpec / doRequest / apiBase. The DB-backed
// behaviour (nothing deleted by omission, version checks under the tier lock,
// history rows) is pinned through the real router in
// internal/api/tier_composition_integration_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

type stubTierEntitlements struct {
	ents     []services.TierEntitlement
	getErr   error
	writeErr error

	gotUpsert *services.TierEntitlementInput
	gotUpdate *services.CompositionUpdate
}

func (s *stubTierEntitlements) comp() services.TierComposition {
	return services.TierComposition{Entitlements: s.ents, Version: "v-current"}
}
func (s *stubTierEntitlements) GetTierComposition(uuid.UUID) (services.TierComposition, error) {
	return s.comp(), s.getErr
}
func (s *stubTierEntitlements) UpsertTierEntitlement(_ uuid.UUID, in services.TierEntitlementInput, _ uuid.UUID) (*services.CompositionWriteResult, error) {
	s.gotUpsert = &in
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	return &services.CompositionWriteResult{Composition: s.comp()}, nil
}
func (s *stubTierEntitlements) UpdateTierComposition(_ uuid.UUID, u services.CompositionUpdate, _ uuid.UUID) (*services.CompositionWriteResult, error) {
	s.gotUpdate = &u
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	// Mirror the real service's precondition so the 428 path is exercised
	// through the handler's error mapping.
	if u.Version == "" {
		return nil, services.ErrCompositionVersionRequired
	}
	return &services.CompositionWriteResult{Composition: s.comp()}, nil
}

func tierEntitlementsEngine(svc tierEntitlementsProvider) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group(apiBase)
	g.GET("/admin/tiers/:id/entitlements", func(c *gin.Context) { getTierEntitlementsWithService(c, svc) })
	g.PUT("/admin/tiers/:id/entitlements", func(c *gin.Context) { updateTierEntitlementsWithService(c, svc) })
	g.PUT("/admin/tiers/:id/entitlements/:key", func(c *gin.Context) { upsertTierEntitlementWithService(c, svc) })
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
const validTierEntsBody = `{"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":10}}],"version":"v-current"}`
const validUpsertBody = `{"included_value":{"quantity":10}}`

// --- GET --------------------------------------------------------------------

func TestContract_GetTierEntitlements_200(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{ents: []services.TierEntitlement{sampleTierEntitlement()}})
	w := doRequest(eng, http.MethodGet, apiBase+tierEntsBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierEntitlementsResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"version":"v-current"`) {
		t.Errorf("GET does not carry the composition version a write must send back: %s", w.Body.String())
	}
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

// --- PUT (multi-item) -------------------------------------------------------

func TestContract_UpdateTierEntitlements_200(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubTierEntitlements{ents: []services.TierEntitlement{sampleTierEntitlement()}}
	eng := tierEntitlementsEngine(stub)
	body := `{"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":10}}],"remove":["storage_gb"],"version":"v-current"}`
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierEntitlementsResponse", w.Body.Bytes())
	if stub.gotUpdate == nil || stub.gotUpdate.Version != "v-current" ||
		len(stub.gotUpdate.Remove) != 1 || stub.gotUpdate.Remove[0] != "storage_gb" ||
		len(stub.gotUpdate.Set) != 1 || stub.gotUpdate.Set[0].ItemKey != "max_sensors" {
		t.Errorf("handler did not pass set/remove/version through: %+v", stub.gotUpdate)
	}
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

// Unparseable body → 400.
func TestContract_UpdateTierEntitlements_400_body(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(`{"entitlements":`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// No version → 428: a multi-item write must say which composition it was
// computed from.
func TestContract_UpdateTierEntitlements_428_noVersion(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase,
		strings.NewReader(`{"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":10}}]}`))
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Stale version → 409 carrying the current version.
func TestContract_UpdateTierEntitlements_409_stale(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{writeErr: &services.StaleCompositionError{Current: "v-newer"}})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CompositionConflictError", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"current_version":"v-newer"`) {
		t.Errorf("409 does not name the current version: %s", w.Body.String())
	}
}

// Unknown item_key → 400 with item_key in the body (LegacyError allows extra keys).
func TestContract_UpdateTierEntitlements_400_unknownKey(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{writeErr: &services.UnknownItemKeyError{Key: "bogus_key"}})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTierEntitlements_500(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{writeErr: context.DeadlineExceeded})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A malformed included_value → 400 carrying the shape the operator should
// have sent, so the composer can pinpoint the cell. The stub returns what the
// real service returns for `{}` on a numeric cap.
func TestContract_UpdateTierEntitlements_400_invalidValue(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{
		writeErr: fmt.Errorf("item max_sensors: %w", &entitlements.InvalidValueError{Kind: entitlements.KindNumericCap, Reason: `missing "quantity"`}),
	})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `missing \"quantity\"`) {
		t.Errorf("400 body does not carry the validation reason: %s", w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// The same item_key twice in one request → 400 with the key, not the bare
// 500 the (tier_id, item_id) primary key used to produce.
func TestContract_UpdateTierEntitlements_400_duplicateKey(t *testing.T) {
	sv := loadSpec(t)
	eng := tierEntitlementsEngine(&stubTierEntitlements{writeErr: &services.DuplicateItemKeyError{Key: "max_sensors"}})
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase, strings.NewReader(validTierEntsBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"item_key":"max_sensors"`) {
		t.Errorf("400 body does not name the duplicated key: %s", w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- PUT /:key (single item) ------------------------------------------------

func TestContract_UpsertTierEntitlement_200(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubTierEntitlements{ents: []services.TierEntitlement{sampleTierEntitlement()}}
	eng := tierEntitlementsEngine(stub)
	w := doRequest(eng, http.MethodPut, apiBase+tierEntsBase+"/max_sensors", strings.NewReader(validUpsertBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TierEntitlementsResponse", w.Body.Bytes())
	if stub.gotUpsert == nil || stub.gotUpsert.ItemKey != "max_sensors" || string(stub.gotUpsert.IncludedValue) != `{"quantity":10}` {
		t.Errorf("handler did not set the item named in the path: %+v", stub.gotUpsert)
	}
}

func TestContract_UpsertTierEntitlement_errors(t *testing.T) {
	sv := loadSpec(t)
	cases := []struct {
		name   string
		path   string
		body   string
		err    error
		status int
		schema string
	}{
		{"bad tier id", "/admin/tiers/not-a-uuid/entitlements/max_sensors", validUpsertBody, nil, http.StatusBadRequest, "LegacyError"},
		{"bad body", tierEntsBase + "/max_sensors", `{"included_value":`, nil, http.StatusBadRequest, "LegacyError"},
		{"unknown tier", tierEntsBase + "/max_sensors", validUpsertBody, services.ErrTierNotFound, http.StatusNotFound, "LegacyError"},
		{"inactive item", tierEntsBase + "/retired", validUpsertBody, &services.UnknownItemKeyError{Key: "retired"}, http.StatusBadRequest, "LegacyError"},
		{"conflicting overage fields", tierEntsBase + "/storage_gb", validUpsertBody,
			&services.OverageConflictError{Key: "storage_gb", Field: "overage_price_cents"}, http.StatusBadRequest, "LegacyError"},
		{"bad value", tierEntsBase + "/max_sensors", `{"included_value":{}}`,
			fmt.Errorf("item max_sensors: %w", &entitlements.InvalidValueError{Kind: entitlements.KindNumericCap, Reason: `missing "quantity"`}),
			http.StatusBadRequest, "LegacyError"},
		{"db failure", tierEntsBase + "/max_sensors", validUpsertBody, context.DeadlineExceeded, http.StatusInternalServerError, "LegacyError"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := tierEntitlementsEngine(&stubTierEntitlements{writeErr: tc.err})
			w := doRequest(eng, http.MethodPut, apiBase+tc.path, strings.NewReader(tc.body))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.status, w.Body.String())
			}
			sv.assertConforms(t, tc.schema, w.Body.Bytes())
		})
	}
}
