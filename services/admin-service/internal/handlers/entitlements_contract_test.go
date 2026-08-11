package handlers

// Contract test for the billable-item catalog HTTP surface (admin-ui
// Entitlements catalog): /admin/billable-items CRUD.
//
// These handlers used a package-global *services.EntitlementsService; this slice
// introduces a billableItemStore interface (the global→injected-interface
// refactor — *services.EntitlementsService satisfies it) so the real gin
// handlers run over httptest with an in-memory stub — no DB — and their bodies
// are asserted against api/openapi/admin-service.openapi.yaml. (The tier- and
// tenant-entitlement handlers still use the global and are out of scope.)
//
// The spec-loading / assertConforms / doRequest harness and apiBase const
// are shared with tenant_billing_contract_test.go (same package, same spec) and
// reused here rather than redefined.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/services"
)

// --- in-memory stub billableItemStore ---------------------------------------

type stubBillableItemStore struct {
	items     []services.BillableItem
	itemsErr  error
	item      *services.BillableItem
	createErr error
	updateErr error
	deleteErr error
}

func (s *stubBillableItemStore) ListBillableItems() ([]services.BillableItem, error) {
	return s.items, s.itemsErr
}
func (s *stubBillableItemStore) CreateBillableItem(services.BillableItemInput) (*services.BillableItem, error) {
	return s.item, s.createErr
}
func (s *stubBillableItemStore) UpdateBillableItem(uuid.UUID, services.BillableItemInput) (*services.BillableItem, error) {
	return s.item, s.updateErr
}
func (s *stubBillableItemStore) DeleteBillableItem(uuid.UUID) error { return s.deleteErr }

// --- engine -----------------------------------------------------------------

func billableItemEngine(store billableItemStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	grp.GET("/admin/billable-items", ListBillableItems(store))
	grp.POST("/admin/billable-items", CreateBillableItem(store))
	grp.PUT("/admin/billable-items/:id", UpdateBillableItem(store))
	grp.DELETE("/admin/billable-items/:id", DeleteBillableItem(store))
	return r
}

const billableItemBase = apiBase + "/admin/billable-items"

func sampleBillableItem() services.BillableItem {
	unit := "asset"
	price := 500
	return services.BillableItem{
		ID:                     uuid.New(),
		Key:                    "max_assets",
		DisplayName:            "Max Assets",
		Description:            "Asset cap",
		Category:               "limits",
		Kind:                   "quota",
		Unit:                   &unit,
		DefaultValue:           json.RawMessage(`100`),
		IsAddonEligible:        true,
		DefaultAddonPriceCents: &price,
		IsActive:               true,
		SortOrder:              1,
	}
}

// minimalBillableItem leaves the omitempty fields unset (absent).
func minimalBillableItem() services.BillableItem {
	return services.BillableItem{
		ID:           uuid.New(),
		Key:          "sso",
		DisplayName:  "SSO",
		Category:     "features",
		Kind:         "flag",
		DefaultValue: json.RawMessage(`false`),
		IsActive:     true,
		SortOrder:    2,
	}
}

const validBillableItemBody = `{"key":"max_assets","display_name":"Max Assets","category":"limits","kind":"quota","default_value":100,"is_active":true}`

// --- list -------------------------------------------------------------------

func TestContract_ListBillableItems_200(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{items: []services.BillableItem{sampleBillableItem(), minimalBillableItem()}})
	w := doRequest(eng, http.MethodGet, billableItemBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BillableItemListResponse", w.Body.Bytes())
}

func TestContract_ListBillableItems_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{items: nil})
	w := doRequest(eng, http.MethodGet, billableItemBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BillableItemListResponse", w.Body.Bytes())
}

// --- create -----------------------------------------------------------------

func TestContract_CreateBillableItem_201(t *testing.T) {
	sv := loadSpec(t)
	it := sampleBillableItem()
	eng := billableItemEngine(&stubBillableItemStore{item: &it})
	w := doRequest(eng, http.MethodPost, billableItemBase, strings.NewReader(validBillableItemBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BillableItem", w.Body.Bytes())
}

func TestContract_CreateBillableItem_400(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{})
	w := doRequest(eng, http.MethodPost, billableItemBase, strings.NewReader(`{"display_name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Duplicate key → 409.
func TestContract_CreateBillableItem_409(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{createErr: &services.DuplicateKeyError{Key: "max_assets"}})
	w := doRequest(eng, http.MethodPost, billableItemBase, strings.NewReader(validBillableItemBody))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- update -----------------------------------------------------------------

func TestContract_UpdateBillableItem_200(t *testing.T) {
	sv := loadSpec(t)
	it := sampleBillableItem()
	eng := billableItemEngine(&stubBillableItemStore{item: &it})
	w := doRequest(eng, http.MethodPut, billableItemBase+"/"+uuid.New().String(), strings.NewReader(validBillableItemBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BillableItem", w.Body.Bytes())
}

func TestContract_UpdateBillableItem_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{})
	w := doRequest(eng, http.MethodPut, billableItemBase+"/not-a-uuid", strings.NewReader(validBillableItemBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateBillableItem_404(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{updateErr: sql.ErrNoRows})
	w := doRequest(eng, http.MethodPut, billableItemBase+"/"+uuid.New().String(), strings.NewReader(validBillableItemBody))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- delete -----------------------------------------------------------------

func TestContract_DeleteBillableItem_204(t *testing.T) {
	eng := billableItemEngine(&stubBillableItemStore{})
	w := doRequest(eng, http.MethodDelete, billableItemBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
}

func TestContract_DeleteBillableItem_404(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{deleteErr: sql.ErrNoRows})
	w := doRequest(eng, http.MethodDelete, billableItemBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Referenced by tiers/tenants → 409.
func TestContract_DeleteBillableItem_409(t *testing.T) {
	sv := loadSpec(t)
	eng := billableItemEngine(&stubBillableItemStore{deleteErr: &services.ItemInUseError{ID: uuid.New(), TierRefs: 2, TenantRefs: 1}})
	w := doRequest(eng, http.MethodDelete, billableItemBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guard ------------------------------------------------------------

func TestContract_BillableItem_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/BillableItem")
	if err != nil {
		t.Fatalf("compile BillableItem: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted BillableItem, but it passed — the guardrail is not actually checking")
	}
}
