package handlers

// Contract test for the compliance remediation-plans read surface. Extends the
// compliance-engine spec-first contract (ADR-0001) and reuses the shared
// harness (loadSpec / assertConforms / do / specBaseURI / cBase / fUUID) from
// the framework + findings contract tests — only the plan stub + engine + cases
// live here.
//
// RemediationPlanHandlers' planService field is now the planStore interface
// (the concrete *services.RemediationPlanService still satisfies it), so these
// tests drive the real handlers with an in-memory stub — no DB.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// --- stub planStore --------------------------------------------------------

type stubPlanStore struct {
	list        []models.RemediationPlan
	total       int
	listErr     error
	byID        *models.RemediationPlan
	byIDErr     error
	progress    *models.PlanProgress
	progressErr error
	items       []models.RemediationPlanItem
	itemsErr    error
	created     *models.RemediationPlan
	createErr   error
	updated     *models.RemediationPlan
	updateErr   error
	deleteErr   error
	addedItem   *models.RemediationPlanItem
	addItemErr  error
	bulkAdded   int
	bulkErr     error
	removeErr   error
	linkErr     error
}

func (s *stubPlanStore) List(uuid.UUID, models.PlanFilters) ([]models.RemediationPlan, int, error) {
	return s.list, s.total, s.listErr
}
func (s *stubPlanStore) GetByID(uuid.UUID, uuid.UUID) (*models.RemediationPlan, error) {
	return s.byID, s.byIDErr
}
func (s *stubPlanStore) Create(uuid.UUID, uuid.UUID, models.CreatePlanInput) (*models.RemediationPlan, error) {
	return s.created, s.createErr
}
func (s *stubPlanStore) Update(uuid.UUID, uuid.UUID, models.UpdatePlanInput) (*models.RemediationPlan, error) {
	return s.updated, s.updateErr
}
func (s *stubPlanStore) Delete(uuid.UUID, uuid.UUID) error { return s.deleteErr }
func (s *stubPlanStore) ListItems(uuid.UUID, uuid.UUID) ([]models.RemediationPlanItem, error) {
	return s.items, s.itemsErr
}
func (s *stubPlanStore) AddItem(uuid.UUID, uuid.UUID, uuid.UUID, models.AddPlanItemInput) (*models.RemediationPlanItem, error) {
	return s.addedItem, s.addItemErr
}
func (s *stubPlanStore) AddItemsBulk(uuid.UUID, uuid.UUID, uuid.UUID, models.AddPlanItemsBulkInput) (int, error) {
	return s.bulkAdded, s.bulkErr
}
func (s *stubPlanStore) RemoveItem(uuid.UUID, uuid.UUID, uuid.UUID) error { return s.removeErr }
func (s *stubPlanStore) LinkTicket(uuid.UUID, uuid.UUID, uuid.UUID, models.LinkTicketInput) error {
	return s.linkErr
}
func (s *stubPlanStore) ListForTicketIDs(uuid.UUID, []uuid.UUID) (map[uuid.UUID][]models.PlanRef, error) {
	return nil, nil
}
func (s *stubPlanStore) GetProgress(uuid.UUID, uuid.UUID) (*models.PlanProgress, error) {
	return s.progress, s.progressErr
}

func newPlanEngine(svc *stubPlanStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &RemediationPlanHandlers{planService: svc}
	grp.GET("/plans", h.ListPlans)
	grp.GET("/plans/:id", h.GetPlan)
	grp.POST("/plans", h.CreatePlan)
	grp.PUT("/plans/:id", h.UpdatePlan)
	grp.DELETE("/plans/:id", h.DeletePlan)
	grp.GET("/plans/:id/progress", h.GetPlanProgress)
	grp.GET("/plans/:id/items", h.ListPlanItems)
	grp.POST("/plans/:id/items", h.AddPlanItem)
	grp.POST("/plans/:id/items/bulk", h.AddPlanItemsBulk)
	grp.DELETE("/plans/:id/items/:itemId", h.RemovePlanItem)
	grp.PUT("/plans/:id/items/:itemId/ticket", h.LinkTicketToItem)
	return r
}

func samplePlanItem() models.RemediationPlanItem {
	now := time.Now().UTC()
	tid := uuid.New()
	return models.RemediationPlanItem{
		ID:              uuid.New(),
		PlanID:          uuid.New(),
		FindingID:       uuid.New(),
		TicketID:        &tid,
		Notes:           strPtrPlan("blocked on cert reissue"),
		AddedAt:         now,
		AddedBy:         uuid.New(),
		FindingSeverity: strPtrPlan("high"),
		FindingSummary:  strPtrPlan("Weak TLS"),
	}
}

func samplePlan() models.RemediationPlan {
	now := time.Now().UTC()
	owner := uuid.New()
	target := now.Add(720 * time.Hour)
	return models.RemediationPlan{
		ID:            uuid.New(),
		TenantID:      uuid.New(),
		Title:         "Q3 PQC migration",
		Description:   strPtrPlan("Migrate weak TLS to PQC-ready"),
		PlanType:      "migration",
		Status:        "active",
		Priority:      "high",
		OwnerID:       &owner,
		TargetDate:    &target,
		CreatedBy:     uuid.New(),
		CreatedAt:     now,
		UpdatedAt:     now,
		ItemCount:     10,
		ResolvedCount: 4,
		Progress:      40,
	}
}

func strPtrPlan(s string) *string { return &s }

// --- the contract tests ----------------------------------------------------

func TestContract_ListPlans_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{list: []models.RemediationPlan{samplePlan()}, total: 1})
	w := do(eng, http.MethodGet, cBase+"/plans", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RemediationPlanListResponse", w.Body.Bytes())
}

func TestContract_GetPlan_200(t *testing.T) {
	sv := loadSpec(t)
	p := samplePlan()
	eng := newPlanEngine(&stubPlanStore{byID: &p})
	w := do(eng, http.MethodGet, cBase+"/plans/"+fUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RemediationPlanResponse", w.Body.Bytes())
}

func TestContract_GetPlan_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{})
	w := do(eng, http.MethodGet, cBase+"/plans/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A nil plan (no error) maps to 404.
func TestContract_GetPlan_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{byID: nil})
	w := do(eng, http.MethodGet, cBase+"/plans/"+fUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPlanProgress_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{progress: &models.PlanProgress{
		TotalItems:       10,
		ByWorkflowStatus: map[string]int{"NEW": 6, "RESOLVED": 4},
		ByTicketStatus:   map[string]int{"open": 6},
		BySeverity:       map[string]int{"high": 5, "medium": 5},
		PercentResolved:  40,
		AllResolved:      false,
	}})
	w := do(eng, http.MethodGet, cBase+"/plans/"+fUUID+"/progress", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlanProgress", w.Body.Bytes())
}

func TestContract_ListPlanItems_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{items: []models.RemediationPlanItem{samplePlanItem()}})
	w := do(eng, http.MethodGet, cBase+"/plans/"+fUUID+"/items", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlanItemsResponse", w.Body.Bytes())
}

func TestContract_ListPlanItems_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{})
	w := do(eng, http.MethodGet, cBase+"/plans/not-a-uuid/items", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- plan + plan-item mutations ---------------------------------------------

func TestContract_CreatePlan_201(t *testing.T) {
	sv := loadSpec(t)
	p := samplePlan()
	eng := newPlanEngine(&stubPlanStore{created: &p})
	w := do(eng, http.MethodPost, cBase+"/plans", strings.NewReader(`{"title":"Q3 migration","plan_type":"migration"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlanMutationResponse", w.Body.Bytes())
}

func TestContract_CreatePlan_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{})
	w := do(eng, http.MethodPost, cBase+"/plans", strings.NewReader(`{"plan_type":"migration"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdatePlan_200(t *testing.T) {
	sv := loadSpec(t)
	p := samplePlan()
	eng := newPlanEngine(&stubPlanStore{updated: &p})
	w := do(eng, http.MethodPut, cBase+"/plans/"+fUUID, strings.NewReader(`{"title":"renamed"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlanMutationResponse", w.Body.Bytes())
}

func TestContract_DeletePlan_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{})
	w := do(eng, http.MethodDelete, cBase+"/plans/"+fUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_AddPlanItem_201(t *testing.T) {
	sv := loadSpec(t)
	it := samplePlanItem()
	eng := newPlanEngine(&stubPlanStore{addedItem: &it})
	w := do(eng, http.MethodPost, cBase+"/plans/"+fUUID+"/items", strings.NewReader(`{"finding_id":"`+fUUID+`"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlanItemMutationResponse", w.Body.Bytes())
}

func TestContract_AddPlanItemsBulk_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{bulkAdded: 3})
	w := do(eng, http.MethodPost, cBase+"/plans/"+fUUID+"/items/bulk", strings.NewReader(`{"finding_ids":["`+fUUID+`"]}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlanItemsBulkResponse", w.Body.Bytes())
}

func TestContract_RemovePlanItem_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{})
	w := do(eng, http.MethodDelete, cBase+"/plans/"+fUUID+"/items/"+fUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_LinkTicketToItem_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPlanEngine(&stubPlanStore{})
	w := do(eng, http.MethodPut, cBase+"/plans/"+fUUID+"/items/"+fUUID+"/ticket", strings.NewReader(`{"ticket_id":"`+fUUID+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_Plan_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/RemediationPlan")
	if err != nil {
		t.Fatalf("compile RemediationPlan: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + fUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted RemediationPlan, but it passed — the guardrail is not actually checking")
	}
}
