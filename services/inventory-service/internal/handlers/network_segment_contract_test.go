package handlers

// Contract test for the network-segments HTTP surface (CMDB network segments).
// Extends the inventory-service spec-first contract (ADR-0001) and reuses the
// shared harness (loadSpec / assertConforms / do / strPtr / aUUID) from
// asset_contract_test.go — only the segment stub + engine + cases live here.
//
// NetworkSegmentHandler was made testable by depending on the
// networkSegmentService interface (the concrete *services.NetworkSegmentService
// still satisfies it), so these tests drive the real handlers with an in-memory
// stub — no database.

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// --- stub networkSegmentService --------------------------------------------

type stubNetworkSegmentService struct {
	list    []models.NetworkSegment
	total   int
	listErr error
	byID    *models.NetworkSegment
	byIDErr error
	// write surface
	createResult *models.NetworkSegment
	createErr    error
	updateResult *models.NetworkSegment
	updateErr    error
	deleteErr    error
	// cloud classification (B-49)
	cloudSegment    *models.NetworkSegment
	cloudSegmentErr error
}

func (s *stubNetworkSegmentService) List(uuid.UUID, models.NetworkSegmentFilters) ([]models.NetworkSegment, int, error) {
	return s.list, s.total, s.listErr
}
func (s *stubNetworkSegmentService) GetByID(uuid.UUID, uuid.UUID) (*models.NetworkSegment, error) {
	return s.byID, s.byIDErr
}
func (s *stubNetworkSegmentService) Create(uuid.UUID, models.NetworkSegmentInput) (*models.NetworkSegment, error) {
	return s.createResult, s.createErr
}
func (s *stubNetworkSegmentService) BulkCreate(_ uuid.UUID, inputs []models.NetworkSegmentInput) *models.BulkImportResult {
	res := models.NewBulkImportResult(len(inputs))
	for i := range inputs {
		res.Add(i, models.BulkRowCreated, nil, "")
	}
	return res
}
func (s *stubNetworkSegmentService) Update(uuid.UUID, uuid.UUID, models.NetworkSegmentInput) (*models.NetworkSegment, error) {
	return s.updateResult, s.updateErr
}
func (s *stubNetworkSegmentService) Delete(uuid.UUID, uuid.UUID) error                  { return s.deleteErr }
func (s *stubNetworkSegmentService) ManageAutoApprovalRules(uuid.UUID, uuid.UUID) error { return nil }
func (s *stubNetworkSegmentService) GetSegmentForIP(uuid.UUID, *string, *string) (*models.NetworkSegment, error) {
	return nil, nil
}
func (s *stubNetworkSegmentService) ClassifyAsset(uuid.UUID, *string, *string, []string) (string, error) {
	return "", nil
}
func (s *stubNetworkSegmentService) FindOrCreateCloudSegment(uuid.UUID, string, string, string, string) (*models.NetworkSegment, error) {
	return s.cloudSegment, s.cloudSegmentErr
}
func (s *stubNetworkSegmentService) ReclassifyAllAssets(uuid.UUID) (int, error)      { return 0, nil }
func (s *stubNetworkSegmentService) MigrateFromNetworkSpaces(uuid.UUID) (int, error) { return 0, nil }

func newSegmentEngine(svc *stubNetworkSegmentService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	h := &NetworkSegmentHandler{segmentService: svc}
	grp.GET("/network-segments", h.GetNetworkSegments)
	grp.POST("/network-segments", h.CreateNetworkSegment)
	grp.GET("/network-segments/:id", h.GetNetworkSegment)
	grp.PUT("/network-segments/:id", h.UpdateNetworkSegment)
	grp.DELETE("/network-segments/:id", h.DeleteNetworkSegment)
	return r
}

func sampleSegment() models.NetworkSegment {
	now := time.Now().UTC()
	return models.NetworkSegment{
		ID:                     uuid.New(),
		TenantID:               uuid.New(),
		Name:                   "prod-vpc-east",
		SegmentType:            "cloud_vpc",
		Value:                  "10.0.0.0/16",
		NetworkType:            "cloud",
		Environment:            "production",
		LocationID:             uuidPtr(uuid.New()),
		BusinessUnit:           strPtr("platform"),
		OwnerEmail:             strPtr("ops@example.com"),
		IsActive:               true,
		AutoApproveDiscoveries: false,
		Tags:                   models.JSONB{"team": "infra"},
		Metadata:               models.JSONB{"region": "us-east-1"},
		CreatedAt:              now,
		UpdatedAt:              now,
	}
}

// minimalSegment leaves omitempty fields unset and the nullable maps nil.
func minimalSegment() models.NetworkSegment {
	now := time.Now().UTC()
	return models.NetworkSegment{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "lab-range",
		SegmentType: "ip_range",
		Value:       "192.168.1.1-192.168.1.254",
		NetworkType: "private",
		Environment: "test",
		// LocationID intentionally nil — exercises the optional/nullable location path.
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func uuidPtr(u uuid.UUID) *uuid.UUID { return &u }

const nsBase = "/api/v2/inventory-service"

// --- the contract tests ----------------------------------------------------

func TestContract_ListNetworkSegments_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{list: []models.NetworkSegment{sampleSegment(), minimalSegment()}, total: 2})
	w := do(eng, http.MethodGet, nsBase+"/network-segments", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegmentListResponse", w.Body.Bytes())
}

func TestContract_GetNetworkSegment_200(t *testing.T) {
	sv := loadSpec(t)
	seg := sampleSegment()
	eng := newSegmentEngine(&stubNetworkSegmentService{byID: &seg})
	w := do(eng, http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
}

func TestContract_GetNetworkSegment_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodGet, nsBase+"/network-segments/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A nil segment (no error) maps to 404.
func TestContract_GetNetworkSegment_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{byID: nil})
	w := do(eng, http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_NetworkSegment_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/NetworkSegment")
	if err != nil {
		t.Fatalf("compile NetworkSegment: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted NetworkSegment, but it passed — the guardrail is not actually checking")
	}
}

// --- write surface: create / update / delete -------------------------

const validSegmentBody = `{"name":"prod-vpc","segment_type":"cloud_vpc","value":"10.0.0.0/16","network_type":"cloud","environment":"production"}`

func TestContract_CreateNetworkSegment_201(t *testing.T) {
	sv := loadSpec(t)
	seg := sampleSegment()
	eng := newSegmentEngine(&stubNetworkSegmentService{createResult: &seg})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
}

func TestContract_CreateNetworkSegment_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// An unknown location_id surfaces as 400 "Invalid request".
func TestContract_CreateNetworkSegment_400_unknownLocation(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{createErr: errors.New("location not found")})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateNetworkSegment_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{createErr: io.EOF})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateNetworkSegment_200(t *testing.T) {
	sv := loadSpec(t)
	seg := sampleSegment()
	eng := newSegmentEngine(&stubNetworkSegmentService{updateResult: &seg})
	w := do(eng, http.MethodPut, nsBase+"/network-segments/"+aUUID, strings.NewReader(validSegmentBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
}

func TestContract_UpdateNetworkSegment_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodPut, nsBase+"/network-segments/not-a-uuid", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateNetworkSegment_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{updateErr: errors.New("network segment not found")})
	w := do(eng, http.MethodPut, nsBase+"/network-segments/"+aUUID, strings.NewReader(validSegmentBody))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteNetworkSegment_204(t *testing.T) {
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodDelete, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body on 204, got: %s", w.Body.String())
	}
}

func TestContract_DeleteNetworkSegment_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodDelete, nsBase+"/network-segments/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteNetworkSegment_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{deleteErr: sql.ErrNoRows})
	w := do(eng, http.MethodDelete, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
