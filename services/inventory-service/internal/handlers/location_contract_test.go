package handlers

// Contract test for the locations HTTP surface (CMDB location hierarchy).
// Extends the inventory-service spec-first contract (ADR-0001) and reuses the
// shared harness (loadSpec / assertConforms / do / strPtr / intPtr / aUUID /
// sampleAsset) from asset_contract_test.go — only the location stub + engine +
// cases live here.
//
// LocationHandler was made testable by depending on the locationService
// interface (the concrete *services.LocationService still satisfies it), so
// these tests drive the real handlers with an in-memory stub — no database.

import (
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

// --- stub locationService --------------------------------------------------

type stubLocationService struct {
	list       []models.Location
	total      int
	listErr    error
	tree       []models.Location
	treeErr    error
	byID       *models.Location
	byIDErr    error
	assets     []models.Asset
	assetsTot  int
	assetsErr  error
	summary    *models.LocationSummary
	summaryErr error
	// write surface
	createResult *models.Location
	createErr    error
	updateResult *models.Location
	updateErr    error
	deleteErr    error
}

func (s *stubLocationService) List(uuid.UUID, models.LocationFilters) ([]models.Location, int, error) {
	return s.list, s.total, s.listErr
}
func (s *stubLocationService) GetTree(uuid.UUID) ([]models.Location, error) {
	return s.tree, s.treeErr
}
func (s *stubLocationService) Create(uuid.UUID, models.LocationInput) (*models.Location, error) {
	return s.createResult, s.createErr
}
func (s *stubLocationService) GetByIDWithChildren(uuid.UUID, uuid.UUID) (*models.Location, error) {
	return s.byID, s.byIDErr
}
func (s *stubLocationService) Update(uuid.UUID, uuid.UUID, models.LocationInput) (*models.Location, error) {
	return s.updateResult, s.updateErr
}
func (s *stubLocationService) Delete(uuid.UUID, uuid.UUID) error { return s.deleteErr }
func (s *stubLocationService) GetLocationAssets(uuid.UUID, uuid.UUID) ([]models.Asset, int, error) {
	return s.assets, s.assetsTot, s.assetsErr
}
func (s *stubLocationService) GetLocationSummary(uuid.UUID, uuid.UUID) (*models.LocationSummary, error) {
	return s.summary, s.summaryErr
}

func newLocationEngine(svc *stubLocationService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	h := &LocationHandler{locationService: svc}
	grp.GET("/locations", h.GetLocations)
	grp.POST("/locations", h.CreateLocation)
	grp.GET("/locations/tree", h.GetLocationTree)
	grp.GET("/locations/:id", h.GetLocation)
	grp.PUT("/locations/:id", h.UpdateLocation)
	grp.DELETE("/locations/:id", h.DeleteLocation)
	grp.GET("/locations/:id/assets", h.GetLocationAssets)
	grp.GET("/locations/:id/summary", h.GetLocationSummary)
	return r
}

// sampleLocation sets the optional geo/cloud fields too.
func sampleLocation() models.Location {
	now := time.Now().UTC()
	pid := uuid.New()
	lat, lng := 37.77, -122.42
	return models.Location{
		ID:           uuid.New(),
		TenantID:     uuid.New(),
		Name:         "SF Datacenter",
		ParentID:     &pid,
		LocationType: "datacenter",
		Description:  strPtr("Primary west-coast DC"),
		City:         strPtr("San Francisco"),
		Country:      strPtr("US"),
		Latitude:     &lat,
		Longitude:    &lng,
		Metadata:     models.JSONB{"tier": "1"},
		FullPath:     "US/California/SF Datacenter",
		CreatedAt:    now,
		UpdatedAt:    now,
		AssetCount:   intPtr(12),
	}
}

// minimalLocation leaves omitempty fields unset (absent, not null).
func minimalLocation() models.Location {
	now := time.Now().UTC()
	return models.Location{
		ID:           uuid.New(),
		TenantID:     uuid.New(),
		Name:         "Rack 7",
		LocationType: "rack",
		FullPath:     "Rack 7",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

const locBase = "/api/v2/inventory-service"

// --- the contract tests ----------------------------------------------------

func TestContract_ListLocations_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{list: []models.Location{sampleLocation(), minimalLocation()}, total: 2})
	w := do(eng, http.MethodGet, locBase+"/locations", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LocationListResponse", w.Body.Bytes())
}

func TestContract_GetLocationTree_200(t *testing.T) {
	sv := loadSpec(t)
	parent := sampleLocation()
	parent.Children = []models.Location{minimalLocation()} // exercise the recursive children
	eng := newLocationEngine(&stubLocationService{tree: []models.Location{parent}})
	w := do(eng, http.MethodGet, locBase+"/locations/tree", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LocationTreeResponse", w.Body.Bytes())
}

func TestContract_GetLocation_200(t *testing.T) {
	sv := loadSpec(t)
	l := sampleLocation()
	eng := newLocationEngine(&stubLocationService{byID: &l})
	w := do(eng, http.MethodGet, locBase+"/locations/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Location", w.Body.Bytes())
}

func TestContract_GetLocation_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{})
	w := do(eng, http.MethodGet, locBase+"/locations/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A nil location (no error) maps to 404.
func TestContract_GetLocation_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{byID: nil})
	w := do(eng, http.MethodGet, locBase+"/locations/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetLocationAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{assets: []models.Asset{sampleAsset()}, assetsTot: 1})
	w := do(eng, http.MethodGet, locBase+"/locations/"+aUUID+"/assets", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LocationAssetsResponse", w.Body.Bytes())
}

func TestContract_Location_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Location")
	if err != nil {
		t.Fatalf("compile Location: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Location, but it passed — the guardrail is not actually checking")
	}
}

// --- GET /locations/{id}/summary --------------------------------------------

func TestContract_GetLocationSummary_200(t *testing.T) {
	sv := loadSpec(t)
	loc := sampleLocation()
	eng := newLocationEngine(&stubLocationService{summary: &models.LocationSummary{
		Location:          loc,
		AssetCount:        12,
		CryptoConfigCount: 8,
		CertificateCount:  4,
		CriticalFindings:  1,
		HighFindings:      2,
		MediumFindings:    3,
		ExpiringCerts30D:  1,
		ExpiredCerts:      0,
	}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/locations/"+aUUID+"/summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LocationSummary", w.Body.Bytes())
}

func TestContract_GetLocationSummary_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/locations/not-a-uuid/summary", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// nil summary (no error) -> 404.
func TestContract_GetLocationSummary_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{summary: nil})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/locations/"+aUUID+"/summary", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetLocationSummary_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{summaryErr: io.EOF})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/locations/"+aUUID+"/summary", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- write surface: create / update / delete -------------------------

func TestContract_CreateLocation_201(t *testing.T) {
	sv := loadSpec(t)
	l := sampleLocation()
	eng := newLocationEngine(&stubLocationService{createResult: &l})
	body := strings.NewReader(`{"name":"SF DC","location_type":"datacenter"}`)
	w := do(eng, http.MethodPost, locBase+"/locations", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Location", w.Body.Bytes())
}

func TestContract_CreateLocation_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{})
	w := do(eng, http.MethodPost, locBase+"/locations", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateLocation_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{createErr: io.EOF})
	body := strings.NewReader(`{"name":"SF DC","location_type":"datacenter"}`)
	w := do(eng, http.MethodPost, locBase+"/locations", body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateLocation_200(t *testing.T) {
	sv := loadSpec(t)
	l := sampleLocation()
	eng := newLocationEngine(&stubLocationService{updateResult: &l})
	body := strings.NewReader(`{"name":"Renamed DC","location_type":"datacenter"}`)
	w := do(eng, http.MethodPut, locBase+"/locations/"+aUUID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Location", w.Body.Bytes())
}

func TestContract_UpdateLocation_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{})
	body := strings.NewReader(`{"name":"x","location_type":"rack"}`)
	w := do(eng, http.MethodPut, locBase+"/locations/not-a-uuid", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteLocation_204(t *testing.T) {
	eng := newLocationEngine(&stubLocationService{})
	w := do(eng, http.MethodDelete, locBase+"/locations/"+aUUID, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body on 204, got: %s", w.Body.String())
	}
}

func TestContract_DeleteLocation_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newLocationEngine(&stubLocationService{})
	w := do(eng, http.MethodDelete, locBase+"/locations/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
