package handlers

// Contract test for the operational overview + remediation-queue HTTP surface.
// Extends the inventory-service spec-first contract (ADR-0001) and reuses the
// shared harness (loadSpec / assertConforms / do / aUUID) from
// asset_contract_test.go — only the operational stub + engine + cases live here.
//
// OperationalHandler was made testable by depending on the operationalStore
// interface (the concrete *services.OperationalService still satisfies it), so
// these tests drive the real handlers with an in-memory stub — no database.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// --- stub operationalStore -------------------------------------------------

type stubOperationalStore struct {
	summaries       []models.LocationFindingSummaryRow
	summariesErr    error
	environments    []models.EnvironmentSummary
	environmentsErr error
	envAssets       []models.Asset
	envAssetsTotal  int
	envAssetsErr    error
	queue           []models.RemediationQueueRow
	queueTotal      int
	queueErr        error
	bySeverity      map[string]int
	byFinding       map[string]int
	statsTotal      int
	statsErr        error
}

func (s *stubOperationalStore) GetLocationSummaries(uuid.UUID) ([]models.LocationFindingSummaryRow, error) {
	return s.summaries, s.summariesErr
}
func (s *stubOperationalStore) GetLocationEnvironments(uuid.UUID, uuid.UUID) ([]models.EnvironmentSummary, error) {
	return s.environments, s.environmentsErr
}
func (s *stubOperationalStore) GetEnvironmentAssets(uuid.UUID, uuid.UUID, string, int, int) ([]models.Asset, int, error) {
	return s.envAssets, s.envAssetsTotal, s.envAssetsErr
}
func (s *stubOperationalStore) GetRemediationQueue(uuid.UUID, models.RemediationQueueFilters) ([]models.RemediationQueueRow, int, error) {
	return s.queue, s.queueTotal, s.queueErr
}
func (s *stubOperationalStore) GetRemediationQueueStats(uuid.UUID) (map[string]int, map[string]int, int, error) {
	return s.bySeverity, s.byFinding, s.statsTotal, s.statsErr
}

func newOperationalEngine(svc *stubOperationalStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	// RemediationTemplateService is pure in-memory (hardcoded defaults, no DB),
	// so the real service is used directly for the templates endpoint.
	h := &OperationalHandler{operational: svc, templates: services.NewRemediationTemplateService()}
	grp.GET("/operational/locations-summary", h.GetLocationsSummary)
	grp.GET("/operational/locations/:id/environments", h.GetLocationEnvironments)
	grp.GET("/operational/locations/:id/environments/:env/assets", h.GetEnvironmentAssets)
	grp.GET("/operational/remediation-queue", h.GetRemediationQueue)
	grp.GET("/operational/remediation-queue/stats", h.GetRemediationStats)
	grp.GET("/operational/remediation-templates", h.GetRemediationTemplates)
	return r
}

func sampleSummaryRow() models.LocationFindingSummaryRow {
	return models.LocationFindingSummaryRow{
		LocationID:        uuid.New(),
		TenantID:          uuid.New(),
		LocationName:      "SF Datacenter",
		LocationType:      "datacenter",
		FullPath:          strPtr("US/California/SF Datacenter"),
		Environment:       "production",
		AssetCount:        42,
		CryptoConfigCount: 80,
		CertificateCount:  30,
		CriticalFindings:  2,
		HighFindings:      5,
		MediumFindings:    8,
		LowFindings:       3,
		ExpiringCerts30D:  4,
		ExpiredCerts:      1,
	}
}

func sampleQueueRow() models.RemediationQueueRow {
	return models.RemediationQueueRow{
		TenantID:      uuid.New(),
		FindingType:   "weak_protocol",
		Severity:      "high",
		AssetID:       uuid.New(),
		AssetHostname: strPtr("web-01.example.com"),
		AssetIP:       strPtr("10.0.0.5"),
		AssetPort:     intPtr(443),
		DetailText:    "TLS 1.0 negotiated",
		CreatedAt:     time.Now().UTC(),
	}
}

const opBase = "/api/v2/inventory-service"

// --- the contract tests ----------------------------------------------------

func TestContract_OperationalLocationsSummary_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{summaries: []models.LocationFindingSummaryRow{sampleSummaryRow()}})
	w := do(eng, http.MethodGet, opBase+"/operational/locations-summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LocationsSummaryResponse", w.Body.Bytes())
}

func TestContract_RemediationQueue_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{queue: []models.RemediationQueueRow{sampleQueueRow()}, queueTotal: 1})
	w := do(eng, http.MethodGet, opBase+"/operational/remediation-queue", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RemediationQueueResponse", w.Body.Bytes())
}

func TestContract_RemediationStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{
		bySeverity: map[string]int{"high": 5, "medium": 8},
		byFinding:  map[string]int{"weak_protocol": 6},
		statsTotal: 13,
	})
	w := do(eng, http.MethodGet, opBase+"/operational/remediation-queue/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RemediationStatsResponse", w.Body.Bytes())
}

func TestContract_OperationalSummary_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/LocationFindingSummaryRow")
	if err != nil {
		t.Fatalf("compile LocationFindingSummaryRow: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"location_id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted LocationFindingSummaryRow, but it passed — the guardrail is not actually checking")
	}
}

// --- environments + env-assets + remediation-templates ----------------------

func sampleEnvironmentSummary() models.EnvironmentSummary {
	return models.EnvironmentSummary{
		Environment:       "production",
		AssetCount:        42,
		CryptoConfigCount: 80,
		CertificateCount:  30,
		CriticalFindings:  2,
		HighFindings:      5,
		MediumFindings:    8,
		LowFindings:       3,
		ExpiringCerts30D:  4,
		ExpiredCerts:      1,
	}
}

func TestContract_LocationEnvironments_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{environments: []models.EnvironmentSummary{sampleEnvironmentSummary()}})
	w := do(eng, http.MethodGet, opBase+"/operational/locations/"+aUUID+"/environments", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EnvironmentsResponse", w.Body.Bytes())
}

func TestContract_LocationEnvironments_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{})
	w := do(eng, http.MethodGet, opBase+"/operational/locations/not-a-uuid/environments", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_EnvironmentAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{envAssets: []models.Asset{sampleAsset()}, envAssetsTotal: 1})
	w := do(eng, http.MethodGet, opBase+"/operational/locations/"+aUUID+"/environments/production/assets", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EnvironmentAssetsResponse", w.Body.Bytes())
}

// Empty result → the handler returns a nil slice → `{"assets": null, ...}`.
func TestContract_EnvironmentAssets_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{envAssets: nil, envAssetsTotal: 0})
	w := do(eng, http.MethodGet, opBase+"/operational/locations/"+aUUID+"/environments/production/assets", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EnvironmentAssetsResponse", w.Body.Bytes())
}

func TestContract_EnvironmentAssets_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{})
	w := do(eng, http.MethodGet, opBase+"/operational/locations/not-a-uuid/environments/production/assets", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Templates come from the real (pure in-memory) RemediationTemplateService.
func TestContract_RemediationTemplates_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOperationalEngine(&stubOperationalStore{})
	w := do(eng, http.MethodGet, opBase+"/operational/remediation-templates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RemediationTemplatesResponse", w.Body.Bytes())
}

func TestContract_EnvironmentSummary_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/EnvironmentSummary")
	if err != nil {
		t.Fatalf("compile EnvironmentSummary: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"environment":"production","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted EnvironmentSummary, but it passed — the guardrail is not actually checking")
	}
}
