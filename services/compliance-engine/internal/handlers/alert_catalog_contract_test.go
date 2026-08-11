package handlers

// Contract test for the compliance-engine tenant alert-catalog HTTP surface
// (Settings → Alert Rules): GET /alert-catalog and PUT /alert-catalog/{type}.
//
// Same pattern as alert_contract_test.go: exercise the REAL gin handlers over
// httptest driven by an in-memory stub satisfying `alertCatalogService` (no
// database), asserting every response body conforms to the schema in
// api/openapi/compliance-engine.openapi.yaml. Shares loadSpec / assertConforms
// / do with framework_contract_test.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/alertcatalog"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// --- in-memory stub service -------------------------------------------------

// stubAlertCatalogService satisfies alertCatalogService.
type stubAlertCatalogService struct {
	catalog    []services.CatalogEntry
	catalogErr error
	updateErr  error
}

func (s *stubAlertCatalogService) GetCatalog(context.Context, uuid.UUID) ([]services.CatalogEntry, error) {
	return s.catalog, s.catalogErr
}
func (s *stubAlertCatalogService) UpdateSetting(context.Context, uuid.UUID, string, bool, map[string]int, uuid.UUID) error {
	return s.updateErr
}

// --- test harness ------------------------------------------------------------

// newAlertCatalogEngine mounts the alert-catalog routes on
// /api/v1/compliance-engine with the same tenant/user injection middleware as
// newAlertEngine. Production routes are registered in cmd/main.go; this
// mirrors them 1:1 for the contract surface only.
func newAlertCatalogEngine(s *stubAlertCatalogService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AlertCatalogHandlers{catalog: s}

	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/alert-catalog", h.GetCatalog)
	grp.PUT("/alert-catalog/:type", h.UpdateCatalogEntry)
	return r
}

// --- sample data ---------------------------------------------------------

// sampleCatalogEntry is a ladder-severity-model entry (certificate_expiring)
// with an effective ladder — exercises the fullest shape of AlertCatalogEntry.
func sampleCatalogEntry() services.CatalogEntry {
	return services.CatalogEntry{
		Entry: alertcatalog.Entry{
			ID:               "certificate_expiring",
			Track:            "tenant",
			Kind:             "policy",
			Status:           "live",
			Source:           "inventory-service",
			SubjectType:      "certificate",
			SeverityModel:    "ladder",
			BaselineDays:     60,
			BaselineSeverity: "medium",
			EnabledByDefault: true,
			Description:      "Certificate approaching expiry.",
		},
		Enabled:        true,
		PreferenceRung: map[string]int{"days": 45},
		Ladder: []alertcatalog.Rung{
			{Days: 45, Severity: "medium", Source: "preference"},
			{Days: 30, Severity: "high", Source: "policy:PCI-DSS"},
		},
	}
}

// sampleFixedCatalogEntry is a fixed-severity-model, operational entry
// (sensor_offline) — exercises the shape with the ladder/preference_rung
// fields both omitted.
func sampleFixedCatalogEntry() services.CatalogEntry {
	return services.CatalogEntry{
		Entry: alertcatalog.Entry{
			ID:               "sensor_offline",
			Track:            "tenant",
			Kind:             "operational",
			Status:           "live",
			Source:           "sensor-manager",
			SubjectType:      "sensor",
			SeverityModel:    "fixed",
			DefaultSeverity:  "high",
			EnabledByDefault: true,
			Description:      "Sensor heartbeat missed.",
		},
		Enabled: true,
	}
}

// --- the contract tests -----------------------------------------------------

func TestContract_GetAlertCatalog_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertCatalogEngine(&stubAlertCatalogService{
		catalog: []services.CatalogEntry{sampleCatalogEntry(), sampleFixedCatalogEntry()},
	})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alert-catalog", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertCatalogListResponse", w.Body.Bytes())
}

// Empty catalog serializes as `"catalog": []` (the handler initializes a
// non-nil slice before appending) — guards against the null-collection
// regression, same shape as ListAlerts_200_empty.
func TestContract_GetAlertCatalog_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertCatalogEngine(&stubAlertCatalogService{catalog: []services.CatalogEntry{}})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alert-catalog", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertCatalogListResponse", w.Body.Bytes())
}

func TestContract_GetAlertCatalog_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertCatalogEngine(&stubAlertCatalogService{catalogErr: errors.New("db down")})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alert-catalog", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateAlertCatalogEntry_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertCatalogEngine(&stubAlertCatalogService{})
	body := strings.NewReader(`{"enabled":true,"preference_rung":{"days":45}}`)
	w := do(eng, http.MethodPut, "/api/v1/compliance-engine/alert-catalog/certificate_expiring", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertCatalogUpdateResponse", w.Body.Bytes())
}

// Spec-quirk regression: `enabled` is required — a body without it fails
// binding with 400 (not 500).
func TestContract_UpdateAlertCatalogEntry_400_missingEnabled(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertCatalogEngine(&stubAlertCatalogService{})
	w := do(eng, http.MethodPut, "/api/v1/compliance-engine/alert-catalog/certificate_expiring", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Spec-quirk regression: an unknown alert type (or an out-of-range preference
// rung) is a service-layer validation error, mapped to 400 (not 404) by the
// handler regardless of the underlying cause.
func TestContract_UpdateAlertCatalogEntry_400_serviceError(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertCatalogEngine(&stubAlertCatalogService{updateErr: errors.New("unknown alert type: bogus_type")})
	body := strings.NewReader(`{"enabled":true}`)
	w := do(eng, http.MethodPut, "/api/v1/compliance-engine/alert-catalog/bogus_type", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
