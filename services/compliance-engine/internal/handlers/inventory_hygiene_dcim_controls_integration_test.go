package handlers

// Reachability for the DCIM hygiene controls (DCIM gap 6): the tenant reaches
// them in Risk & Compliance → Posture under Inventory Hygiene, whose control
// browser reads GET /frameworks/:id. Driven through the real handler over the
// SEEDED framework: every IH-007..IH-015 control is listed, at its severity,
// bound to its measurement, and its description names the page where the fix
// is made.
//
// Skips without TEST_DATABASE_URL (shared/testdb).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_InventoryHygiene_ListsDCIMControlsWithTheirPage(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	var frameworkID uuid.UUID
	if err := db.Get(&frameworkID, `SELECT id FROM platform_frameworks WHERE code = 'inventory-hygiene'`); err != nil {
		t.Fatalf("seeded inventory-hygiene: %v", err)
	}

	gin.SetMode(gin.TestMode)
	h := NewTenantFrameworkHandlers(services.NewTenantFrameworkService(db), services.NewFrameworkLicenseService(db))
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(sharedmw.CtxKeyTenantID, tenant); c.Next() })
	r.GET("/api/v1/compliance-engine/frameworks/:id", h.ViewFramework)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/compliance-engine/frameworks/"+frameworkID.String(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET framework: %d %s", w.Code, w.Body)
	}
	var body struct {
		Framework struct {
			Controls []struct {
				ControlID        string `json:"control_id"`
				Description      string `json:"description"`
				BaselineSeverity string `json:"baseline_severity"`
				Measurements     []struct {
					MeasurementType struct {
						Code string `json:"code"`
					} `json:"measurement_type"`
				} `json:"measurements"`
			} `json:"controls"`
		} `json:"framework"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := []struct{ control, severity, measurement, page string }{
		{"IH-007", "low", "unracked_count", "Infrastructure → Racks"},
		{"IH-008", "low", "rack_position_missing_count", "Infrastructure → Racks"},
		{"IH-009", "low", "stale_planned_cable_count", "Ports tab"},
		{"IH-010", "medium", "unconfirmed_cable_count", "Ports tab"},
		{"IH-011", "low", "untyped_interface_count", "Interfaces tab"},
		{"IH-012", "high", "duplicate_address_count", "Infrastructure → Networks"},
		{"IH-013", "medium", "warranty_expired_count", "Lifecycle card"},
		{"IH-014", "high", "past_end_of_support_count", "Lifecycle card"},
		{"IH-015", "medium", "end_of_support_soon_count", "Lifecycle card"},
	}
	for _, wc := range want {
		found := false
		for _, c := range body.Framework.Controls {
			if c.ControlID != wc.control {
				continue
			}
			found = true
			if c.BaselineSeverity != wc.severity {
				t.Errorf("%s severity %q, want %q", wc.control, c.BaselineSeverity, wc.severity)
			}
			if len(c.Measurements) != 1 || c.Measurements[0].MeasurementType.Code != wc.measurement {
				t.Errorf("%s measurements %+v, want exactly %s", wc.control, c.Measurements, wc.measurement)
			}
			if !strings.Contains(c.Description, wc.page) {
				t.Errorf("%s description does not name %q: %s", wc.control, wc.page, c.Description)
			}
		}
		if !found {
			t.Errorf("Inventory Hygiene does not list %s", wc.control)
		}
	}
}
