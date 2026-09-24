package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/scoring"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/service"
	"github.com/vistasecurity/vistaplatform/shared/healthbands"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// RC-14 / decision 8, through the REAL router main() serves (newRouter), the
// real auth + platform.health gate, and a real Postgres:
//
//   - health_alerts are reconciled, not appended: recalculating the same band
//     leaves ONE active alert per type, a band change updates it in place, and
//     a recovered tenant has its alerts resolved;
//   - the board's active_alerts counts every active alert, not only critical;
//   - a soft-deleted tenant leaves the board;
//   - the response still matches the TenantHealthSummary contract.

const boardSigningValue = "tenant-health-board-integration-signing-value"

type boardHarness struct {
	t      *testing.T
	db     *sql.DB
	router *gin.Engine
	bearer string
}

func newBoardHarness(t *testing.T) *boardHarness {
	t.Helper()
	db := testdb.Connect(t)
	gin.SetMode(gin.TestMode)
	svc := service.NewHealthService(repository.NewHealthRepository(db, db))
	router := newRouter(handlers.NewHealthHandlers(svc), newTestAuditMiddleware(t), boardSigningValue, "unused-internal-value", db)

	role := testdb.NewPlatformRole(t, db, rbac.PermissionPlatformHealth)
	user := testdb.NewPlatformUser(t, db, role)
	return &boardHarness{t: t, db: db, router: router, bearer: testdb.SignPlatformToken(t, boardSigningValue, user, "support_agent")}
}

func (h *boardHarness) do(method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+h.bearer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	if testdb.RefusedByPlatformGate(w) {
		h.t.Fatalf("%s %s refused by the platform gate: %d %s", method, path, w.Code, w.Body.String())
	}
	return w
}

// metricsFor returns fully-measured metrics whose overall health lands in the
// wanted band, and fails the test if the scorer disagrees — the fixtures must
// not silently drift into a different band when the index changes.
func metricsFor(t *testing.T, tenant uuid.UUID, band healthbands.Band) models.HealthMetrics {
	t.Helper()
	m := models.HealthMetrics{
		TenantID: tenant, Timestamp: time.Now(), LastSecurityUpdate: time.Now(),
		FeatureUsage: map[string]int{},
	}
	switch band {
	case healthbands.Failing:
		// Slow, idle, 50% compliance, no cost efficiency.
		m.AvgResponseTime, m.ErrorRate, m.ComplianceScore = 1000, 0.05, 50
	case healthbands.Poor:
		m.AvgResponseTime, m.ErrorRate, m.ComplianceScore, m.CostEfficiency = 1000, 0.05, 100, 100
	case healthbands.Excellent:
		m.AvgResponseTime, m.Throughput, m.Uptime, m.ComplianceScore = 100, 1000, 99.99, 100
		m.ActiveUsers, m.APICalls, m.UserEngagement, m.CostEfficiency = 1000, 10000, 100, 100
		m.FeatureUsage = map[string]int{"a": 1, "b": 1, "c": 1, "d": 1, "e": 1}
	default:
		t.Fatalf("no fixture for band %s", band)
	}
	if got := scoring.NewHealthScorer().CalculateHealthScore(m).HealthStatus; got != string(band) {
		t.Fatalf("fixture for %s scores as %s — adjust metricsFor", band, got)
	}
	return m
}

func (h *boardHarness) calculate(tenant uuid.UUID, band healthbands.Band) {
	h.t.Helper()
	w := h.do(http.MethodPost, "/api/v1/tenant-health-service/calculate",
		models.HealthScoreRequest{TenantID: tenant, Metrics: metricsFor(h.t, tenant, band)})
	if w.Code != http.StatusOK {
		h.t.Fatalf("POST /calculate (%s) = %d %s", band, w.Code, w.Body.String())
	}
}

func (h *boardHarness) activeAlerts(tenant uuid.UUID) []models.HealthAlert {
	h.t.Helper()
	w := h.do(http.MethodGet, "/api/v1/tenant-health-service/tenants/"+tenant.String()+"/alerts", nil)
	if w.Code != http.StatusOK {
		h.t.Fatalf("GET alerts = %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Alerts []models.HealthAlert `json:"alerts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		h.t.Fatal(err)
	}
	return out.Alerts
}

func (h *boardHarness) board() map[uuid.UUID]map[string]any {
	h.t.Helper()
	w := h.do(http.MethodGet, "/api/v1/tenant-health-service/tenants?limit=10000", nil)
	if w.Code != http.StatusOK {
		h.t.Fatalf("GET /tenants = %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Tenants []map[string]any `json:"tenants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		h.t.Fatal(err)
	}
	rows := map[uuid.UUID]map[string]any{}
	for _, r := range out.Tenants {
		id, err := uuid.Parse(r["tenant_id"].(string))
		if err != nil {
			h.t.Fatal(err)
		}
		rows[id] = r
	}
	return rows
}

// allRows counts every health_alerts row for the tenant, active or not.
func (h *boardHarness) allRows(tenant uuid.UUID) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM health_alerts WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func byType(alerts []models.HealthAlert) map[string][]models.HealthAlert {
	out := map[string][]models.HealthAlert{}
	for _, a := range alerts {
		out[a.AlertType] = append(out[a.AlertType], a)
	}
	return out
}

func TestIntegration_HealthAlertsReconcileThroughRealRouter(t *testing.T) {
	h := newBoardHarness(t)
	tenant := testdb.NewTenant(t, h.db)

	// Failing: one critical health_decline (plus the recommendations alert).
	h.calculate(tenant, healthbands.Failing)
	first := byType(h.activeAlerts(tenant))
	if len(first["health_decline"]) != 1 || first["health_decline"][0].Severity != "critical" {
		t.Fatalf("after failing: health_decline alerts = %+v, want one critical", first["health_decline"])
	}
	declineID := first["health_decline"][0].ID
	rowsAfterFirst := h.allRows(tenant)

	// Same band again: nothing is appended. This is the insert-only bug — every
	// 30-minute cycle used to add another copy of every alert.
	h.calculate(tenant, healthbands.Failing)
	h.calculate(tenant, healthbands.Failing)
	if n := h.allRows(tenant); n != rowsAfterFirst {
		t.Fatalf("recalculating the same band grew health_alerts %d -> %d rows; alerts must be upserted per (tenant, type)", rowsAfterFirst, n)
	}

	// Failing -> poor: the ONE health_decline alert follows the band.
	h.calculate(tenant, healthbands.Poor)
	poor := byType(h.activeAlerts(tenant))
	if len(poor["health_decline"]) != 1 {
		t.Fatalf("after poor: %d active health_decline alerts, want exactly 1", len(poor["health_decline"]))
	}
	if a := poor["health_decline"][0]; a.ID != declineID || a.Severity != "high" || a.Title != "Poor Health Status" {
		t.Fatalf("after poor: health_decline = %+v, want the same alert (%s) updated to high / Poor Health Status", a, declineID)
	}

	// The board counts EVERY active alert. Poor raises a HIGH alert, not a
	// critical one, which the old critical-only column showed as 0.
	row := h.board()[tenant]
	if row == nil {
		t.Fatal("tenant missing from the board")
	}
	active := len(h.activeAlerts(tenant))
	if got := int(row["active_alerts"].(float64)); got != active || got == 0 {
		t.Fatalf("board active_alerts = %d, want %d (every active alert)", got, active)
	}
	if got := int(row["critical_alerts"].(float64)); got != 0 {
		t.Fatalf("board critical_alerts = %d, want 0 — poor raises a high alert", got)
	}

	// A calculation that measured NOTHING (every peer down) is no evidence of
	// recovery: the open alerts must stay open, not be resolved by default.
	unknown := models.HealthMetrics{TenantID: tenant, Timestamp: time.Now(), FeatureUsage: map[string]int{},
		UnavailableSources: []string{models.SourceMonitoring, models.SourceAuth, models.SourceInventory, models.SourceResourceTracker}}
	if w := h.do(http.MethodPost, "/api/v1/tenant-health-service/calculate",
		models.HealthScoreRequest{TenantID: tenant, Metrics: unknown}); w.Code != http.StatusOK {
		t.Fatalf("POST /calculate (unknown) = %d %s", w.Code, w.Body.String())
	}
	if got := byType(h.activeAlerts(tenant))["health_decline"]; len(got) != 1 || got[0].ID != declineID {
		t.Fatalf("an unmeasured calculation changed the open alerts: health_decline = %+v", got)
	}

	// Recovery resolves everything the new calculation no longer raises. The
	// stale "Poor Health Status" next to a good score is the reported bug.
	h.calculate(tenant, healthbands.Excellent)
	if left := h.activeAlerts(tenant); len(left) != 0 {
		t.Fatalf("after recovery %d alert(s) still active: %+v", len(left), left)
	}
	var resolvedAt sql.NullTime
	if err := h.db.QueryRow(`SELECT resolved_at FROM health_alerts WHERE id = $1 AND NOT is_active`, declineID).Scan(&resolvedAt); err != nil || !resolvedAt.Valid {
		t.Fatalf("health_decline alert %s was not resolved (resolved_at=%v, err=%v)", declineID, resolvedAt, err)
	}
	if got := int(h.board()[tenant]["active_alerts"].(float64)); got != 0 {
		t.Fatalf("board active_alerts after recovery = %d, want 0", got)
	}
}

func TestIntegration_HealthBoardExcludesSoftDeletedTenants(t *testing.T) {
	h := newBoardHarness(t)
	live := testdb.NewTenant(t, h.db)
	gone := testdb.NewTenant(t, h.db)
	h.calculate(live, healthbands.Poor)
	h.calculate(gone, healthbands.Poor)

	if _, err := h.db.Exec(`UPDATE tenants SET deleted_at = now() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	board := h.board()
	if board[live] == nil {
		t.Fatal("live tenant missing from the board")
	}
	if board[gone] != nil {
		t.Fatalf("soft-deleted tenant %s is still on the board: %v", gone, board[gone])
	}
}

// The board rows keep matching the published contract: every required key
// present, nothing the schema does not declare (it is additionalProperties:
// false, and the generated client types the console reads from it).
func TestIntegration_HealthBoardMatchesContract(t *testing.T) {
	h := newBoardHarness(t)
	tenant := testdb.NewTenant(t, h.db)
	h.calculate(tenant, healthbands.Poor)

	raw, err := os.ReadFile("../../../api/openapi/tenant-health-service.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string       `yaml:"required"`
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	schema := spec.Components.Schemas["TenantHealthSummary"]
	if !slices.Contains(schema.Required, "active_alerts") {
		t.Fatal("contract does not require active_alerts")
	}

	row := h.board()[tenant]
	var got, declared []string
	for k := range row {
		got = append(got, k)
	}
	for k := range schema.Properties {
		declared = append(declared, k)
	}
	sort.Strings(got)
	sort.Strings(declared)
	for _, k := range schema.Required {
		if _, ok := row[k]; !ok {
			t.Errorf("board row lacks required key %q (row keys %v)", k, got)
		}
	}
	for _, k := range got {
		if !slices.Contains(declared, k) {
			t.Errorf("board row carries undeclared key %q (declared %v)", k, declared)
		}
	}
}
