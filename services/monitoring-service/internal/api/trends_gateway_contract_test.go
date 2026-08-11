package api

// Contract tests for the monitoring-service admin-ui surfaces beyond status +
// alerting (ADR-0001): historical trends, admin system-status, and the Traefik
// gateway proxy. UI consumers: admin-ui status-api.ts + gateway-api.ts.
//
// trends + admin-status run over an in-memory metricsProvider stub (the field is
// now the narrow interface; see metrics_provider.go). The gateway handlers
// transparently proxy Traefik's dashboard API — the test points them at an
// httptest server via TRAEFIK_DASHBOARD_URL, so they're exercised with no real
// Traefik. Reuses statusLoadSpec / assertConforms / statusDo / statusBase.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/services"
)

// --- metrics stub -----------------------------------------------------------

type stubMetricsProvider struct {
	trends    []services.TrendPoint
	trendsErr error
	platform  models.SystemMetrics
}

func (s *stubMetricsProvider) GetHistoricalTrends(string, string, int, time.Time, time.Time) ([]services.TrendPoint, error) {
	return s.trends, s.trendsErr
}
func (s *stubMetricsProvider) GetPlatformMetrics() (models.SystemMetrics, error) {
	return s.platform, nil
}
func (s *stubMetricsProvider) GetPlatformMetricsSummary(time.Time, time.Time) (*models.PlatformMetricsSummary, error) {
	return nil, nil
}
func (s *stubMetricsProvider) GetServiceMetrics(string, time.Duration) (*models.ServiceMetrics, error) {
	return nil, nil
}
func (s *stubMetricsProvider) GetIncidentHistory(int) ([]models.Incident, error) { return nil, nil }
func (s *stubMetricsProvider) GetUptimeStats() (*models.UptimeStats, error)      { return nil, nil }
func (s *stubMetricsProvider) GetTenantPerformanceSummary(uuid.UUID) (*models.TenantPerformanceSummary, error) {
	return nil, nil
}

func sampleTrendPoint() services.TrendPoint {
	v := 42.5
	return services.TrendPoint{Timestamp: time.Now().UTC(), Value: &v, Status: "ok"}
}

// --- trends -----------------------------------------------------------------

func newTrendsEngine(mp metricsProvider) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithMetrics(mp)
	r := gin.New()
	r.Group(statusBase).GET("/trends", srv.GetHistoricalTrends)
	return r
}

func TestContract_GetHistoricalTrends_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newTrendsEngine(&stubMetricsProvider{trends: []services.TrendPoint{sampleTrendPoint()}})
	w := statusDo(eng, http.MethodGet, statusBase+"/trends?metric_type=latency_p95&window=1h")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrendsResponse", w.Body.Bytes())
}

// Empty series → nil slice → `"trends": null`.
func TestContract_GetHistoricalTrends_200_empty(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newTrendsEngine(&stubMetricsProvider{trends: nil})
	w := statusDo(eng, http.MethodGet, statusBase+"/trends")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrendsResponse", w.Body.Bytes())
}

func TestContract_GetHistoricalTrends_400_window(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newTrendsEngine(&stubMetricsProvider{})
	w := statusDo(eng, http.MethodGet, statusBase+"/trends?window=bogus")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetHistoricalTrends_400_metric(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newTrendsEngine(&stubMetricsProvider{})
	w := statusDo(eng, http.MethodGet, statusBase+"/trends?metric_type=bogus")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetHistoricalTrends_500(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newTrendsEngine(&stubMetricsProvider{trendsErr: errPing})
	w := statusDo(eng, http.MethodGet, statusBase+"/trends?metric_type=error_rate&window=1d")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- admin status -----------------------------------------------------------

func TestContract_GetAdminSystemStatus_200(t *testing.T) {
	sv := statusLoadSpec(t)
	srv := newServerWithHealthAndMetrics(&stubHealthProvider{status: sampleSystemStatus()}, &stubMetricsProvider{})
	r := gin.New()
	r.Group(statusBase).GET("/admin/status", srv.getAdminSystemStatus)
	w := statusDo(r, http.MethodGet, statusBase+"/admin/status")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemStatusResponse", w.Body.Bytes())
}

// --- gateway proxy ----------------------------------------------------------

func newGatewayEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := &Server{}
	r := gin.New()
	g := r.Group(statusBase + "/gateway")
	g.GET("/overview", srv.getGatewayOverview)
	g.GET("/routers", srv.getGatewayRouters)
	g.GET("/services", srv.getGatewayServices)
	g.GET("/middlewares", srv.getGatewayMiddlewares)
	return r
}

// 200: a stand-in Traefik returns valid JSON; the handler passes it through.
func TestContract_Gateway_200(t *testing.T) {
	sv := statusLoadSpec(t)
	traefik := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/overview" {
			_, _ = w.Write([]byte(`{"http":{"routers":{"total":3}}}`))
			return
		}
		_, _ = w.Write([]byte(`[{"name":"web@docker"}]`)) // routers/services/middlewares are arrays
	}))
	defer traefik.Close()
	t.Setenv("TRAEFIK_DASHBOARD_URL", traefik.URL)

	eng := newGatewayEngine()
	for _, p := range []string{"/gateway/overview", "/gateway/routers", "/gateway/services", "/gateway/middlewares"} {
		w := statusDo(eng, http.MethodGet, statusBase+p)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200; body=%s", p, w.Code, w.Body.String())
		}
		sv.assertConforms(t, "GatewayPassthrough", w.Body.Bytes())
	}
}

// Not configured (env unset) → 503.
func TestContract_Gateway_503_unconfigured(t *testing.T) {
	sv := statusLoadSpec(t)
	os.Unsetenv("TRAEFIK_DASHBOARD_URL")
	eng := newGatewayEngine()
	w := statusDo(eng, http.MethodGet, statusBase+"/gateway/overview")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Unreachable upstream → 503.
func TestContract_Gateway_503_unreachable(t *testing.T) {
	sv := statusLoadSpec(t)
	t.Setenv("TRAEFIK_DASHBOARD_URL", "http://127.0.0.1:1")
	eng := newGatewayEngine()
	w := statusDo(eng, http.MethodGet, statusBase+"/gateway/overview")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Upstream returns non-JSON → 502.
func TestContract_Gateway_502(t *testing.T) {
	sv := statusLoadSpec(t)
	traefik := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer traefik.Close()
	t.Setenv("TRAEFIK_DASHBOARD_URL", traefik.URL)

	eng := newGatewayEngine()
	w := statusDo(eng, http.MethodGet, statusBase+"/gateway/overview")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
