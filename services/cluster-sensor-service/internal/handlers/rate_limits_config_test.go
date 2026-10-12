package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// PUT /config/rate-limits refuses a value that would break job creation, naming
// the field, before it reaches the database. The limiter here has no database:
// a request that got past validation would panic, not return 400.
func TestUpdateRateLimits_RejectsOutOfRangeValuesNamingTheField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &DiscoveryHandler{rateLimiter: services.NewRateLimiter(nil)}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(sharedmw.CtxKeyTenantID, uuid.New())
		c.Next()
	})
	r.PUT("/config/rate-limits", h.UpdateRateLimits)

	for body, field := range map[string]string{
		`{"concurrent_jobs": 0}`:                    "concurrent_jobs",
		`{"concurrent_jobs": -1}`:                   "concurrent_jobs",
		`{"scans_per_hour": 0}`:                     "scans_per_hour",
		`{"scans_per_hour": 100001}`:                "scans_per_hour",
		`{"max_targets_per_job": 0}`:                "max_targets_per_job",
		`{"max_targets_per_job": 1001}`:             "max_targets_per_job",
		`{"is_active": true, "concurrent_jobs": 0}`: "concurrent_jobs",
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/config/rate-limits", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), field) {
			t.Errorf("PUT %s = %d %s, want 400 naming %s", body, w.Code, w.Body.String(), field)
		}
	}
}

// A refusal at a limit is a 429 naming the limit; too many targets is a 400
// naming the number — neither collapses into the generic create failure.
func TestWriteCreateJobError_MapsLimitRefusals(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, tc := range map[string]struct {
		err    error
		status int
		want   string
	}{
		"rate limit": {&services.RateLimitExceededError{Limit: "concurrent jobs", Count: 3, Max: 3}, http.StatusTooManyRequests, "concurrent jobs (3/3)"},
		"wrapped":    {errors.Join(errors.New("x"), &services.RateLimitExceededError{Limit: "scans this hour", Count: 2, Max: 2}), http.StatusTooManyRequests, "scans this hour"},
		"too many":   {&services.TooManyTargetsError{Max: 2, Got: 3}, http.StatusBadRequest, "limit is 2 per job"},
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		writeCreateJobError(c, tc.err)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want %d containing %q", name, w.Code, w.Body.String(), tc.status, tc.want)
		}
	}
}
