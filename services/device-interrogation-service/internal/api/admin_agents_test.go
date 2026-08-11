package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Server-side operator tenant scope for GET /admin/agents.
//
// A malformed tenant_id must be rejected with 400 by the handler BEFORE any
// store call — so it never surfaces as a 500 from the uuid-typed tenant_id
// column. The validation short-circuits ahead of NewAgentService, so this
// exercises the real handler with nil db/redis (never dereferenced on this
// path). Mirrors TestListAdminJobs_InvalidTenantID in the jobs contract test.
func TestAdminListAgents_InvalidTenantID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/agents", adminListAgentsHandler(nil, nil, nil))

	req := httptest.NewRequest(http.MethodGet, "/admin/agents?tenant_id=not-a-uuid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed tenant_id, got %d (body=%s)", w.Code, w.Body.String())
	}
}
