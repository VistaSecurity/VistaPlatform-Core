package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// POST /discovery/jobs/{id}/import is the ingestion transport
// discovery-processor-service uses. It used to be a tenant-facing endpoint too:
// the Discover wizard fetched a job's results into the browser and posted them
// back, and the body's asset_status / auto_approve were honoured — so any caller
// holding discovery.create could post auto_approve:true and inject assets
// straight to `monitoring`, bypassing the tenant's approval policy entirely.
//
// The gateway exposes /api/v1/inventory-service/* wholesale, so this route is
// still reachable from a browser. The guard, not the route table, is what makes
// it internal — which is why it is tested here.
func TestIngestPipelineFindings_RejectsNonInternalCallers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &DiscoveryHandler{}

	body := `{"findings":[{"resolved_ip":"192.0.2.10","port":443,"protocol":"TLS"}],"asset_status":"monitoring","auto_approve":true}`

	engine := gin.New()
	engine.POST("/discovery/jobs/:id/import", func(c *gin.Context) {
		// A logged-in tenant user: tenant in context, but NOT an internal call.
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		h.IngestPipelineFindings(c)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/discovery/jobs/"+uuid.New().String()+"/import", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("a tenant-authenticated caller got %d, want 403 — this endpoint accepts an approval status and must be unreachable from any client", w.Code)
	}
}

// The body has no status a caller can set. Since WP3 inventory-service
// evaluates the tenant's auto-approval rules itself, so asset_status (which
// discovery-processor used to send) and auto_approve are both outside the
// wire shape: a body carrying them binds, and nothing reads them. The
// behavioural half — a "monitoring" asset_status leaves a new asset pending —
// is TestIntegration_RoutePipelineImport_IgnoresSuppliedStatus.
func TestIngestFindingsBody_CarriesNoStatus(t *testing.T) {
	var body ingestFindingsBody
	if err := json.Unmarshal([]byte(`{"findings":[],"asset_status":"monitoring","auto_approve":true}`), &body); err != nil {
		t.Fatalf("a legacy body must still bind: %v", err)
	}
	typ := reflect.TypeOf(body)
	if typ.NumField() != 1 || typ.Field(0).Name != "Findings" {
		t.Fatalf("ingestFindingsBody grew a field (%d fields); a caller-settable status is what this transport must not carry", typ.NumField())
	}
}
