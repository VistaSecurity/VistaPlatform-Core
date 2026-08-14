package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// Even on the internal transport the status is not taken verbatim: only
// "monitoring" (a rule discovery-processor already matched) moves off the
// default, and auto_approve is not part of the wire shape at all — a body
// carrying it binds cleanly and changes nothing.
func TestResolveIngestedAssetStatus_DefaultsDenyAndIgnoresAutoApprove(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"auto_approve is not read at all", `{"findings":[],"auto_approve":true}`, "pending_approval"},
		{"unknown status falls back", `{"findings":[],"asset_status":"approved"}`, "pending_approval"},
		{"denied cannot be asserted", `{"findings":[],"asset_status":"denied"}`, "pending_approval"},
		{"empty status falls back", `{"findings":[],"asset_status":""}`, "pending_approval"},
		{"absent status falls back", `{"findings":[]}`, "pending_approval"},
		{"monitoring is honoured", `{"findings":[],"asset_status":"monitoring"}`, "monitoring"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body ingestFindingsBody
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatalf("bind %s: %v", tc.body, err)
			}
			if got := resolveIngestedAssetStatus(body.AssetStatus); got != tc.want {
				t.Fatalf("body %s resolved to %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
