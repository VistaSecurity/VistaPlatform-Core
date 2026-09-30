package cbom

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Core answers 402 on the comparison routes, not a bare 404.
//
// A 404 from `/cbom/compare/:base/:head` reads as "those artifacts do not
// exist" — which is what the MCP compare tool led an agent to conclude. The
// documented answer for a capability outside the edition is 402 with the same
// body shape RequireFeature writes.
func TestCoreComparisonRoutesAnswer402(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := r.Group("/api/v1/cbom-service")
	RegisterUnavailableComparisonRoutes(api)

	const a, b = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	for _, tc := range []struct{ name, method, path, body string }{
		{"GET url form", http.MethodGet, "/api/v1/cbom-service/cbom/compare/" + a + "/" + b, ""},
		{"POST body form", http.MethodPost, "/api/v1/cbom-service/cbom/compare", `{"base_id":"` + a + `","head_id":"` + b + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
			}
			var body struct {
				Error   string `json:"error"`
				Feature string `json:"feature"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v (%s)", err, w.Body.String())
			}
			if !strings.Contains(body.Error, "not included in your subscription") {
				t.Errorf("error = %q, want the documented 'not included in your subscription' sentence", body.Error)
			}
			if body.Feature != FeatureCBOMSigning {
				t.Errorf("feature = %q, want %q (the key the UI upgrade card keys on)", body.Feature, FeatureCBOMSigning)
			}
		})
	}
}

// The stubs must not swallow a neighbouring route: only comparison is refused.
func TestCoreComparisonStubsDoNotShadowOtherRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := r.Group("/api/v1/cbom-service")
	RegisterUnavailableComparisonRoutes(api)
	api.GET("/cbom/artifacts", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/cbom-service/cbom/artifacts", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("artifacts list = %d, want 200", w.Code)
	}
}
