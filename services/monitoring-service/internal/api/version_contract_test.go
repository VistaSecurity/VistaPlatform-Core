package api

// Contract test for GET /monitoring-service/version (the About-page version
// aggregator). Reuses the status harness (statusLoadSpec / statusDo /
// statusBase) from status_contract_test.go — only the version engine + case
// live here.
//
// The aggregator fans out to peer /health endpoints over HTTP; constructing it
// with an EMPTY peer map means no network calls, so the real handler is driven
// over httptest and its body asserted against the spec.

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func newVersionEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	agg := NewVersionAggregator(map[string]string{}, nil) // no peers → no network; nil → plain client
	r := gin.New()
	grp := r.Group(statusBase)
	grp.GET("/version", agg.Handle)
	return r
}

func TestContract_GetVersion_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newVersionEngine()
	w := statusDo(eng, http.MethodGet, statusBase+"/version")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "VersionResponse", w.Body.Bytes())
}
