package main

// network-segments/classify-asset is gone ( WP3, F2). discovery-processor
// was its only caller: it classified every discovery here, then the import
// classified the same finding again. The import is now the one classifier, so
// the route, its handler and the processor's client method were deleted.
//
// main.go registers its routes inline in main(), so no test can build the
// production engine. This builds a gin router from main.go's OWN registration
// table — every api / apiv2 registration, under its real group prefix — with a
// stub handler, so the request below is matched exactly as the production
// router would match it, wildcard siblings (`/infrastructure-assets/:id`, …)
// included. Both polarities: the deleted route 404s, and a sibling registered
// beside it still answers, so a broken scan cannot pass vacuously.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func routeTableEngine(t *testing.T) *gin.Engine {
	t.Helper()
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	groups := map[string]*gin.RouterGroup{"api": r.Group("/api/v1"), "apiv2": r.Group("/api/v2")}
	stub := func(c *gin.Context) { c.Status(http.StatusTeapot) }
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		m := routeReg.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		groups[m[1]].Handle(m[2], m[3], stub)
		n++
	}
	if n < 100 {
		t.Fatalf("scanned only %d registrations from %s; the scan is broken", n, mainPath)
	}
	return r
}

func TestRouteClassifyAssetIsGone(t *testing.T) {
	r := routeTableEngine(t)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/api/v2/inventory-service/network-segments/classify-asset", http.StatusNotFound},
		{http.MethodPost, "/api/v1/inventory-service/network-segments/classify-asset", http.StatusNotFound},
		// DCIM row 1.6: the segment and space routes are retired with the
		// table; prefixes are /ipam/prefixes.
		{http.MethodGet, "/api/v2/inventory-service/network-segments", http.StatusNotFound},
		{http.MethodPost, "/api/v2/inventory-service/network-segments/bulk", http.StatusNotFound},
		{http.MethodPost, "/api/v2/inventory-service/network-segments/reclassify-all", http.StatusNotFound},
		{http.MethodGet, "/api/v2/inventory-service/network-segments/00000000-0000-0000-0000-000000000001", http.StatusNotFound},
		{http.MethodPost, "/api/v2/inventory-service/network-segments/00000000-0000-0000-0000-000000000001/claim", http.StatusNotFound},
		{http.MethodGet, "/api/v1/inventory-service/network-spaces", http.StatusNotFound},
		{http.MethodGet, "/api/v1/network-spaces", http.StatusNotFound},
		{http.MethodGet, "/api/v2/inventory-service/network-spaces", http.StatusNotFound},
		// Siblings that must still be mounted.
		{http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/enrich-all", http.StatusTeapot},
		{http.MethodPost, "/api/v1/inventory-service/discovery/jobs/00000000-0000-0000-0000-000000000001/import", http.StatusTeapot},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}
