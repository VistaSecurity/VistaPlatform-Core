package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Skip() opts one route out of LogRequest. The sibling route on the same group
// must still be recorded, or the opt-out has silently become "audit nothing".
//
// To mutation-test: delete the skipContextKey check in LogRequest and the
// skipped-route assertion fails; make Skip a no-op and it fails the same way.
func TestSkipRouteIsNotRecordedButSiblingIs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BatchSize = 1000 // never flushed during the test
	m := &Middleware{config: cfg, batch: make([]*ActivityLogRequest, 0, cfg.BatchSize), stopChan: make(chan struct{})}

	r := gin.New()
	r.Use(m.LogRequest())
	g := r.Group("/api/v1/svc/things/:id")
	g.POST("/heartbeat", Skip(), func(c *gin.Context) { c.Status(http.StatusOK) })
	g.GET("/poll", Skip(), func(c *gin.Context) { c.Status(http.StatusOK) })
	g.POST("/submit", func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(method, path string) {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
	}

	do(http.MethodPost, "/api/v1/svc/things/abc/heartbeat")
	do(http.MethodGet, "/api/v1/svc/things/abc/poll")
	if got := m.PendingEntries(); len(got) != 0 {
		t.Fatalf("skipped routes produced %d audit entries, want 0: %+v", len(got), got[0])
	}

	do(http.MethodPost, "/api/v1/svc/things/abc/submit")
	if got := m.PendingEntries(); len(got) != 1 {
		t.Fatalf("non-skipped sibling produced %d audit entries, want 1", len(got))
	}
}
