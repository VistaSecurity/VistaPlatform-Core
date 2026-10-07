package handlers

// POST /sensors/:sensor_id/discoveries decoded whatever body arrived — a
// sensor sends 100 discoveries a call by default, and nothing stopped one call
// carrying millions, all decoded into memory and written in one transaction.
// These tests drive the handler as the sensor-manager router mounts it (a
// path-parameter route, the handler first thing after authentication) and pin
// the byte ceiling and the per-batch count ceiling. The Handler has no service
// behind it: a request that is refused never reaches it, and one that is not
// refused panics into gin.Recovery's 500 — which is how "reached the service"
// shows up here.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type endlessJSON struct {
	n      atomic.Int64
	opened bool
}

func (b *endlessJSON) Read(p []byte) (int, error) {
	i := 0
	if !b.opened {
		i = copy(p, `{"discoveries":[{"host":"`)
		b.opened = true
	}
	for ; i < len(p); i++ {
		p[i] = 'a'
	}
	b.n.Add(int64(len(p)))
	return len(p), nil
}

func discoveriesEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	h := &Handler{}
	r.POST("/sensors/:sensor_id/discoveries", h.SubmitDiscoveries)
	return r
}

func postDiscoveries(r *gin.Engine, body *httptest.ResponseRecorder, req *http.Request) *httptest.ResponseRecorder {
	r.ServeHTTP(body, req)
	return body
}

func TestSubmitDiscoveries_RefusesAnOversizeDeclaredBody(t *testing.T) {
	r := discoveriesEngine()
	req := httptest.NewRequest(http.MethodPost, "/sensors/"+uuid.NewString()+"/discoveries",
		strings.NewReader(strings.Repeat("a", maxDiscoveryBatchBytes+1)))
	req.Header.Set("Content-Type", "application/json")
	w := postDiscoveries(r, httptest.NewRecorder(), req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
}

func TestSubmitDiscoveries_StopsAnUndeclaredStreamAtTheCap(t *testing.T) {
	r := discoveriesEngine()
	body := &endlessJSON{}
	req := httptest.NewRequest(http.MethodPost, "/sensors/"+uuid.NewString()+"/discoveries", body)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	w := postDiscoveries(r, httptest.NewRecorder(), req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	if got := body.n.Load(); got > 2*maxDiscoveryBatchBytes {
		t.Fatalf("pulled %d bytes from an endless stream; the cap is %d", got, maxDiscoveryBatchBytes)
	}
}

func TestSubmitDiscoveries_RefusesMoreDiscoveriesThanTheCount(t *testing.T) {
	r := discoveriesEngine()
	body := `{"discoveries":[` + strings.Repeat(`{},`, maxDiscoveriesPerBatch) + `{}]}`
	req := httptest.NewRequest(http.MethodPost, "/sensors/"+uuid.NewString()+"/discoveries", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := postDiscoveries(r, httptest.NewRecorder(), req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
}

func TestSubmitDiscoveries_OrdinaryBatchReachesTheService(t *testing.T) {
	r := discoveriesEngine()
	req := httptest.NewRequest(http.MethodPost, "/sensors/"+uuid.NewString()+"/discoveries",
		strings.NewReader(`{"discoveries":[{},{}]}`))
	req.Header.Set("Content-Type", "application/json")
	w := postDiscoveries(r, httptest.NewRecorder(), req)
	// No service is wired, so reaching it is a recovered panic: 500, never 413/400.
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (reached the unwired service); body=%s", w.Code, w.Body.String())
	}
}
