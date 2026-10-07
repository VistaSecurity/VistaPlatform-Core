package api

// POST /agents/:id/results bound a models.JobResult with no ceiling: one agent
// report could be any size. Drives the handler the way the agent-outbound group
// mounts it. A refused report never reaches the service; one that is not
// refused reaches an unwired service, which is a recovered panic (500).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type endlessResult struct {
	n      atomic.Int64
	opened bool
}

func (b *endlessResult) Read(p []byte) (int, error) {
	i := 0
	if !b.opened {
		i = copy(p, `{"error":"`)
		b.opened = true
	}
	for ; i < len(p); i++ {
		p[i] = 'a'
	}
	b.n.Add(int64(len(p)))
	return len(p), nil
}

func agentResultsEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.POST("/agents/:id/results", submitAgentResultsHandler(nil, nil, nil))
	return r
}

func TestAgentResults_RefuseAnOversizeDeclaredBody(t *testing.T) {
	r := agentResultsEngine()
	req := httptest.NewRequest(http.MethodPost, "/agents/"+uuid.NewString()+"/results",
		strings.NewReader(strings.Repeat("a", maxAgentResultBytes+1)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
}

func TestAgentResults_StopAnUndeclaredStreamAtTheCap(t *testing.T) {
	r := agentResultsEngine()
	body := &endlessResult{}
	req := httptest.NewRequest(http.MethodPost, "/agents/"+uuid.NewString()+"/results", body)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	if got := body.n.Load(); got > 2*maxAgentResultBytes {
		t.Fatalf("pulled %d bytes from an endless stream; the cap is %d", got, maxAgentResultBytes)
	}
}

func TestAgentResults_OrdinaryReportReachesTheService(t *testing.T) {
	r := agentResultsEngine()
	req := httptest.NewRequest(http.MethodPost, "/agents/"+uuid.NewString()+"/results",
		strings.NewReader(`{"job_id":"`+uuid.NewString()+`","success":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusRequestEntityTooLarge || w.Code == http.StatusBadRequest {
		t.Fatalf("an ordinary report was refused: status %d body=%s", w.Code, w.Body.String())
	}
}
