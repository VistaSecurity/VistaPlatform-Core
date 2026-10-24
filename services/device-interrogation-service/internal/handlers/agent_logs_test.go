package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentlogs"
)

// memAgentLogStore is AgentLogStore in memory, keyed exactly as Redis is.
type memAgentLogStore struct {
	requests map[string]agentlogs.Request
	exports  map[string]agentlogs.Export
	capable  map[string]bool
}

func newMemAgentLogStore() *memAgentLogStore {
	return &memAgentLogStore{requests: map[string]agentlogs.Request{}, exports: map[string]agentlogs.Export{}, capable: map[string]bool{}}
}

func memKey(t, a uuid.UUID) string { return t.String() + ":" + a.String() }

func (m *memAgentLogStore) PutRequest(_ context.Context, t, a uuid.UUID, r agentlogs.Request) error {
	m.requests[memKey(t, a)] = r
	return nil
}
func (m *memAgentLogStore) GetRequest(_ context.Context, t, a uuid.UUID) (*agentlogs.Request, error) {
	if r, ok := m.requests[memKey(t, a)]; ok {
		return &r, nil
	}
	return nil, nil
}
func (m *memAgentLogStore) DeleteRequest(_ context.Context, t, a uuid.UUID) error {
	delete(m.requests, memKey(t, a))
	return nil
}
func (m *memAgentLogStore) PutExport(_ context.Context, t, a uuid.UUID, e agentlogs.Export) error {
	m.exports[memKey(t, a)] = e
	return nil
}
func (m *memAgentLogStore) GetExport(_ context.Context, t, a uuid.UUID) (*agentlogs.Export, error) {
	if e, ok := m.exports[memKey(t, a)]; ok {
		return &e, nil
	}
	return nil, nil
}
func (m *memAgentLogStore) MarkCapable(_ context.Context, t, a uuid.UUID) error {
	m.capable[memKey(t, a)] = true
	return nil
}
func (m *memAgentLogStore) Capable(_ context.Context, t, a uuid.UUID) (bool, error) {
	return m.capable[memKey(t, a)], nil
}

type logsRig struct {
	h       *AgentLogsHandler
	store   *memAgentLogStore
	tenant  uuid.UUID
	agent   uuid.UUID
	tenantR *gin.Engine // tenant-JWT side
	agentR  *gin.Engine // AgentAuth side
}

func newLogsRig(t *testing.T) *logsRig {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rig := &logsRig{store: newMemAgentLogStore(), tenant: uuid.New(), agent: uuid.New()}
	rig.h = &AgentLogsHandler{
		store: rig.store,
		agentExists: func(_ context.Context, tenantID, agentID uuid.UUID) (bool, error) {
			return tenantID == rig.tenant && agentID == rig.agent, nil
		},
		now: func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) },
	}
	rig.tenantR = gin.New()
	rig.tenantR.Use(func(c *gin.Context) { c.Set("tenantID", rig.tenant); c.Next() })
	rig.tenantR.GET("/agents/:id/logs", rig.h.GetLogs)
	rig.tenantR.POST("/agents/:id/logs/request", rig.h.RequestLogs)

	// AgentAuth resolves the tenant from the agent's own record and sets both.
	rig.agentR = gin.New()
	rig.agentR.Use(func(c *gin.Context) {
		c.Set("tenantID", rig.tenant)
		c.Set("agent_id", rig.agent)
		c.Next()
	})
	rig.agentR.POST("/agents/:id/logs", rig.h.Upload)
	return rig
}

func doJSON(r http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAgentLogs_RoundTrip(t *testing.T) {
	rig := newLogsRig(t)
	base := "/agents/" + rig.agent.String()

	// Nothing yet, and an agent that never said it can export logs.
	w := doJSON(rig.tenantR, http.MethodGet, base+"/logs", nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"request"`) || !strings.Contains(w.Body.String(), `"supported":false`) {
		t.Fatalf("initial GET = %d %s", w.Code, w.Body.String())
	}

	// The console asks for 50 lines.
	w = doJSON(rig.tenantR, http.MethodPost, base+"/logs/request", map[string]int{"lines": 50})
	if w.Code != http.StatusAccepted {
		t.Fatalf("request = %d %s", w.Code, w.Body.String())
	}
	var asked struct{ Request agentlogs.Request }
	_ = json.Unmarshal(w.Body.Bytes(), &asked)
	if asked.Request.ID == "" || asked.Request.Lines != 50 {
		t.Fatalf("request = %+v", asked.Request)
	}

	// An agent whose build cannot export logs is not handed the request.
	if got := rig.h.OnHeartbeat(context.Background(), rig.tenant, rig.agent, false); got != nil {
		t.Fatalf("an incapable agent was handed %+v", got)
	}
	// A capable one is, and is recorded as capable.
	got := rig.h.OnHeartbeat(context.Background(), rig.tenant, rig.agent, true)
	if got == nil || got.ID != asked.Request.ID {
		t.Fatalf("heartbeat handed %+v, want request %s", got, asked.Request.ID)
	}

	// The agent replies; a credential in a line is masked by the platform too.
	lines := []string{"agent started", `connecting to https://admin:hunter2@fw.example.net`, "job done"}
	w = doJSON(rig.agentR, http.MethodPost, base+"/logs", agentlogs.Upload{RequestID: got.ID, Lines: lines})
	if w.Code != http.StatusOK {
		t.Fatalf("upload = %d %s", w.Code, w.Body.String())
	}

	w = doJSON(rig.tenantR, http.MethodGet, base+"/logs", nil)
	var view AgentLogsView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Supported {
		t.Error("supported = false after a capable heartbeat")
	}
	if view.Request != nil {
		t.Errorf("the request was not cleared after the upload: %+v", view.Request)
	}
	if view.Export == nil || view.Export.LineCount != 3 || view.Export.RequestID != got.ID {
		t.Fatalf("export = %+v", view.Export)
	}
	if strings.Contains(strings.Join(view.Export.Lines, "\n"), "hunter2") {
		t.Fatalf("a credential reached the export: %v", view.Export.Lines)
	}
}

// An upload nobody asked for, or for a request that has been replaced, must be
// refused: otherwise an agent could put lines in the console at will.
func TestAgentLogs_UploadNeedsTheCurrentRequest(t *testing.T) {
	rig := newLogsRig(t)
	base := "/agents/" + rig.agent.String()

	w := doJSON(rig.agentR, http.MethodPost, base+"/logs", agentlogs.Upload{RequestID: "made-up", Lines: []string{"x"}})
	if w.Code != http.StatusConflict {
		t.Fatalf("unsolicited upload = %d, want 409", w.Code)
	}

	doJSON(rig.tenantR, http.MethodPost, base+"/logs/request", nil)
	first := rig.store.requests[memKey(rig.tenant, rig.agent)].ID
	doJSON(rig.tenantR, http.MethodPost, base+"/logs/request", nil)
	if rig.store.requests[memKey(rig.tenant, rig.agent)].ID == first {
		t.Fatal("a second request did not replace the first")
	}
	w = doJSON(rig.agentR, http.MethodPost, base+"/logs", agentlogs.Upload{RequestID: first, Lines: []string{"x"}})
	if w.Code != http.StatusConflict {
		t.Fatalf("upload for a replaced request = %d, want 409", w.Code)
	}
	if len(rig.store.exports) != 0 {
		t.Fatal("a refused upload was stored")
	}
}

func TestAgentLogs_TenantRoutesCheckTheAgent(t *testing.T) {
	rig := newLogsRig(t)
	other := "/agents/" + uuid.NewString()
	if w := doJSON(rig.tenantR, http.MethodGet, other+"/logs", nil); w.Code != http.StatusNotFound {
		t.Errorf("GET for an unknown agent = %d, want 404", w.Code)
	}
	if w := doJSON(rig.tenantR, http.MethodPost, other+"/logs/request", nil); w.Code != http.StatusNotFound {
		t.Errorf("request for an unknown agent = %d, want 404", w.Code)
	}
	if w := doJSON(rig.tenantR, http.MethodGet, "/agents/not-a-uuid/logs", nil); w.Code != http.StatusBadRequest {
		t.Errorf("GET with a malformed id = %d, want 400", w.Code)
	}
	if len(rig.store.requests) != 0 {
		t.Error("a request was recorded for an agent outside the tenant")
	}
}

func TestAgentLogs_RequestClampsLines(t *testing.T) {
	rig := newLogsRig(t)
	w := doJSON(rig.tenantR, http.MethodPost, "/agents/"+rig.agent.String()+"/logs/request", map[string]int{"lines": 1_000_000})
	if w.Code != http.StatusAccepted {
		t.Fatalf("request = %d", w.Code)
	}
	if got := rig.store.requests[memKey(rig.tenant, rig.agent)].Lines; got != agentlogs.MaxLines {
		t.Fatalf("lines = %d, want %d", got, agentlogs.MaxLines)
	}
}

// The console reads these two bodies through the generated client, so they are
// held to the spec like every other tenant route.
func TestContract_AgentLogs(t *testing.T) {
	sv := loadSpec(t)
	rig := newLogsRig(t)
	base := "/agents/" + rig.agent.String()

	w := doJSON(rig.tenantR, http.MethodGet, base+"/logs", nil)
	sv.assertConforms(t, "AgentLogsView", w.Body.Bytes())

	w = doJSON(rig.tenantR, http.MethodPost, base+"/logs/request", map[string]int{"lines": 20})
	sv.assertConforms(t, "AgentLogRequestAccepted", w.Body.Bytes())

	req := rig.h.OnHeartbeat(context.Background(), rig.tenant, rig.agent, true)
	doJSON(rig.agentR, http.MethodPost, base+"/logs", agentlogs.Upload{RequestID: req.ID, Lines: []string{"a", "b"}})
	// Pending request cleared, export present, capability set.
	w = doJSON(rig.tenantR, http.MethodGet, base+"/logs", nil)
	sv.assertConforms(t, "AgentLogsView", w.Body.Bytes())

	// A request with no export yet, too.
	doJSON(rig.tenantR, http.MethodPost, base+"/logs/request", nil)
	w = doJSON(rig.tenantR, http.MethodGet, base+"/logs", nil)
	sv.assertConforms(t, "AgentLogsView", w.Body.Bytes())
}
