package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The desired-state exchange is a LINE in the heartbeat handler, and a line is
// exactly what tests miss: every unit test of the exchange itself stayed green
// when `resp["config"] = payload` was deleted, because the handler that carries
// it to the agent was never driven.
//
// So this drives the real heartbeat handler. Mutation check: delete that line,
// or the block that records the agent's report, and this fails.
func TestIntegration_AgentHeartbeatCarriesTheConfigExchange(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)

	agentID := uuid.New()
	if _, err := admin.Exec(`INSERT INTO public.device_agents (id, tenant_id, name, version, platform, status, registration_key)
		VALUES ($1, $2, 'beat-agent', '1.0.0', 'linux', 'active', $3)`, agentID, tenant, uuid.NewString()); err != nil {
		t.Fatalf("seeding agent: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// The tenant is put in context the way AgentAuth puts it there; everything
	// after that is the real handler.
	r.POST("/agents/:id/heartbeat", func(c *gin.Context) {
		c.Set("tenantID", tenant)
		c.Next()
	}, agentHeartbeatHandler(admin, admin, nil))

	post := func(body string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/agents/"+agentID.String()+"/heartbeat", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat = %d: %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding %q: %v", w.Body.String(), err)
		}
		return out
	}

	// A beat with no configuration report still gets an answer: the agent has
	// to be told what it should be running before it can ever converge.
	got := post(`{"version":"1.0.0"}`)
	cfg, ok := got["config"].(map[string]any)
	if !ok {
		t.Fatalf("heartbeat response carried no config block: %v\n"+
			"Without it the agent is never told its desired state and can never converge.", got)
	}
	revision, _ := cfg["revision"].(string)
	if revision == "" {
		t.Fatal("the config block carried no revision")
	}
	if _, ok := cfg["values"].(map[string]any); !ok {
		t.Errorf("the config block carried no values: %v", cfg)
	}

	// The agent's report has to be RECORDED, not just answered: report the
	// revision we were handed, and the stored state must say so.
	post(`{"version":"1.0.0","config_revision":"` + revision + `"}`)

	var stored sql.NullString
	if err := admin.QueryRow(`SELECT reported_revision FROM public.agent_config_state WHERE device_agent_id = $1`, agentID).
		Scan(&stored); err != nil {
		t.Fatalf("reading the recorded state: %v — the agent's report was never stored", err)
	}
	if stored.String != revision {
		t.Errorf("recorded revision = %q, want %q", stored.String, revision)
	}
}
