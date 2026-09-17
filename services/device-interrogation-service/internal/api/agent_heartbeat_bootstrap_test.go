package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// An agent enrolled before desired state existed comes back with host inventory
// turned on in its own configuration file. The FIRST answer it gets has to
// describe what it is already doing, because it obeys that answer: before this
// fix it was handed the built-in defaults, applied them, and stopped collecting
// for good ~60s after startup.
//
// Driven through the real heartbeat handler, because every previous bug here
// was a missing line in it. Mutation check: remove the BootstrapFromReport call
// from confighttp.ExchangeCtx and this fails.
func TestIntegration_AgentHeartbeatAdoptsTheAgentsOwnStartingPosition(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)

	agentID := uuid.New()
	if _, err := admin.Exec(`INSERT INTO public.device_agents (id, tenant_id, name, version, platform, status, registration_key)
		VALUES ($1, $2, 'bootstrap-agent', '1.0.0', 'linux', 'active', $3)`, agentID, tenant, uuid.NewString()); err != nil {
		t.Fatalf("seeding agent: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
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

	values := func(resp map[string]any) map[string]any {
		t.Helper()
		cfg, ok := resp["config"].(map[string]any)
		if !ok {
			t.Fatalf("no config block in %v", resp)
		}
		vals, ok := cfg["values"].(map[string]any)
		if !ok {
			t.Fatalf("no values in %v", cfg)
		}
		return vals
	}

	// First beat: the agent says what it is running.
	got := values(post(`{"version":"1.0.0","config_running":{"host_inventory_enabled":true,"host_inventory_interval_seconds":21600}}`))
	if got["host_inventory_enabled"] != true {
		t.Errorf("the platform answered host_inventory_enabled=%v on the agent's FIRST beat; "+
			"applying that answer is what switched off an operator's host inventory", got["host_inventory_enabled"])
	}
	if iv, _ := got["host_inventory_interval_seconds"].(float64); iv != 21600 {
		t.Errorf("host_inventory_interval_seconds = %v, want the agent's own 21600", got["host_inventory_interval_seconds"])
	}

	// It is now the device's own override, visible to an operator as such —
	// not a built-in default nobody chose.
	var stored []byte
	if err := admin.QueryRow(`SELECT values FROM public.agent_config_overrides WHERE device_agent_id = $1`, agentID).
		Scan(&stored); err != nil {
		t.Fatalf("reading the override: %v — the agent's position was never recorded", err)
	}
	var vals agentconfig.Values
	if err := json.Unmarshal(stored, &vals); err != nil {
		t.Fatalf("decoding the stored override %q: %v", stored, err)
	}
	if v := vals[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("stored override = %s, want the agent's host_inventory_enabled=true", stored)
	}

	// An older agent on the same tenant reports nothing about its
	// configuration, and must acquire no override from that silence.
	olderID := uuid.New()
	if _, err := admin.Exec(`INSERT INTO public.device_agents (id, tenant_id, name, version, platform, status, registration_key)
		VALUES ($1, $2, 'older-agent', '0.9.0', 'linux', 'active', $3)`, olderID, tenant, uuid.NewString()); err != nil {
		t.Fatalf("seeding older agent: %v", err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/agents/"+olderID.String()+"/heartbeat",
		bytes.NewBufferString(`{"version":"0.9.0"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("older agent heartbeat = %d: %s", w.Code, w.Body.String())
	}
	var rows int
	if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_overrides WHERE device_agent_id = $1`, olderID).Scan(&rows); err != nil {
		t.Fatalf("counting overrides: %v", err)
	}
	if rows != 0 {
		t.Errorf("an agent that reported no settings acquired %d override row(s)", rows)
	}
}
