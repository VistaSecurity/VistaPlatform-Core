package api

// The agent poll route is where an agent's capability is read ( slice B).
// Driven through the SAME handler router.go mounts at GET /agents/:id/jobs, so
// deleting the header read there — and with it every agent's declaration —
// fails this: a capable agent would then be treated as an old one and never
// handed the discovery it was named for.
//
// Skips without TEST_DATABASE_URL and a reachable Redis (make test-integration-db).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AgentJobsRoute_DeviceDiscoveryCapability(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	addr := os.Getenv("REDIS_URL")
	if addr == "" {
		addr = "localhost:6379"
	}
	opts, err := redis.ParseURL(addr)
	if err != nil {
		opts = &redis.Options{Addr: addr}
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis unreachable at %s: %v", addr, err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", "agent-jobs-route-test-master-key-0123456789")

	tenant := testdb.NewTenant(t, owner)
	agent := uuid.New()
	if _, err := owner.Exec(`INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, profile, status)
		VALUES ($1, $2, $3, 'linux', '1.0', 'device_interrogation', 'active')`, agent, tenant, "regkey-"+agent.String()); err != nil {
		t.Fatal(err)
	}
	job := uuid.New()
	if _, err := owner.Exec(`INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, status, parameters, credentials, expires_at)
		VALUES ($1, $2, 'device_discovery', $3, 'pending', '{"device_type":"fortinet","management_url":"https://192.0.2.10"}',
		        '{"username":"readonly","password":"plain-for-route-test","device_type":"fortinet"}', $4)`,
		job, tenant, agent, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rdb.Del(context.Background(), "device_agent:capabilities:"+agent.String()).Err() })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/agents/:id/jobs", getAgentJobsHandler(app, owner, rdb))
	poll := func(header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/agents/"+agent.String()+"/jobs", nil)
		if header != "" {
			req.Header.Set(di.AgentCapabilitiesHeader, header)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// An agent build that predates the job type sends no header.
	if w := poll(""); w.Code != http.StatusNoContent {
		t.Fatalf("old agent's poll = %d %s, want 204", w.Code, w.Body)
	}
	w := poll("device_discovery")
	if w.Code != http.StatusOK {
		t.Fatalf("capable agent's poll = %d %s, want the job", w.Code, w.Body)
	}
	var got struct {
		ID   uuid.UUID `json:"id"`
		Type string    `json:"type"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.ID != job || got.Type != di.JobTypeDeviceDiscovery {
		t.Fatalf("claimed %+v, want discovery %s", got, job)
	}
	if w := poll("device_discovery"); w.Code != http.StatusNoContent {
		t.Fatalf("second poll = %d, want 204 (claimed once)", w.Code)
	}
	// The declaration was remembered for Add device's agent check.
	if v, _ := rdb.Get(context.Background(), "device_agent:capabilities:"+agent.String()).Result(); v != di.CapabilityDeviceDiscovery {
		t.Fatalf("capability not recorded: %q", v)
	}
}
