package main

// Explicit external targets through the REAL router ( W5.13b).
//
// buildAPIRouter is what main() mounts — body cap, audit middleware on the
// context and per request, the discovery routes with their permission gates —
// so this drives the route a browser's request reaches, against a real
// Postgres, with the audit sink an httptest server standing in for
// audit-service. Deleting the consent check, the audit call or the
// audit-middleware wiring in main.go each turns one of these assertions red;
// the helper-level tests in shared/identity/dispatchguard cannot see any of
// the three.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type mapResolver map[string][]string

func (r mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, a := range r[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

// auditSink is audit-service as far as the middleware can tell.
type auditSink struct {
	mu      sync.Mutex
	entries []map[string]interface{}
}

func (s *auditSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var entry map[string]interface{}
	if json.Unmarshal(body, &entry) == nil {
		s.mu.Lock()
		s.entries = append(s.entries, entry)
		s.mu.Unlock()
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
}

// waitFor returns the first entry with eventType, waiting out the middleware's
// asynchronous flush.
func (s *auditSink) waitFor(eventType string, within time.Duration) map[string]interface{} {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, e := range s.entries {
			if e["event_type"] == eventType {
				s.mu.Unlock()
				return e
			}
		}
		s.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

func (s *auditSink) count(eventType string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.entries {
		if e["event_type"] == eventType {
			n++
		}
	}
	return n
}

func TestIntegration_ExternalTargets_ThroughTheRealRouter(t *testing.T) {
	t.Setenv("DATABASE_URL", "") // tenant state is not under test; see gateRouter
	t.Setenv("AUDIT_USE_NATS", "")
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true") // the chart sets it; unset means off
	gin.SetMode(gin.TestMode)

	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	// A tenant member holding discovery.create — the existing permission for
	// starting a scan. No new permission gates external targets.
	user := uuid.New()
	if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, "scanner-"+user.String()[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	var role uuid.UUID
	if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, 'scan_starter', 'Scan starter') RETURNING id`, tenant).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name = 'discovery.create'`, role); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, user, tenant, role); err != nil {
		t.Fatal(err)
	}

	sink := &auditSink{}
	auditSrv := httptest.NewServer(sink)
	t.Cleanup(auditSrv.Close)
	auditCfg := auditmiddleware.DefaultConfig()
	auditCfg.ServiceName = "cluster-sensor-service"
	auditCfg.AuditServiceURL = auditSrv.URL
	auditCfg.BatchSize = 1
	auditCfg.FlushInterval = 50 * time.Millisecond
	audit := auditmiddleware.NewMiddleware(auditCfg)

	svc := services.NewDiscoveryService(db, db).WithResolver(mapResolver{
		"www.example.com":      {"93.184.216.34"},
		"metadata.example.com": {"169.254.169.254"},
	})
	h := handlers.NewDiscoveryHandler(svc, services.NewRateLimiter(db), nil, nil)
	router := gin.New()
	router.Use(gin.Recovery())
	buildAPIRouter(router, h, raw, gateTestJWTSecret, audit)

	token := mintToken(t, user, tenant, "member")
	post := func(body string) (*httptest.ResponseRecorder, map[string]interface{}) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/jobs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		var parsed map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &parsed)
		return w, parsed
	}
	jobs := func() int {
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id=$1`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const shape = `"protocols":["TLS"],"ports":[443],"execution_mode":"auto"`

	// 1. No flag: 422, the external targets listed, nothing created, nothing audited.
	w, body := post(`{"targets":["10.0.0.5","93.184.216.34","https://www.example.com/"],` + shape + `}`)
	if w.Code != http.StatusUnprocessableEntity || body["error"] != dispatchguard.CodeExternalTargetsUnconfirmed {
		t.Fatalf("unconfirmed: status=%d body=%s, want 422 %s", w.Code, w.Body.String(), dispatchguard.CodeExternalTargetsUnconfirmed)
	}
	listed, _ := body["external_targets"].([]interface{})
	if len(listed) != 2 {
		t.Fatalf("unconfirmed: external_targets=%v, want the two public targets", body["external_targets"])
	}
	if n := jobs(); n != 0 {
		t.Fatalf("unconfirmed request created %d job(s)", n)
	}

	// 2. Reserved through a name, confirmed: 400 with the reason.
	w, body = post(`{"targets":["metadata.example.com"],"external_targets_confirmed":true,` + shape + `}`)
	if w.Code != http.StatusBadRequest || body["error"] != dispatchguard.CodeTargetsRefused {
		t.Fatalf("metadata name: status=%d body=%s, want 400 %s", w.Code, w.Body.String(), dispatchguard.CodeTargetsRefused)
	}

	// 3. Operator switch off: 403, its own code.
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "false")
	w, body = post(`{"targets":["93.184.216.34"],"external_targets_confirmed":true,` + shape + `}`)
	if w.Code != http.StatusForbidden || body["error"] != dispatchguard.CodeExternalTargetsDisabled {
		t.Fatalf("switch off: status=%d body=%s, want 403 %s", w.Code, w.Body.String(), dispatchguard.CodeExternalTargetsDisabled)
	}
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	if n := sink.count(handlers.AuditEventExternalTargets); n != 0 {
		t.Fatalf("%d external-target audit event(s) for requests that scanned nothing", n)
	}

	// 4. Confirmed: 202, job created with the pin, audit event with who and what.
	w, body = post(`{"targets":["10.0.0.5","93.184.216.34","https://www.example.com/"],"external_targets_confirmed":true,` + shape + `}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("confirmed: status=%d body=%s, want 202", w.Code, w.Body.String())
	}
	job, _ := body["job"].(map[string]interface{})
	jobID, _ := job["id"].(string)
	var pinned string
	if err := raw.QueryRow(`SELECT metadata->'pinned_addresses'->>'www.example.com' FROM discovery_jobs WHERE id=$1`, jobID).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if pinned != `["93.184.216.34"]` {
		t.Fatalf("pinned = %s, want the address that was authorized", pinned)
	}
	entry := sink.waitFor(handlers.AuditEventExternalTargets, 5*time.Second)
	if entry == nil {
		t.Fatal("a confirmed external scan wrote no audit event")
	}
	if entry["user_id"] != user.String() || entry["tenant_id"] != tenant.String() || entry["resource_id"] != jobID || entry["event_category"] != "discovery" {
		t.Fatalf("audit event does not say who/which job: %v", entry)
	}
	meta, _ := entry["metadata"].(map[string]interface{})
	recorded, _ := json.Marshal(meta["external_targets"])
	for _, want := range []string{`"target":"93.184.216.34"`, `"target":"https://www.example.com/"`, `"addresses":["93.184.216.34"]`} {
		if !strings.Contains(string(recorded), want) {
			t.Fatalf("audit external_targets %s missing %s", recorded, want)
		}
	}
	if strings.Contains(string(recorded), "10.0.0.5") {
		t.Fatalf("audit lists an in-scope target as external: %s", recorded)
	}
	if _, ok := entry["occurred_at"]; !ok {
		t.Fatalf("audit event has no timestamp: %v", entry)
	}
}
