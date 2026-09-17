package handlers_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func seedAgent(t *testing.T, db *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO public.device_agents (id, tenant_id, name, version, platform, status, registration_key)
		VALUES ($1, $2, $3, '1.0.0', 'windows', 'active', $4)`,
		id, tenant, "agent-"+id.String()[:8], uuid.NewString()); err != nil {
		t.Fatalf("seeding agent: %v", err)
	}
	return id
}

// call drives the handler through a gin context carrying the tenant the
// middleware would have set.
func call(t *testing.T, h gin.HandlerFunc, tenant uuid.UUID, method, target, body string, params gin.Params) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, target, bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("tenantID", tenant)
	c.Set("userID", uuid.New())
	c.Params = params
	h(c)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding %q: %v", w.Body.String(), err)
	}
	return out
}

func TestIntegration_AgentConfig_SetAndRead(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)
	h := handlers.NewAgentConfigHandler(admin)
	p := gin.Params{{Key: "id", Value: agentID.String()}}

	w := call(t, h.PutAgentConfig, tenant, http.MethodPut, "/config",
		`{"values":{"host_inventory_enabled":true,"host_inventory_interval_seconds":21600}}`, p)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}

	w = call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", p)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", w.Code, w.Body.String())
	}
	body := decode(t, w)
	settings, _ := body["settings"].([]any)
	var found bool
	for _, s := range settings {
		m := s.(map[string]any)
		if m["key"] == string(agentconfig.KeyHostInventoryEnabled) {
			found = true
			if m["value"] != true {
				t.Errorf("host inventory = %v, want true", m["value"])
			}
			if m["origin"] != string(agentconfig.OriginDevice) {
				t.Errorf("origin = %v, want device", m["origin"])
			}
		}
	}
	if !found {
		t.Error("host_inventory_enabled missing from the settings list")
	}
	status, _ := body["status"].(map[string]any)
	if status["state"] != string(agentconfig.StateNeverReported) {
		t.Errorf("state = %v, want never_reported — this agent has not checked in", status["state"])
	}
}

// A below-floor interval is accepted, raised, and the operator is TOLD. The
// agent raises it silently today, so whoever typed five minutes never learns it
// became an hour.
func TestIntegration_AgentConfig_FloorIsRaisedAndReported(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)
	h := handlers.NewAgentConfigHandler(admin)
	p := gin.Params{{Key: "id", Value: agentID.String()}}

	w := call(t, h.PutAgentConfig, tenant, http.MethodPut, "/config",
		`{"values":{"host_inventory_interval_seconds":300}}`, p)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}
	adjusted, _ := decode(t, w)["adjusted"].([]any)
	if len(adjusted) != 1 {
		t.Fatalf("adjusted = %v, want one note saying the value was raised", adjusted)
	}

	w = call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", p)
	for _, s := range decode(t, w)["settings"].([]any) {
		m := s.(map[string]any)
		if m["key"] == string(agentconfig.KeyHostInventoryInterval) && m["value"].(float64) != 3600 {
			t.Errorf("stored interval = %v, want 3600 — the console must show what will really run", m["value"])
		}
	}
}

func TestIntegration_AgentConfig_RejectsInvalidValues(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)
	h := handlers.NewAgentConfigHandler(admin)
	p := gin.Params{{Key: "id", Value: agentID.String()}}

	w := call(t, h.PutAgentConfig, tenant, http.MethodPut, "/config",
		`{"values":{"poll_interval_seconds":99999,"log_level":"shout"}}`, p)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT = %d, want 400: %s", w.Code, w.Body.String())
	}
	problems, _ := decode(t, w)["problems"].([]any)
	if len(problems) != 2 {
		t.Errorf("problems = %v, want both reported at once", problems)
	}
}

// An agent id belonging to another tenant is a 404, not a 403 and not a silent
// empty read: the answer must not tell one tenant that another's agent exists.
func TestIntegration_AgentConfig_OtherTenantsAgentIsNotFound(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenantA := testdb.NewTenant(t, admin)
	tenantB := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenantA)
	h := handlers.NewAgentConfigHandler(admin)
	p := gin.Params{{Key: "id", Value: agentID.String()}}

	if w := call(t, h.GetAgentConfig, tenantB, http.MethodGet, "/config", "", p); w.Code != http.StatusNotFound {
		t.Errorf("GET as another tenant = %d, want 404", w.Code)
	}
	if w := call(t, h.PutAgentConfig, tenantB, http.MethodPut, "/config", `{"values":{"poll_interval_seconds":60}}`, p); w.Code != http.StatusNotFound {
		t.Errorf("PUT as another tenant = %d, want 404", w.Code)
	}
}

// Fleet defaults reach a device that has no override, and the device's own
// override still wins.
func TestIntegration_AgentConfig_FleetDefaultsApply(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	plain := seedAgent(t, admin, tenant)
	opted := seedAgent(t, admin, tenant)
	h := handlers.NewAgentConfigHandler(admin)

	if w := call(t, h.PutAgentConfig, tenant, http.MethodPut, "/config",
		`{"values":{"host_inventory_enabled":false}}`, gin.Params{{Key: "id", Value: opted.String()}}); w.Code != http.StatusOK {
		t.Fatalf("seeding the override: %d %s", w.Code, w.Body.String())
	}
	if w := call(t, h.PutAgentFleetDefaults, tenant, http.MethodPut, "/config/defaults",
		`{"values":{"host_inventory_enabled":true}}`, nil); w.Code != http.StatusOK {
		t.Fatalf("PUT defaults = %d: %s", w.Code, w.Body.String())
	}

	value := func(id uuid.UUID) any {
		w := call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", gin.Params{{Key: "id", Value: id.String()}})
		for _, s := range decode(t, w)["settings"].([]any) {
			m := s.(map[string]any)
			if m["key"] == string(agentconfig.KeyHostInventoryEnabled) {
				return m["value"]
			}
		}
		return nil
	}
	if got := value(plain); got != true {
		t.Errorf("inheriting agent = %v, want the fleet default true", got)
	}
	if got := value(opted); got != false {
		t.Errorf("overriding agent = %v, want its own explicit false to survive the fleet default", got)
	}
}

// The heartbeat exchange: the agent's report is recorded and the answer is what
// it should be running. This is the whole convergence loop in one call.
func TestIntegration_AgentConfig_HeartbeatExchange(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)
	h := handlers.NewAgentConfigHandler(admin)
	ctx := context.Background()

	if w := call(t, h.PutAgentConfig, tenant, http.MethodPut, "/config",
		`{"values":{"host_inventory_enabled":true}}`, gin.Params{{Key: "id", Value: agentID.String()}}); w.Code != http.StatusOK {
		t.Fatalf("seeding config: %d %s", w.Code, w.Body.String())
	}

	// First beat: the agent knows nothing yet.
	payload, err := h.Exchange(ctx, tenant, agentID, handlers.AgentReport{})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if payload.Revision == "" {
		t.Fatal("no revision returned; the agent has nothing to compare against")
	}
	if v := payload.Values[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("host inventory = %v, want the desired true", v)
	}

	// It checked in but named no revision — an old build, or one that has not
	// applied anything yet. That is NOT "pending": pending promises a
	// convergence that a device which cannot report will never reach.
	w := call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", gin.Params{{Key: "id", Value: agentID.String()}})
	if got := decode(t, w)["status"].(map[string]any)["state"]; got != string(agentconfig.StateNotReporting) {
		t.Errorf("state after a beat naming no revision = %v, want not_reporting", got)
	}

	// Second beat: the agent reports the revision it applied.
	if _, err := h.Exchange(ctx, tenant, agentID, handlers.AgentReport{ConfigRevision: payload.Revision}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	w = call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", gin.Params{{Key: "id", Value: agentID.String()}})
	if got := decode(t, w)["status"].(map[string]any)["state"]; got != string(agentconfig.StateApplied) {
		t.Errorf("state after the agent reported the desired revision = %v, want applied", got)
	}

	// A failure the agent reports must reach the console with its reason.
	if _, err := h.Exchange(ctx, tenant, agentID, handlers.AgentReport{
		ConfigRevision: payload.Revision,
		ConfigFailures: map[string]string{string(agentconfig.KeyHostInventoryEnabled): "no permission to read the package database"},
	}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	w = call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", gin.Params{{Key: "id", Value: agentID.String()}})
	status := decode(t, w)["status"].(map[string]any)
	if status["state"] != string(agentconfig.StateFailed) {
		t.Fatalf("state = %v, want failed", status["state"])
	}
	failures, _ := status["failures"].(map[string]any)
	if failures[string(agentconfig.KeyHostInventoryEnabled)] != "no permission to read the package database" {
		t.Errorf("the agent's own reason was lost: %v", failures)
	}
}

// TestIntegration_AgentConfig_WorksOnTheAppRolePool is the regression for a
// defect every other test in this file was blind to.
//
// `device_agents` is an RLS table, and the service connects as the non-owner
// role `crypto_app` wherever serviceRls is enabled — the shipped default. A
// query on the plain pool therefore has no `app.tenant_id`, the policy
// evaluates against NULL, and the agent is invisible to its OWN tenant: all
// four endpoints answered 404 on any default install while passing every test
// here, because testdb.Connect returns the table OWNER, which bypasses
// policies.
//
// So this one connects as the app role deliberately. Mutation check: put the
// ownership query back on the plain pool (`h.db.QueryRowContext(...)` instead
// of WithTenantTx) and this fails with 404 while every other test stays green.
func TestIntegration_AgentConfig_WorksOnTheAppRolePool(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)

	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewAgentConfigHandler(app)
	p := gin.Params{{Key: "id", Value: agentID.String()}}

	if w := call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", p); w.Code != http.StatusOK {
		t.Fatalf("GET on the app-role pool = %d, want 200: %s\n"+
			"A 404 here means the tenant cannot see its own agent — the whole surface is dead under the default RLS posture.",
			w.Code, w.Body.String())
	}
	if w := call(t, h.PutAgentConfig, tenant, http.MethodPut, "/config",
		`{"values":{"host_inventory_enabled":true}}`, p); w.Code != http.StatusOK {
		t.Fatalf("PUT on the app-role pool = %d, want 200: %s", w.Code, w.Body.String())
	}

	w := call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", p)
	for _, s := range decode(t, w)["settings"].([]any) {
		m := s.(map[string]any)
		if m["key"] == string(agentconfig.KeyHostInventoryEnabled) && m["value"] != true {
			t.Errorf("host inventory = %v, want the saved true to survive on the app-role pool", m["value"])
		}
	}

	// And the isolation the owner-pool test asserts must still hold here.
	other := testdb.NewTenant(t, admin)
	if w := call(t, h.GetAgentConfig, other, http.MethodGet, "/config", "", p); w.Code != http.StatusNotFound {
		t.Errorf("another tenant's GET = %d, want 404", w.Code)
	}
}

// TestIntegration_AgentConfig_ResponseMatchesItsSpec closes the class of defect
// that the refactor onto the shared HTTP core introduced and nothing caught.
//
// That refactor dropped `agent_id` from this response while the OpenAPI schema
// still declared it REQUIRED and the generated TypeScript still typed it
// non-optional. Every test passed: none of them asserted the field, and
// `make api-contract` only checks that the generated client matches the spec —
// not that the handler does.
//
// So this reads the spec and compares. It is deliberately strict in both
// directions: a required field the handler omits is a broken contract, and a
// field the handler sends that the spec never declares is a contract nobody
// wrote down.
func TestIntegration_AgentConfig_ResponseMatchesItsSpec(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)

	h := handlers.NewAgentConfigHandler(admin)
	w := call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "",
		gin.Params{{Key: "id", Value: agentID.String()}})
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", w.Code, w.Body.String())
	}

	required, declared := specFields(t, "AgentConfigResponse")
	body := decode(t, w)

	for _, field := range required {
		if _, ok := body[field]; !ok {
			t.Errorf("the spec requires %q and the handler does not send it", field)
		}
	}
	for field := range body {
		if !declared[field] {
			t.Errorf("the handler sends %q and the spec does not declare it", field)
		}
	}
}

// specFields reads one schema's `required` list and its declared property names
// out of the OpenAPI document.
//
// A crude parse, and self-checking because of it: a schema it cannot find, or
// one it reads as having no fields, fails the test rather than passing
// vacuously. That is the whole risk with a guard like this — it is worth more
// as a loud failure than as a silent pass.
func specFields(t *testing.T, schema string) ([]string, map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..",
		"api", "openapi", "device-interrogation-service.openapi.yaml"))
	if err != nil {
		t.Fatalf("reading the spec: %v", err)
	}

	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == schema+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("schema %s not found in the spec — this guard is inert, fix it", schema)
	}

	var (
		required   []string
		declared   = map[string]bool{}
		inRequired bool
		inProps    bool
	)
	for _, l := range lines[start+1:] {
		trimmed := strings.TrimSpace(l)
		indent := len(l) - len(strings.TrimLeft(l, " "))
		if indent <= 4 && trimmed != "" && !strings.HasPrefix(trimmed, "-") {
			break // the next schema
		}
		switch {
		case trimmed == "required:":
			inRequired, inProps = true, false
		case trimmed == "properties:":
			inRequired, inProps = false, true
		case inRequired && strings.HasPrefix(trimmed, "- "):
			required = append(required, strings.TrimPrefix(trimmed, "- "))
		case inProps && indent == 8 && strings.HasSuffix(trimmed, ":"):
			declared[strings.TrimSuffix(trimmed, ":")] = true
		}
	}
	if len(required) == 0 || len(declared) == 0 {
		t.Fatalf("parsed %d required and %d declared fields for %s — the parse is broken, not the handler",
			len(required), len(declared), schema)
	}
	return required, declared
}

// Version visibility (owner decision 4): the console shows what a device
// runs, what this release expects, and whether it is behind — computed from the
// platform's own release rather than from anything external.
func TestIntegration_AgentConfig_ReportsVersionState(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)
	h := handlers.NewAgentConfigHandler(admin)
	p := gin.Params{{Key: "id", Value: agentID.String()}}

	version := func() map[string]any {
		t.Helper()
		w := call(t, h.GetAgentConfig, tenant, http.MethodGet, "/config", "", p)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d: %s", w.Code, w.Body.String())
		}
		v, _ := decode(t, w)["version"].(map[string]any)
		if v == nil {
			t.Fatal("the response carried no version block")
		}
		return v
	}

	// The agent was seeded at 1.0.0 (seedAgent).
	t.Setenv("SERVICE_VERSION", "v1.0.0")
	if got := version()["state"]; got != string(agentconfig.VersionCurrent) {
		t.Errorf("state = %v, want current when the agent matches the release", got)
	}

	t.Setenv("SERVICE_VERSION", "v1.2.0")
	got := version()
	if got["state"] != string(agentconfig.VersionBehind) {
		t.Errorf("state = %v, want behind", got["state"])
	}
	if got["device"] != "1.0.0" || got["expected"] != "v1.2.0" {
		t.Errorf("version block = %v, want both sides reported so the console can name them", got)
	}

	// A platform that does not know its own version must say UNKNOWN, never
	// "current": an operator reading "up to date" against an unknown baseline
	// would believe a fleet was patched when nobody had checked.
	t.Setenv("SERVICE_VERSION", "")
	if st := version()["state"]; st != string(agentconfig.VersionUnknown) {
		t.Errorf("state = %v with no platform version, want unknown", st)
	}
}

// The restart request, end to end through the operator endpoint and back out on
// the exchange the agent reads.
//
// The pieces are tested separately — ShouldRestart in agentconfig, the storage
// in the store, the exit decision in the agent — and all three can be right
// while nothing connects them. This is the connection.
func TestIntegration_AgentConfig_RestartRequestReachesTheAgent(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenant)
	h := handlers.NewAgentConfigHandler(admin)
	p := gin.Params{{Key: "id", Value: agentID.String()}}
	ctx := context.Background()

	// Before: the agent is told nothing about restarting.
	payload, err := h.Exchange(ctx, tenant, agentID, handlers.AgentReport{})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !payload.RestartRequestedAt.IsZero() {
		t.Fatalf("an agent nobody asked to restart was told to: %v", payload.RestartRequestedAt)
	}
	revisionBefore := payload.Revision

	w := call(t, h.RequestAgentRestart, tenant, http.MethodPost, "/restart", "", p)
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /restart = %d, want 202: %s", w.Code, w.Body.String())
	}
	body := decode(t, w)
	if body["restart_requested_at"] == nil {
		t.Error("the response did not say when the restart was requested")
	}
	// The caveat has to reach the operator: an unsupervised agent STOPS.
	if note, _ := body["note"].(string); !strings.Contains(note, "not run as a service") {
		t.Errorf("the response does not warn that an unsupervised agent stops: %q", note)
	}

	after, err := h.Exchange(ctx, tenant, agentID, handlers.AgentReport{})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if after.RestartRequestedAt.IsZero() {
		t.Fatal("the request never reached the agent's exchange payload")
	}
	// The AGE is what the device decides on; the timestamp beside it is display
	// only. So this asserts the age is USABLE, not merely present.
	//
	// The first version of this checked `>= 0`, which Age can never violate —
	// an assertion that cannot fail, guarding the one field the whole feature
	// turns on. Hard-coding the age to 0 deleted the feature end to end and
	// every test stayed green.
	if after.RestartRequestAgeSeconds < 1 {
		t.Errorf("request age = %ds — a device reads 0 as 'nobody asked', so the restart never happens",
			after.RestartRequestAgeSeconds)
	}

	if after.Revision != revisionBefore {
		t.Errorf("the desired revision moved from %q to %q; a restart is not a setting",
			revisionBefore, after.Revision)
	}
}

// Another tenant cannot restart this tenant's agent. Of everything in this
// surface, this is the one that ends somebody's collection.
func TestIntegration_AgentConfig_RestartIsTenantScoped(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenantA := testdb.NewTenant(t, admin)
	tenantB := testdb.NewTenant(t, admin)
	agentID := seedAgent(t, admin, tenantA)

	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewAgentConfigHandler(app)
	p := gin.Params{{Key: "id", Value: agentID.String()}}

	if w := call(t, h.RequestAgentRestart, tenantB, http.MethodPost, "/restart", "", p); w.Code != http.StatusNotFound {
		t.Errorf("another tenant restarting this agent = %d, want 404", w.Code)
	}
	if w := call(t, h.RequestAgentRestart, tenantA, http.MethodPost, "/restart", "", p); w.Code != http.StatusAccepted {
		t.Errorf("the owning tenant = %d, want 202", w.Code)
	}
}
