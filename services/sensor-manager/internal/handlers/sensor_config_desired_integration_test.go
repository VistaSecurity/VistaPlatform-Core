package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func seedSensor(t *testing.T, db *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO public.sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, $3, 'linux', '1.0.0', 'datacenter_host', 'active')`,
		id, tenant, "sensor-"+id.String()[:8]); err != nil {
		t.Fatalf("seeding sensor: %v", err)
	}
	return id
}

func call(t *testing.T, h gin.HandlerFunc, tenant uuid.UUID, method, body string, params gin.Params) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, "/desired-config", bytes.NewBufferString(body))
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

func settingValue(t *testing.T, w *httptest.ResponseRecorder, key agentconfig.Key) any {
	t.Helper()
	for _, s := range decode(t, w)["settings"].([]any) {
		m := s.(map[string]any)
		if m["key"] == string(key) {
			return m["value"]
		}
	}
	return nil
}

// The sensor half of the same surface the agents use, on the app role — the
// posture a real deployment runs, where `sensors` is RLS-protected and a
// plain-pool query would make every endpoint answer 404 for the tenant's own
// sensors.
func TestIntegration_SensorDesiredConfig_SetAndRead(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)

	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewSensorConfigHandler(app)
	p := gin.Params{{Key: "sensor_id", Value: sensorID.String()}}

	if w := call(t, h.PutSensorDesiredConfig, tenant, http.MethodPut,
		`{"values":{"dedup_ttl_minutes":15,"active_probing":false}}`, p); w.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}

	w := call(t, h.GetSensorDesiredConfig, tenant, http.MethodGet, "", p)
	if w.Code != http.StatusOK {
		t.Fatalf("GET on the app-role pool = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := settingValue(t, w, agentconfig.KeyDedupTTLMinutes); got != float64(15) {
		t.Errorf("dedup ttl = %v, want 15", got)
	}
	if got := settingValue(t, w, agentconfig.KeyActiveProbing); got != false {
		t.Errorf("active probing = %v, want an explicit false to stick", got)
	}
	if state := decode(t, w)["status"].(map[string]any)["state"]; state != string(agentconfig.StateNeverReported) {
		t.Errorf("state = %v, want never_reported", state)
	}
}

// The confirmation path, which has no live consumer on the agent runtime: DNS
// decoding is a sensor setting, and it became remotely settable ONLY on the
// condition that turning it on is confirmed and audited.
func TestIntegration_SensorDesiredConfig_DNSNeedsConfirmation(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)

	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewSensorConfigHandler(app)
	p := gin.Params{{Key: "sensor_id", Value: sensorID.String()}}

	// Without the flag: refused, and the answer NAMES what would be collected.
	w := call(t, h.PutSensorDesiredConfig, tenant, http.MethodPut,
		`{"values":{"host_observation_dns":true}}`, p)
	if w.Code != http.StatusConflict {
		t.Fatalf("PUT without confirmation = %d, want 409: %s", w.Code, w.Body.String())
	}
	needs, _ := decode(t, w)["needs_confirming"].([]any)
	if len(needs) != 1 {
		t.Fatalf("needs_confirming = %v, want the DNS setting", needs)
	}
	if text, _ := needs[0].(map[string]any)["confirm"].(string); text == "" {
		t.Error("the confirmation carried no text; an operator must be told what starts being collected")
	}

	// Nothing was stored by the refused attempt.
	if got := settingValue(t, call(t, h.GetSensorDesiredConfig, tenant, http.MethodGet, "", p),
		agentconfig.KeyHostObservationDNS); got != false {
		t.Errorf("DNS decoding = %v after a REFUSED save; a 409 must not be a partial write", got)
	}

	// With the flag: accepted.
	if w := call(t, h.PutSensorDesiredConfig, tenant, http.MethodPut,
		`{"values":{"host_observation_dns":true},"confirmed":true}`, p); w.Code != http.StatusOK {
		t.Fatalf("PUT with confirmation = %d: %s", w.Code, w.Body.String())
	}
	if got := settingValue(t, call(t, h.GetSensorDesiredConfig, tenant, http.MethodGet, "", p),
		agentconfig.KeyHostObservationDNS); got != true {
		t.Errorf("DNS decoding = %v after a confirmed save, want true", got)
	}

	// And it is AUDITED with the acting user — the other half of the condition.
	var count int
	if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_audit
		WHERE tenant_id = $1 AND sensor_id = $2 AND changed_by IS NOT NULL`, tenant, sensorID).Scan(&count); err != nil {
		t.Fatalf("reading the audit trail: %v", err)
	}
	if count == 0 {
		t.Error("turning on DNS decoding left no audit row naming who did it")
	}
}

// A restart-only setting must be reported as such at SAVE time. host_observation
// is one: the BPF filter is fixed when the capture handle opens, so switching
// the decoders on without reopening it leaves them running and receiving
// nothing. An operator not told this reads the resulting awaiting_restart as a
// failure.
func TestIntegration_SensorDesiredConfig_ReportsRestartRequired(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)

	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewSensorConfigHandler(app)
	p := gin.Params{{Key: "sensor_id", Value: sensorID.String()}}

	w := call(t, h.PutSensorDesiredConfig, tenant, http.MethodPut,
		`{"values":{"host_observation":false}}`, p)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}
	restart, _ := decode(t, w)["needs_restart"].([]any)
	if len(restart) != 1 || restart[0] != string(agentconfig.KeyHostObservation) {
		t.Errorf("needs_restart = %v, want [host_observation]", restart)
	}
}

// Fleet defaults move an inheriting sensor and leave an overriding one alone.
func TestIntegration_SensorDesiredConfig_FleetDefaults(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	inheriting := seedSensor(t, admin, tenant)
	overriding := seedSensor(t, admin, tenant)

	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewSensorConfigHandler(app)

	if w := call(t, h.PutSensorDesiredConfig, tenant, http.MethodPut, `{"values":{"dedup_ttl_minutes":5}}`,
		gin.Params{{Key: "sensor_id", Value: overriding.String()}}); w.Code != http.StatusOK {
		t.Fatalf("seeding the override: %d %s", w.Code, w.Body.String())
	}
	if w := call(t, h.PutSensorFleetDefaults, tenant, http.MethodPut, `{"values":{"dedup_ttl_minutes":120}}`, nil); w.Code != http.StatusOK {
		t.Fatalf("PUT defaults = %d: %s", w.Code, w.Body.String())
	}

	read := func(id uuid.UUID) any {
		return settingValue(t, call(t, h.GetSensorDesiredConfig, tenant, http.MethodGet, "",
			gin.Params{{Key: "sensor_id", Value: id.String()}}), agentconfig.KeyDedupTTLMinutes)
	}
	if got := read(inheriting); got != float64(120) {
		t.Errorf("inheriting sensor = %v, want the fleet default 120", got)
	}
	if got := read(overriding); got != float64(5) {
		t.Errorf("overriding sensor = %v, want its own 5 to survive", got)
	}
}

// Another tenant's sensor is a 404, not a 403 and not an empty read.
func TestIntegration_SensorDesiredConfig_OtherTenantIsNotFound(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenantA := testdb.NewTenant(t, admin)
	tenantB := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenantA)

	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewSensorConfigHandler(app)
	p := gin.Params{{Key: "sensor_id", Value: sensorID.String()}}

	if w := call(t, h.GetSensorDesiredConfig, tenantB, http.MethodGet, "", p); w.Code != http.StatusNotFound {
		t.Errorf("GET as another tenant = %d, want 404", w.Code)
	}
	if w := call(t, h.PutSensorDesiredConfig, tenantB, http.MethodPut, `{"values":{"dedup_ttl_minutes":9}}`, p); w.Code != http.StatusNotFound {
		t.Errorf("PUT as another tenant = %d, want 404", w.Code)
	}
}
