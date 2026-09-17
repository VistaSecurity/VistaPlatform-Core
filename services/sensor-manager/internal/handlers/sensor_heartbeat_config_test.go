package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The desired-state exchange is a BLOCK inside the heartbeat handler, and a
// block is what tests miss: every test of the exchange itself stays green when
// the line that carries it to the sensor is deleted. So this drives the real
// heartbeat handler.
//
// Mutation check: delete `response.Config = payload`, or the RecordReport half,
// and this fails.
func TestIntegration_SensorHeartbeatCarriesTheConfigExchange(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)

	h := newHeartbeatHandler(t, admin)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sensors/:sensor_id/heartbeat", h.Heartbeat)

	// status "active" is what the sensor binary actually sends (sensor/cmd/main.go).
	// "healthy" is documented on SensorHealth and handled by the heartbeat
	// UPDATE's CASE, but violates sensors_status_check — see issue filed
	// separately; not this feature's to fix, but worth knowing before copying
	// this payload.
	post := func(body string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/sensors/"+sensorID.String()+"/heartbeat", bytes.NewBufferString(body))
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

	// A beat with no configuration report still gets an answer: a sensor has to
	// be told what it should be running before it can ever converge.
	got := post(`{"sensor_id":"` + sensorID.String() + `","status":"active"}`)
	cfg, ok := got["config"].(map[string]any)
	if !ok {
		t.Fatalf("heartbeat response carried no config block: %v\n"+
			"Without it the sensor is never told its desired state and can never converge.", got)
	}
	revision, _ := cfg["revision"].(string)
	if revision == "" {
		t.Fatal("the config block carried no revision")
	}

	// The sensor's report must be RECORDED, not merely answered.
	post(`{"sensor_id":"` + sensorID.String() + `","status":"active","config_revision":"` + revision + `"}`)

	var stored sql.NullString
	if err := admin.QueryRow(`SELECT reported_revision FROM public.agent_config_state WHERE sensor_id = $1`, sensorID).
		Scan(&stored); err != nil {
		t.Fatalf("reading the recorded state: %v — the sensor's report was never stored", err)
	}
	if stored.String != revision {
		t.Errorf("recorded revision = %q, want %q", stored.String, revision)
	}

	// And the operator surface now reads "applied" for it.
	w := call(t, handlers.NewSensorConfigHandler(admin).GetSensorDesiredConfig, tenant, http.MethodGet, "",
		gin.Params{{Key: "sensor_id", Value: sensorID.String()}})
	if state := decode(t, w)["status"].(map[string]any)["state"]; state != string(agentconfig.StateApplied) {
		t.Errorf("state = %v, want applied once the sensor reported the desired revision", state)
	}
}

func newHeartbeatHandler(t *testing.T, db *sql.DB) *handlers.Handler {
	t.Helper()
	repo := database.NewSensorRepository(db, db)
	legacy := services.NewSensorService(db, db)
	v2 := services.NewSensorServiceV2(repo)
	return handlers.NewHandlerWithBoth(legacy, v2, repo, db, db)
}
