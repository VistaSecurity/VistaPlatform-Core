package handlers

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Command creation accepts only the verbs a sensor's dispatcher handles as
// operator actions. Mutation check: delete the tenantCommandTypes lookup in
// CreateSensorCommand and the "garbage" case returns 201.
func TestCreateSensorCommand_RejectsUnknownCommandType(t *testing.T) {
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	path := base + "/sensors/" + aUUID + "/commands"

	for _, ct := range []string{"garbage", "discovery_job", "resolve_identity_dns", "RESTART"} {
		w := do(eng, http.MethodPost, path, strings.NewReader(`{"command_type":"`+ct+`"}`))
		if w.Code != http.StatusBadRequest {
			t.Errorf("command_type %q = %d, want 400; body=%s", ct, w.Code, w.Body.String())
		}
	}
	for ct := range tenantCommandTypes {
		w := do(eng, http.MethodPost, path, strings.NewReader(`{"command_type":"`+ct+`"}`))
		if w.Code != http.StatusCreated {
			t.Errorf("command_type %q = %d, want 201; body=%s", ct, w.Code, w.Body.String())
		}
	}
}

func TestCreateSensorCommand_RejectsOversizedPayload(t *testing.T) {
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	path := base + "/sensors/" + aUUID + "/commands"
	big := strings.Repeat("a", maxCommandPayloadBytes+1)
	w := do(eng, http.MethodPost, path, strings.NewReader(`{"command_type":"update_config","payload":{"x":"`+big+`"}}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized payload = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestCreateSensorCommand_PendingCapIs429(t *testing.T) {
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), commandCapReached: true})
	w := do(eng, http.MethodPost, base+"/sensors/"+aUUID+"/commands", strings.NewReader(`{"command_type":"restart"}`))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("capped create = %d, want 429; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "maximum number of pending commands") {
		t.Errorf("429 body should explain the cap: %s", w.Body.String())
	}
}

// A database failure must not read as "this tenant has no sensors".
// Mutation check: restore the 200 + empty list in GetSensors / zeroed stats in
// GetSensorStats and both subtests go red.
func TestFleetListAndStats_DBErrorIs503(t *testing.T) {
	eng := newEngine(&stubSensorRepo{listErr: errors.New("connection refused")})
	for _, path := range []string{"/sensors", "/sensors/stats"} {
		w := do(eng, http.MethodGet, base+path, nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want 503; body=%s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"error"`) {
			t.Errorf("GET %s: no error body: %s", path, w.Body.String())
		}
	}
}

func TestGetSensorDiscoveries_LimitBounds(t *testing.T) {
	repo := &stubSensorRepo{getSensor: sampleSensor()}
	eng := newEngine(repo)
	path := base + "/sensors/" + aUUID + "/discoveries"

	cases := []struct {
		query     string
		wantCode  int
		wantLimit int
	}{
		{"", http.StatusOK, 50},
		{"?limit=10", http.StatusOK, 10},
		{"?limit=500", http.StatusOK, 500},
		{"?limit=100000", http.StatusOK, 500},
		{"?limit=abc", http.StatusBadRequest, 0},
		{"?limit=0", http.StatusBadRequest, 0},
		{"?limit=-5", http.StatusBadRequest, 0},
	}
	for _, tc := range cases {
		repo.lastDiscoveriesLimit = 0
		w := do(eng, http.MethodGet, path+tc.query, nil)
		if w.Code != tc.wantCode {
			t.Errorf("%q = %d, want %d; body=%s", tc.query, w.Code, tc.wantCode, w.Body.String())
			continue
		}
		if repo.lastDiscoveriesLimit != tc.wantLimit {
			t.Errorf("%q: repo limit = %d, want %d", tc.query, repo.lastDiscoveriesLimit, tc.wantLimit)
		}
	}
}

// A malformed id must be a 400 the sensor stops retrying, not a Postgres cast
// error surfacing as a 500. Mutation check: remove the uuid.Parse guards in
// AcknowledgeCommand and the stub service (which would error like Postgres
// does) turns these into 500s.
func TestOutbound_MalformedIDsAre400(t *testing.T) {
	legacy := &stubLegacySensorService{updateErr: errors.New("pq: invalid input syntax for type uuid")}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{sensorService: legacy, log: logrus.New()}
	r.POST("/sensors/:sensor_id/commands/:command_id/ack", h.AcknowledgeCommand)
	r.GET("/sensors/:sensor_id/commands/poll", h.PollCommands)
	r.GET("/sensors/:sensor_id/config", h.GetSensorConfig)
	r.GET("/sensors/:sensor_id/webhook-config", h.GetWebhookConfig)

	good := uuid.NewString()
	cases := []struct{ method, path, body string }{
		{http.MethodPost, "/sensors/" + good + "/commands/not-a-uuid/ack", `{"sensor_id":"` + good + `"}`},
		{http.MethodPost, "/sensors/not-a-uuid/commands/" + good + "/ack", `{"sensor_id":"` + good + `"}`},
		{http.MethodGet, "/sensors/not-a-uuid/commands/poll", ""},
		{http.MethodGet, "/sensors/not-a-uuid/config", ""},
		{http.MethodGet, "/sensors/not-a-uuid/webhook-config", ""},
	}
	for _, tc := range cases {
		w := do(r, tc.method, tc.path, strings.NewReader(tc.body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s %s = %d, want 400; body=%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}
