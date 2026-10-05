package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// Tenant-sensor dispatch. cluster-sensor-service now dispatches a
// `sensors` job to the tenant sensor it names, so the tenant-facing proxy
// FORWARDS such requests instead of refusing them. What it still refuses
// locally is the request shape no dispatcher can honour: preferred sensor ids
// on a mode that does not dispatch, more or fewer than one sensor, an id that
// is not a UUID. Everything about whether the sensor exists, is the tenant's,
// is live, is decided downstream — and its verdict (400/404/409, with the
// reason) is passed through rather than collapsed into "failed to create
// discovery job".

func postDiscoveryJob(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &DiscoveryHandler{}

	engine := gin.New()
	engine.POST("/discovery/jobs", func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		h.CreateJob(c)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/discovery/jobs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)
	return w
}

func TestCreateJob_RefusesAnUndispatchableSensorRequestShape(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"preferred sensor ids without the mode", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"auto","preferred_sensor_ids":["` + uuid.New().String() + `"]}`, "preferred_sensor_ids"},
		{"sensors mode, no sensor", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"sensors"}`, "exactly one"},
		{"sensors mode, two sensors", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"sensors","preferred_sensor_ids":["` + uuid.New().String() + `","` + uuid.New().String() + `"]}`, "exactly one"},
		{"sensors mode, id not a uuid", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"sensors","preferred_sensor_ids":["xps16"]}`, "not a UUID"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postDiscoveryJob(t, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400. body=%s", w.Code, w.Body.String())
			}
			var parsed struct {
				Error   string `json:"error"`
				Details string `json:"details"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("decode body: %v (%s)", err, w.Body.String())
			}
			if !strings.Contains(parsed.Details, tc.want) {
				t.Errorf("details = %q, want it to mention %q", parsed.Details, tc.want)
			}
		})
	}
}

// newProxyEngine mounts the real CreateJob handler in front of a fake
// cluster-sensor-service.
func newProxyEngine(t *testing.T, cluster http.HandlerFunc) (*gin.Engine, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(cluster)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	svc, err := services.NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatalf("NewDiscoveryService: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := NewDiscoveryHandler(nil, svc)
	engine := gin.New()
	engine.POST("/discovery/jobs", func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		h.CreateJob(c)
	})
	return engine, srv
}

func postThrough(engine *gin.Engine, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/discovery/jobs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)
	return w
}

// The positive polarity: every supported mode — `sensors` with one sensor
// included — reaches cluster-sensor-service. Without this, "refuse the bad
// shapes" could quietly become "refuse everything" and the test above would
// stay green.
func TestCreateJob_ForwardsSupportedExecutionModes(t *testing.T) {
	sensorID := uuid.New().String()
	cases := []struct {
		name string
		body string
	}{
		{"empty", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":""}`},
		{"auto", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"auto"}`},
		{"cloud", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"cloud"}`},
		{"async", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"async"}`},
		{"sensors with one sensor", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"sensors","preferred_sensor_ids":["` + sensorID + `"]}`},
		{"SENSORS padded", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":" Sensors ","preferred_sensor_ids":["` + sensorID + `"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwarded := false
			var gotBody map[string]interface{}
			engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.WriteHeader(http.StatusInternalServerError) // stop before audit logging
			})
			defer srv.Close()

			w := postThrough(engine, tc.body)
			if !forwarded {
				t.Fatalf("request never reached cluster-sensor-service; status=%d body=%s", w.Code, w.Body.String())
			}
			if strings.Contains(tc.name, "sensors") {
				ids, _ := gotBody["preferred_sensor_ids"].([]interface{})
				if len(ids) != 1 || ids[0] != sensorID {
					t.Errorf("forwarded preferred_sensor_ids = %v, want [%s]", ids, sensorID)
				}
			}
		})
	}
}

// Downstream's verdict on the sensor is the caller's to act on, so its status
// and reason come through: 404 unknown, 409 offline, 400 the platform's own.
func TestCreateJob_PassesThroughTheDispatchVerdict(t *testing.T) {
	cases := []struct {
		name   string
		status int
		reason string
	}{
		{"unknown sensor", http.StatusNotFound, "sensor not found: 5f7d1b34-6c0a-4c1e-9c8f-2b1d3e4f5a6b"},
		{"offline sensor", http.StatusConflict, "sensor offline: sensor xps16-sensor offline; nothing was scanned"},
		{"platform sensor", http.StatusBadRequest, "invalid sensor dispatch request: Platform Discovery Sensor is the platform sensor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": tc.reason})
			})
			defer srv.Close()

			w := postThrough(engine, `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"sensors","preferred_sensor_ids":["`+uuid.New().String()+`"]}`)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d passed through; body=%s", w.Code, tc.status, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.reason) {
				t.Errorf("body = %s, want the downstream reason %q", w.Body.String(), tc.reason)
			}
		})
	}
}

// A downstream 5xx stays a generic 400 "failed to create discovery job" —
// only 4xx verdicts pass through, because a 5xx's body is not a reason the
// caller can act on.
func TestCreateJob_DoesNotPassThroughDownstreamServerErrors(t *testing.T) {
	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"internal detail"}`))
	})
	defer srv.Close()
	w := postThrough(engine, `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"auto"}`)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "internal detail") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

// `protocols` is allowlisted (H6 of): an OT/ICS name there would reach
// cluster-sensor's OT probers without the explicit ot_probe_protocols opt-in, its
// audit column and its one-standard-port restriction. The person is told why,
// and nothing is forwarded.
func TestCreateJob_RefusesProtocolsOutsideTheAllowlist(t *testing.T) {
	cases := []struct {
		name      string
		protocols string
		wantOT    bool
	}{
		{"modbus beside TLS", `["TLS","Modbus"]`, true},
		{"OPC UA", `["OPC UA"]`, true},
		{"opc_ua", `["opc_ua"]`, true},
		{"EtherNet/IP", `["EtherNet/IP"]`, true},
		{"BACnet", `["BACnet"]`, true},
		{"DNP3", `["DNP3"]`, true},
		{"HART-IP", `["HART-IP"]`, true},
		{"garbage", `["TLS","garbage"]`, false},
		{"empty name", `["TLS",""]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwarded := false
			engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				w.WriteHeader(http.StatusInternalServerError)
			})
			defer srv.Close()

			w := postThrough(engine, `{"targets":["198.51.100.10"],"protocols":`+tc.protocols+`,"ports":[443],"execution_mode":"auto"}`)
			if forwarded {
				t.Fatal("a job with a refused protocol reached cluster-sensor-service")
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400. body=%s", w.Code, w.Body.String())
			}
			var parsed struct {
				Error   string `json:"error"`
				Details string `json:"details"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("decode body: %v (%s)", err, w.Body.String())
			}
			if parsed.Error != "validation_error" {
				t.Errorf("error = %q, want validation_error", parsed.Error)
			}
			for _, allowed := range []string{"TLS", "SSH", "SMB"} {
				if !strings.Contains(parsed.Details, allowed) {
					t.Errorf("details %q do not name the allowed value %s", parsed.Details, allowed)
				}
			}
			if got := strings.Contains(parsed.Details, "ot_probe_protocols"); got != tc.wantOT {
				t.Errorf("details %q: points at ot_probe_protocols = %v, want %v", parsed.Details, got, tc.wantOT)
			}
		})
	}
}

// The positive polarity: every shape the product sends today still goes
// through, in the spellings people use. Without it "allowlist the field" could
// quietly become "refuse the field".
func TestCreateJob_ForwardsAllowedProtocols(t *testing.T) {
	for _, protocols := range []string{
		`["TLS"]`, `["SSH"]`, `["TLS","SSH"]`, `["SMB"]`, `["tls","ssh"]`,
		`["HTTPS","LDAPS","SMTPS","IMAPS","POP3S","FTPS","SSL"]`,
		`[]`, // service default: cluster-sensor decides what a job with no pair means
	} {
		t.Run(protocols, func(t *testing.T) {
			forwarded := false
			engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				w.WriteHeader(http.StatusInternalServerError) // stop before audit logging
			})
			defer srv.Close()
			w := postThrough(engine, `{"targets":["198.51.100.10"],"protocols":`+protocols+`,"ports":[443],"execution_mode":"auto"}`)
			if !forwarded {
				t.Fatalf("a job with protocols %s never reached cluster-sensor-service; status=%d body=%s", protocols, w.Code, w.Body.String())
			}
		})
	}
}

// A refusal that does reach this proxy from cluster-sensor-service (a caller
// that skipped this handler's own check) must still say why: the code alone
// is not an answer a person can act on.
func TestCreateJob_PassesThroughDownstreamProtocolRefusal(t *testing.T) {
	const reason = `protocols: "Modbus" not accepted; allowed values are TLS, SSH, SMB`
	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "validation_error", "details": reason})
	})
	defer srv.Close()
	w := postThrough(engine, `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"auto"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Modbus") {
		t.Fatalf("status=%d body=%s, want 400 carrying the downstream reason", w.Code, w.Body.String())
	}
}
