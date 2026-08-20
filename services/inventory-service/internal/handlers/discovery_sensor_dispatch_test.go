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

// Tenant-sensor dispatch does not exist: nothing converts a discovery job into a
// sensor command, and requested_sensor_ids is stored but consumed by nothing.
// A job asking for it used to be accepted and then run from the platform cluster
// instead — reaching nothing on a target only the tenant's sensor can see, and
// finishing `completed` with zero findings.
//
// Running somewhere other than where the caller asked is worse than refusing, so
// the request is refused. These tests pin the refusal at the tenant-facing entry
// point; cluster-sensor-service rejects it again on its own creation path
// (TestRejectSensorDispatch), and its job processor fails any pre-existing row
// rather than running it in-cluster.
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

func TestCreateJob_RejectsSensorExecutionMode(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"lowercase", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"sensors"}`},
		{"mixed case", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"Sensors"}`},
		{"padded", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":" sensors "}`},
		{"preferred sensor ids without the mode", `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"auto","preferred_sensor_ids":["` + uuid.New().String() + `"]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postDiscoveryJob(t, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — a sensor-dispatch request must be refused, not silently run on another executor. body=%s", w.Code, w.Body.String())
			}
			var parsed struct {
				Error   string `json:"error"`
				Details string `json:"details"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("decode body: %v (%s)", err, w.Body.String())
			}
			if !strings.Contains(parsed.Details, "sensors") {
				t.Errorf("details = %q, want it to name the unsupported execution mode", parsed.Details)
			}
		})
	}
}

// The other side of the guard: the supported modes must still reach
// cluster-sensor-service. Without this, "reject sensors" could quietly become
// "reject everything" and the reject-test above would stay green.
func TestCreateJob_ForwardsSupportedExecutionModes(t *testing.T) {
	for _, mode := range []string{"", "auto", "cloud", "async"} {
		t.Run("mode="+mode, func(t *testing.T) {
			forwarded := false
			cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				w.WriteHeader(http.StatusInternalServerError) // stop before audit logging
			}))
			defer cluster.Close()

			t.Setenv("CLUSTER_SENSOR_SERVICE_URL", cluster.URL)
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

			body := `{"targets":["198.51.100.10"],"protocols":["TLS"],"ports":[443],"execution_mode":"` + mode + `"}`
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/discovery/jobs", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			engine.ServeHTTP(w, req)

			if strings.Contains(w.Body.String(), "cannot be dispatched to") {
				t.Fatalf("execution_mode %q was rejected as sensor dispatch: %s", mode, w.Body.String())
			}
			if !forwarded {
				t.Fatalf("execution_mode %q never reached cluster-sensor-service; body=%s", mode, w.Body.String())
			}
		})
	}
}
