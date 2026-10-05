package handlers

// Contract + validation for the additional-TLS-ports sensor setting (
// WP5), through the REAL desired-config handler and the sensor-manager spec.
// No database: describing settings needs only the registry, and a refused
// write is refused before the store is touched.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/confighttp"
)

// Every sensor setting as the GET endpoints render it — the port list
// included, with its kind and its built-in port table — conforms to the spec.
// A `port_list` kind the spec's enum does not list, or a value the spec's
// oneOf does not admit, fails here.
func TestContract_SensorSettings_describePortList(t *testing.T) {
	sv := loadSpec(t)
	device := agentconfig.Values{agentconfig.KeyExtraTLSPorts: agentconfig.Text("9443,10443")}
	body, err := json.Marshal(gin.H{
		"runtime":  agentconfig.RuntimeSensor,
		"settings": confighttp.Describe(agentconfig.Resolve(agentconfig.RuntimeSensor, nil, device)),
	})
	if err != nil {
		t.Fatal(err)
	}
	sv.assertConforms(t, "SensorConfigDefaultsResponse", body)

	var out struct {
		Settings []map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	var found map[string]any
	for _, s := range out.Settings {
		if s["key"] == string(agentconfig.KeyExtraTLSPorts) {
			found = s
		}
	}
	if found == nil {
		t.Fatal("extra_tls_ports is not described; the console has nothing to render")
	}
	if found["kind"] != "port_list" || found["value"] != "9443,10443" || found["apply"] != "restart" || found["label"] != "Additional TLS ports" {
		t.Errorf("described as %v", found)
	}
	if ports, _ := found["built_in_ports"].(map[string]any); ports["443"] != "HTTPS" {
		t.Errorf("built_in_ports = %v, want the sensor's table keyed by port", found["built_in_ports"])
	}
}

// A write with a junk port list is refused with 400, every bad entry named,
// in the shape the spec declares — through the handler the route mounts.
func TestContract_PutSensorFleetDefaults_400_badPortList(t *testing.T) {
	sv := loadSpec(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", testTenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})
	// No database: a refused value never reaches the store, and if it did the
	// nil pool would answer 500, not 400.
	r.PUT("/sensors/config/defaults", NewSensorConfigHandler(nil).PutSensorFleetDefaults)

	for _, tc := range []struct {
		body string
		want []string
	}{
		{`{"values":{"extra_tls_ports":"9443,abc,70000"}}`, []string{`"abc" is not a port number`, "70000 is outside the port range 1-65535"}},
		{`{"values":{"extra_tls_ports":"9000-9010"}}`, []string{`"9000-9010" is a range`}},
		{`{"values":{"extra_tls_ports":9443}}`, []string{"expected a list of port numbers"}},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/sensors/config/defaults", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400: %s", tc.body, w.Code, w.Body.String())
		}
		sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		var got struct {
			Problems []string `json:"problems"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(got.Problems, "\n")
		for _, want := range tc.want {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: problems %q do not name %q", tc.body, got.Problems, want)
			}
		}
	}
}
