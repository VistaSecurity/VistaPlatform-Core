package handlers

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// Regression tests for (cross-tenant sensor IDOR). The whole by-sensor-id
// management surface must refuse a sensor that belongs to another tenant. The
// stub models that with forTenantErr: GetSensorByIDForTenant returns "not
// found" for the caller's tenant even though the sensor exists, exactly as the
// real tenant-scoped query would. Every guarded route must answer 404 — never
// reach the data/mutation path. Downstream data (commands/health) is populated
// too: a handler that skipped the guard would 200 with it and fail loudly.
func TestIDOR_CrossTenantSensorRoutesReturn404(t *testing.T) {
	cases := []struct {
		name, method, path string
		body               string
	}{
		{"get", http.MethodGet, "/api/v1/sensor-manager/sensors/" + aUUID, ""},
		{"update-status", http.MethodPut, "/api/v1/sensor-manager/sensors/" + aUUID + "/status", `{"status":"inactive"}`},
		{"delete", http.MethodDelete, "/api/v1/sensor-manager/sensors/" + aUUID, ""},
		{"create-command", http.MethodPost, "/api/v1/sensor-manager/sensors/" + aUUID + "/commands", `{"command_type":"restart"}`},
		{"list-commands", http.MethodGet, "/api/v1/sensor-manager/sensors/" + aUUID + "/commands", ""},
		{"health", http.MethodGet, "/api/v1/sensor-manager/sensors/" + aUUID + "/health", ""},
		{"health-history", http.MethodGet, "/api/v1/sensor-manager/sensors/" + aUUID + "/health/history", ""},
		{"discoveries", http.MethodGet, "/api/v1/sensor-manager/sensors/" + aUUID + "/discoveries", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newEngine(&stubSensorRepo{
				getSensor:    sampleSensor(),
				forTenantErr: errSensorNotForTenant{},
				commands:     []*models.SensorCommand{sampleCommand()},
				health:       sampleHealth(),
			})
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			w := do(eng, tc.method, tc.path, body)
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s %s = %d, want 404 (cross-tenant must be denied); body=%s",
					tc.method, tc.path, w.Code, w.Body.String())
			}
		})
	}
}

// A distinct error type so the test reads clearly; the guard only checks for
// a non-nil error from the scoped lookup.
type errSensorNotForTenant struct{}

func (errSensorNotForTenant) Error() string { return "sensor not found" }
