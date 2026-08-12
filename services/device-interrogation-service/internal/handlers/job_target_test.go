package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// TestBuildJobParametersCarriesAddress pins at the creation site: the job
// payload must be sufficient for an executor that cannot read the device row.
func TestBuildJobParametersCarriesAddress(t *testing.T) {
	device := &models.Device{
		ID:            uuid.New(),
		DeviceType:    "unifi",
		Hostname:      strPtr("home gw"),
		IPAddress:     strPtr("192.0.2.1"),
		ManagementURL: strPtr("https://192.0.2.1:8443"),
		Metadata:      models.JSONB{"site_id": "default"},
	}

	params := buildJobParameters(device, nil)

	for key, want := range map[string]string{
		"device_type":    "unifi",
		"device_id":      device.ID.String(),
		"hostname":       "home gw",
		"ip_address":     "192.0.2.1",
		"management_url": "https://192.0.2.1:8443",
		"site_id":        "default",
	} {
		if got, _ := params[key].(string); got != want {
			t.Errorf("params[%q] = %q, want %q", key, got, want)
		}
	}
}

// TestBuildJobParametersOmitsEmptyFields keeps absent values out of the payload
// entirely, so a consumer can distinguish "not set" from "set to empty".
func TestBuildJobParametersOmitsEmptyFields(t *testing.T) {
	device := &models.Device{
		ID:         uuid.New(),
		DeviceType: "unifi",
		IPAddress:  strPtr("10.0.0.5"),
		Hostname:   strPtr(""), // stored but blank
	}

	params := buildJobParameters(device, nil)

	if _, present := params["hostname"]; present {
		t.Error("blank hostname should be omitted, not sent as an empty string")
	}
	if _, present := params["management_url"]; present {
		t.Error("nil management_url should be omitted")
	}
	if got, _ := params["ip_address"].(string); got != "10.0.0.5" {
		t.Errorf("params[ip_address] = %q, want %q", got, "10.0.0.5")
	}
}

// TestBuildJobParametersMergesExtra covers the bulk path, which tags its jobs.
func TestBuildJobParametersMergesExtra(t *testing.T) {
	device := &models.Device{
		ID:         uuid.New(),
		DeviceType: "f5",
		IPAddress:  strPtr("10.0.0.5"),
	}

	params := buildJobParameters(device, map[string]interface{}{"bulk": true})

	if bulk, _ := params["bulk"].(bool); !bulk {
		t.Error("expected bulk marker to be carried through")
	}
	if got, _ := params["ip_address"].(string); got != "10.0.0.5" {
		t.Errorf("params[ip_address] = %q, want the address to survive the merge", got)
	}
}

// TestBuildJobParametersAlwaysHasATarget is the regression guard proper: for any
// device that has an address at all, the payload must carry one.
func TestBuildJobParametersAlwaysHasATarget(t *testing.T) {
	devices := map[string]*models.Device{
		"hostname only":       {ID: uuid.New(), DeviceType: "unifi", Hostname: strPtr("gw.example.test")},
		"ip only":             {ID: uuid.New(), DeviceType: "unifi", IPAddress: strPtr("192.0.2.1")},
		"management url only": {ID: uuid.New(), DeviceType: "unifi", ManagementURL: strPtr("https://gw:8443")},
	}

	for name, device := range devices {
		t.Run(name, func(t *testing.T) {
			params := buildJobParameters(device, nil)
			var found bool
			for _, key := range []string{"hostname", "ip_address", "management_url"} {
				if s, ok := params[key].(string); ok && s != "" {
					found = true
				}
			}
			if !found {
				t.Errorf("payload carries no address the agent could reach: %#v", params)
			}
		})
	}
}
