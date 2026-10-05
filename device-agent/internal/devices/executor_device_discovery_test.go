package devices

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
)

// An Add device routed to this agent ( slice B) runs the SAME shared
// identification the platform runs, through the REAL Execute dispatch and the
// REAL Fortinet collector against a fake FortiGate. Deleting the
// `case di.JobTypeDeviceDiscovery` line fails this with "unknown job type".
//
// The fake's status answer also carries a private key and a PSK beside the
// identity — what a vendor could put in any response. The posted result is
// the IdentificationReport allowlist, so neither may appear anywhere in it,
// nor may the device password.
func TestExecute_DeviceDiscovery_PostsAllowlistedIdentification(t *testing.T) {
	const secretKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/system/status") {
			body, _ := json.Marshal(map[string]interface{}{
				"status": "success", "serial": "FGT60F0000000001", "version": "v7.4.4",
				"psksecret": "branch-tunnel-psk", "private-key": secretKey,
				"results": []map[string]interface{}{{"hostname": "fw-branch-01", "model_name": "FortiGate 60F", "version": "v7.4.4", "psksecret": "branch-tunnel-psk"}},
			})
			_, _ = w.Write(body)
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","results":[]}`))
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	rec := &recordingClient{}
	exec := &JobExecutor{submitter: rec, config: &config.Config{}, registry: di.NewRegistry()}
	job := &models.Job{
		ID:          uuid.New(),
		Type:        di.JobTypeDeviceDiscovery,
		DeviceType:  "fortinet",
		Credentials: map[string]interface{}{"username": "readonly", "password": "device-password-123"},
		Parameters:  map[string]interface{}{"device_type": "fortinet", "management_url": srv.URL},
	}
	if err := exec.Execute(job); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := rec.last()
	if got == nil || !got.Success || got.Identification == nil {
		t.Fatalf("no successful identification was submitted: %+v", got)
	}
	if got.Identification.SerialNumber != "FGT60F0000000001" || got.Identification.Model == "" {
		t.Errorf("identification = %+v, want the FortiGate's serial and model", *got.Identification)
	}
	if len(got.Assets) != 0 || len(got.Facts) != 0 || len(got.Metadata) != 0 {
		t.Errorf("a discovery posts the identification only; got assets/facts/metadata: %+v", got)
	}
	blob, _ := json.Marshal(got)
	for _, leak := range []string{"branch-tunnel-psk", "PRIVATE KEY", "device-password-123", "psksecret", "private-key", "password"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("posted result carries %q: %s", leak, blob)
		}
	}
}

// A failed identification goes home as its typed code and nothing else: the
// cause can carry whatever the device said.
func TestExecute_DeviceDiscovery_FailureIsTypedCodeOnly(t *testing.T) {
	// A listener closed before anyone dials it: connection refused.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	devicetest.AllowListener(t, addr)

	rec := &recordingClient{}
	exec := &JobExecutor{submitter: rec, config: &config.Config{}, registry: di.NewRegistry()}
	for _, c := range []struct {
		name, deviceType string
		want             di.IdentifyFailure
	}{
		{"unreachable", "fortinet", di.IdentifyConnectionFailed},
		{"type with no identification step", "other", di.IdentifyNotSupported},
	} {
		t.Run(c.name, func(t *testing.T) {
			job := &models.Job{
				ID: uuid.New(), Type: di.JobTypeDeviceDiscovery, DeviceType: c.deviceType,
				Credentials: map[string]interface{}{"username": "u", "password": "device-password-123"},
				Parameters:  map[string]interface{}{"device_type": c.deviceType, "management_url": "https://" + addr},
			}
			if err := exec.Execute(job); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			got := rec.last()
			if got == nil || got.Success {
				t.Fatalf("want a failed result, got %+v", got)
			}
			if got.FailureCode != string(c.want) || got.Error != string(c.want) {
				t.Errorf("failure = (%q, %q), want the code %q alone", got.FailureCode, got.Error, c.want)
			}
		})
	}
}
