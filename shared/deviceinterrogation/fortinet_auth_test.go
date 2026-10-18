package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
)

func TestFortinetIdentify_UsesBearerTokenAndMonitorStatus(t *testing.T) {
	const token = "fortigate-readonly-token"
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want bearer token", got)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v2/monitor/system/status" {
			t.Errorf("path = %q, want current FortiOS status endpoint", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
            "status":"success",
            "serial":"FW40FTK000000001",
            "version":"v7.4.8",
            "results":{"hostname":"vista-lab-fw","model_name":"FortiWiFi 40F"}
        }`))
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	for _, tc := range []struct {
		name  string
		creds Credentials
	}{
		{name: "token credential", creds: Credentials{Token: token}},
		{name: "stored token marker", creds: Credentials{Username: fortinetTokenUsername, Password: token}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (&FortinetInterrogator{}).Identify(context.Background(), DeviceInfo{
				DeviceType: "fortinet", ManagementURL: srv.URL,
			}, tc.creds)
			if err != nil {
				t.Fatalf("Identify: %v", err)
			}
			if got.Model != "FortiWiFi 40F" || got.SerialNumber != "FW40FTK000000001" || got.FirmwareVersion != "v7.4.8" || got.Hostname != "vista-lab-fw" {
				t.Errorf("identity = %+v", got)
			}
		})
	}
	if requests != 2 {
		t.Errorf("requests = %d, want one monitor request per identification", requests)
	}
}

// A refused credential is not retried on the legacy path: a second login with a
// stale password risks locking the account out.
func TestFortinetIdentify_AuthRefusalDoesNotFallBack(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	_, err := (&FortinetInterrogator{}).Identify(context.Background(), DeviceInfo{
		DeviceType: "fortinet", ManagementURL: srv.URL,
	}, Credentials{Username: "admin", Password: "stale"})
	if err == nil {
		t.Fatal("want an authentication error")
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1 (no legacy retry after 401)", requests)
	}
}
