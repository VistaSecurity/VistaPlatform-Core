package deviceinterrogation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Vendor error bodies never reach a warning (review B1 on).
//
// An appliance's error BODY is its free text, and has been seen to carry what
// must never be stored: an F5 401 echoing the auth token and password, a
// FortiOS 500 quoting a PSK, a UniFi meta.msg quoting a password. Each case
// plants two kinds of secret: NAMED ones (which shared/redact.Text would also
// catch) and one UNNAMED free-text value that only keeping the body out of the
// error can stop — so this pins the layer-1 fix, not just the backstop. The
// vendor's numeric code must survive: it is the diagnosis.
func TestCollectors_ErrorBodiesNeverReachAWarning(t *testing.T) {
	cases := []struct {
		name, deviceType, endpoint string
		server                     func(t *testing.T) *httptest.Server
		secrets                    []string
		wantDetail                 string
	}{
		{
			name: "F5 401 body", deviceType: "f5_bigip", endpoint: "/mgmt/tm/net/vlan",
			server: func(t *testing.T) *httptest.Server {
				fixture := newF5OpsTestServer(t)
				fixture.Close()
				return httptest.NewServer(refuseHandler(fixture.Config.Handler,
					func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/net/vlan") },
					http.StatusUnauthorized,
					`{"code":401,"message":"Authentication failed for session F5FREETEXT9",`+
						`"X-F5-Auth-Token":"F5TOKSECRET1","token":"F5TOKSECRET2","password":"F5PWSECRET3"}`))
			},
			secrets:    []string{"F5FREETEXT9", "F5TOKSECRET1", "F5TOKSECRET2", "F5PWSECRET3"},
			wantDetail: "F5 code 401",
		},
		{
			name: "FortiOS 500 body", deviceType: "fortigate", endpoint: "/api/v2/cmdb/system/interface",
			server: func(t *testing.T) *httptest.Server {
				fixture := newFortinetOpsTestServer(t)
				fixture.Close()
				return httptest.NewServer(refuseHandler(fixture.Config.Handler,
					func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/cmdb/system/interface") },
					http.StatusInternalServerError,
					`{"http_status":500,"status":"error","error":-5,"psksecret":"ENC FGPSKSECRET1",`+
						`"error_message":"tunnel vpn1 uses FGFREETEXT9"}`))
			},
			secrets:    []string{"FGPSKSECRET1", "FGFREETEXT9"},
			wantDetail: "FortiOS error -5",
		},
		{
			// The monitor API goes through its own request path.
			name: "FortiOS monitor 403 body", deviceType: "fortigate", endpoint: "/api/v2/monitor/router/ipv4",
			server: func(t *testing.T) *httptest.Server {
				fixture := newFortinetOpsTestServer(t)
				fixture.Close()
				return httptest.NewServer(refuseHandler(fixture.Config.Handler,
					func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/monitor/router/ipv4") },
					http.StatusForbidden,
					`{"http_status":403,"status":"error","error":-37,"error_message":"admin FGMONFREETEXT9 lacks routing"}`))
			},
			secrets:    []string{"FGMONFREETEXT9"},
			wantDetail: "FortiOS error -37",
		},
		{
			// FortiOS also refuses inside a 200: status "error" in the envelope,
			// with error_message as free text beside the numeric code.
			name: "FortiOS 200 error envelope", deviceType: "fortigate", endpoint: "/api/v2/cmdb/vpn.ipsec/phase1-interface",
			server: func(t *testing.T) *httptest.Server {
				fixture := newFortinetOpsTestServer(t)
				fixture.Close()
				return httptest.NewServer(refuseHandler(fixture.Config.Handler,
					func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/vpn.ipsec/phase1-interface") },
					http.StatusOK,
					`{"status":"error","error":-8,"error_message":"psk FGENVFREETEXT9 invalid"}`))
			},
			secrets:    []string{"FGENVFREETEXT9"},
			wantDetail: "FortiOS code -8",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := c.server(t)
			defer srv.Close()
			result := interrogateVia(t, c.deviceType, DeviceInfo{ManagementURL: srv.URL})
			w := findWarning(t, result, c.endpoint)
			if !strings.Contains(w.Detail, c.wantDetail) {
				t.Errorf("detail = %q; want the vendor's code %q kept", w.Detail, c.wantDetail)
			}
			blob, _ := json.Marshal(result)
			for _, s := range c.secrets {
				if strings.Contains(string(blob), s) {
					t.Errorf("%q from the error body reached the result (detail %q)", s, w.Detail)
				}
			}
		})
	}

	t.Run("UniFi meta.msg", func(t *testing.T) {
		fixture := newMockUnifiOSController(t)
		fixture.Close()
		srv := httptest.NewTLSServer(refuseHandler(fixture.Config.Handler,
			func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/stat/sta") },
			http.StatusOK, `{"meta":{"rc":"error","msg":"password: UNIFIPW1 for UNIFIFREETEXT9"},"data":[]}`))
		defer srv.Close()
		interrogator, err := NewRegistry().Get("unifi")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		result, err := interrogator.Interrogate(context.Background(),
			DeviceInfo{DeviceType: "unifi", ManagementURL: srv.URL},
			Credentials{Username: "admin", Password: "admin", InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("Interrogate: %v", err)
		}
		w := findWarning(t, result, "/proxy/network/api/s/default/stat/sta")
		blob, _ := json.Marshal(result)
		for _, s := range []string{"UNIFIPW1", "UNIFIFREETEXT9"} {
			if strings.Contains(string(blob), s) {
				t.Errorf("%q from meta.msg reached the result (detail %q)", s, w.Detail)
			}
		}
		if !strings.Contains(w.Detail, "unrecognised controller error") {
			t.Errorf("detail = %q; a free-text meta.msg must be replaced, and say so", w.Detail)
		}
	})

	// The controller's own error tokens are the diagnosis, and survive.
	t.Run("UniFi error token kept", func(t *testing.T) {
		err := unifiAPIError("api.err.NoPermission")
		if err.Error() != "API error: api.err.NoPermission" || ClassifyWarningReason(err) != WarningPermissionDenied {
			t.Errorf("unifiAPIError(NoPermission) = %q / %q", err, ClassifyWarningReason(err))
		}
	})

	// PAN-OS: only a numeric envelope code is kept.
	t.Run("PAN-OS non-numeric code dropped", func(t *testing.T) {
		if got := panAPIError("PANFREETEXT9", "show arp all").Error(); strings.Contains(got, "PANFREETEXT9") {
			t.Errorf("a non-numeric PAN-OS code reached the error: %q", got)
		}
		if got := panAPIError("403", "show arp all").Error(); !strings.Contains(got, "PAN-OS code 403") {
			t.Errorf("the numeric PAN-OS code was lost: %q", got)
		}
	})
}
