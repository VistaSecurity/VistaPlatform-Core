package deviceinterrogation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Identify drives the REAL vendor clients through the Registry against fake
// appliances. Each fake checks the credentials the way its vendor does, so the
// bad-password case is the device refusing them — not a stub returning an
// error the test chose.

const (
	identifyGoodUser = "admin"
	identifyGoodPass = "correct-horse"
)

// pathRecorder remembers every path a fake appliance was asked for, so a test
// can assert what Identify did NOT fetch.
type pathRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (p *pathRecorder) add(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paths = append(p.paths, path)
}

func (p *pathRecorder) all() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.paths...)
}

func newFortinetIdentifyServer(t *testing.T, rec *pathRecorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.URL.RequestURI())
		if user, pass, ok := r.BasicAuth(); !ok || user != identifyGoodUser || pass != identifyGoodPass {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":"error","error":-1,"echo":"` + pass + `"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/cmdb/system/status") {
			_, _ = w.Write([]byte(fortinetSystemStatusResponse))
			return
		}
		_, _ = w.Write([]byte(fortinetEmptyResponse))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newPanIdentifyServer(t *testing.T, rec *pathRecorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rec.add(panRequestShape(r))
		w.Header().Set("Content-Type", "application/xml")
		if r.Form.Get("type") == "keygen" {
			if r.Form.Get("user") != identifyGoodUser || r.Form.Get("password") != identifyGoodPass {
				// PAN-OS answers a bad password with HTTP 403 and code 403.
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>`))
				return
			}
			_, _ = w.Write([]byte(`<response status="success"><result><key>FAKEAPIKEY==</key></result></response>`))
			return
		}
		if r.Header.Get(panAPIKeyHeader) != "FAKEAPIKEY==" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.Contains(r.Form.Get("cmd"), "<system>") {
			_, _ = w.Write([]byte(panFixture(t, "paloalto_system_info.xml")))
			return
		}
		_, _ = w.Write([]byte(panEmptyResultResponse))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// panRequestShape is everything a PAN-OS request asks for — method, path and
// every parameter — minus the credential-bearing ones. Recording only `type`
// let an extra op command (`<show><config><running>`) through the scope
// assertion unseen ( review NB-3).
func panRequestShape(r *http.Request) string {
	keys := make([]string, 0, len(r.Form))
	for k := range r.Form {
		switch k {
		case "key", "user", "password":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{r.Method, r.URL.Path}
	for _, k := range keys {
		parts = append(parts, k+"="+strings.Join(r.Form[k], ","))
	}
	return strings.Join(parts, " ")
}

func newF5IdentifyServer(t *testing.T, rec *pathRecorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/mgmt/shared/authn/login") {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["username"] != identifyGoodUser || body["password"] != identifyGoodPass {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"code":401,"message":"Authentication failed."}`))
				return
			}
			_, _ = w.Write([]byte(`{"token":{"token":"FAKE-TOKEN"}}`))
			return
		}
		if r.Header.Get("X-F5-Auth-Token") != "FAKE-TOKEN" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/sys/version"):
			_, _ = w.Write([]byte(f5VersionResponse))
		case strings.HasSuffix(r.URL.Path, "/sys/hardware"):
			_, _ = w.Write([]byte(f5HardwareResponse))
		default:
			_, _ = w.Write([]byte(f5EmptyCollection))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newUnifiIdentifyServer is a UniFi OS console (UDM): the JSON login at
// /api/auth/login selects the /proxy/network prefix. The legacy paths answer
// 404, as they do on a console — which is what makes the bad-password case
// load-bearing for the refusal-wins rule in authenticate().
func newUnifiIdentifyServer(t *testing.T, rec *pathRecorder) *httptest.Server {
	t.Helper()
	ok := func(w http.ResponseWriter, data []map[string]interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}, "data": data})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != identifyGoodUser || body["password"] != identifyGoodPass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{
			{"name": "office-ap", "ip": "192.0.2.20", "mac": "aa:bb:cc:00:00:20", "model": "U6LR", "type": "uap", "serial": "AP-SERIAL", "version": "6.6.55"},
			{"name": "udm-gateway", "ip": "192.0.2.1", "mac": "aa:bb:cc:00:00:01", "model": "UDMPRO", "type": "udm", "serial": "UDM-SERIAL-0001", "version": "4.0.6",
				"x_authkey": "MUST-NOT-BE-COLLECTED"},
		})
	})
	mux.HandleFunc("/proxy/network/api/s/default/list/setting", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{{"key": "super_identity", "name": "HQ Console", "x_mesh_psk": "MUST-NOT-BE-COLLECTED"}})
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.URL.RequestURI())
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRegistryIdentify_EveryHTTPVendor(t *testing.T) {
	cases := []struct {
		deviceType string
		server     func(*testing.T, *pathRecorder) *httptest.Server
		want       DeviceIdentification
		// allowed is every request Identify may make. Anything else is the full
		// sweep leaking into the light call.
		allowed []string
	}{
		{
			deviceType: "fortinet",
			server:     newFortinetIdentifyServer,
			want: DeviceIdentification{
				DeviceIdentity: DeviceIdentity{Vendor: fortinetVendor, Model: "FortiGate 60F", SerialNumber: "FGT60F0000000001", FirmwareVersion: "v7.4.4"},
				Hostname:       "fw-branch-01",
			},
			allowed: []string{"/api/v2/cmdb/system/status"},
		},
		{
			deviceType: "palo_alto",
			server:     newPanIdentifyServer,
			want: DeviceIdentification{
				DeviceIdentity: DeviceIdentity{Vendor: panVendor, Model: "PA-3220", SerialNumber: "013201001234", OSVersion: "PAN-OS 11.1.4-h7"},
				Hostname:       "fw-edge-01", IPAddress: "192.0.2.5", MACAddress: "00:1b:17:0a:0b:0c",
			},
			allowed: []string{
				"POST /api/ type=keygen",
				"GET /api/ cmd=<show><system><info></info></system></show> type=op",
			},
		},
		{
			deviceType: "f5",
			server:     newF5IdentifyServer,
			want: DeviceIdentification{
				DeviceIdentity: DeviceIdentity{Vendor: f5Vendor, Model: "BIG-IP Virtual Edition", SerialNumber: "f5-abcd-efgh", FirmwareVersion: "17.1.1.3"},
			},
			allowed: []string{"/mgmt/shared/authn/login", "/mgmt/tm/sys/version", "/mgmt/tm/sys/hardware"},
		},
		{
			deviceType: "unifi",
			server:     newUnifiIdentifyServer,
			want: DeviceIdentification{
				DeviceIdentity: DeviceIdentity{Vendor: unifiVendor, Model: "UDMPRO", SerialNumber: "UDM-SERIAL-0001", FirmwareVersion: "4.0.6"},
				Hostname:       "udm-gateway", IPAddress: "192.0.2.1", MACAddress: "aa:bb:cc:00:00:01",
			},
			allowed: []string{"/api/auth/login", "/proxy/network/api/s/default/stat/device", "/proxy/network/api/s/default/list/setting"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.deviceType, func(t *testing.T) {
			rec := &pathRecorder{}
			srv := tc.server(t, rec)
			got, err := NewRegistry().Identify(context.Background(),
				DeviceInfo{DeviceType: tc.deviceType, ManagementURL: srv.URL},
				Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
			if err != nil {
				t.Fatalf("Identify: %v", err)
			}
			for field, pair := range map[string][2]string{
				"vendor":   {got.Vendor, tc.want.Vendor},
				"model":    {got.Model, tc.want.Model},
				"serial":   {got.SerialNumber, tc.want.SerialNumber},
				"hostname": {got.Hostname, tc.want.Hostname},
				"ip":       {got.IPAddress, tc.want.IPAddress},
				"mac":      {got.MACAddress, tc.want.MACAddress},
			} {
				if pair[0] != pair[1] {
					t.Errorf("%s = %q, want %q", field, pair[0], pair[1])
				}
			}
			if tc.want.FirmwareVersion != "" && got.FirmwareVersion != tc.want.FirmwareVersion {
				t.Errorf("firmware = %q, want %q", got.FirmwareVersion, tc.want.FirmwareVersion)
			}
			if tc.want.OSVersion != "" && got.OSVersion != tc.want.OSVersion {
				t.Errorf("os version = %q, want %q", got.OSVersion, tc.want.OSVersion)
			}
			if got.TargetHost != "127.0.0.1" || got.TargetPort == 0 {
				t.Errorf("target = %s:%d, want the dialled test server", got.TargetHost, got.TargetPort)
			}
			allowed := map[string]bool{}
			for _, p := range tc.allowed {
				allowed[p] = true
			}
			for _, p := range rec.all() {
				if !allowed[p] {
					t.Errorf("Identify requested %q, which is not part of the identity call; allowed: %v", p, tc.allowed)
				}
			}
			encoded, _ := json.Marshal(got)
			if strings.Contains(string(encoded), "MUST-NOT-BE-COLLECTED") {
				t.Errorf("identification carries a poison value: %s", encoded)
			}
		})
	}
}

// Bad credentials are the device refusing them, and the reason is typed.
func TestRegistryIdentify_BadCredentialsAreAuthenticationFailed(t *testing.T) {
	for deviceType, server := range map[string]func(*testing.T, *pathRecorder) *httptest.Server{
		"fortinet":  newFortinetIdentifyServer,
		"palo_alto": newPanIdentifyServer,
		"f5":        newF5IdentifyServer,
		"unifi":     newUnifiIdentifyServer,
	} {
		t.Run(deviceType, func(t *testing.T) {
			srv := server(t, &pathRecorder{})
			_, err := NewRegistry().Identify(context.Background(),
				DeviceInfo{DeviceType: deviceType, ManagementURL: srv.URL},
				Credentials{Username: identifyGoodUser, Password: "wrong-password"})
			assertIdentifyCode(t, err, IdentifyAuthenticationFailed)
			if strings.Contains(err.Error(), "wrong-password") {
				t.Errorf("the error carries the password the device echoed: %v", err)
			}
		})
	}
}

// The O-01 regression, pinned: an endpoint that is NOT the declared device —
// here a plain web server that answers every path 200 with an empty JSON
// object — must not come back as a successful identification.
func TestRegistryIdentify_SomethingElseAnsweringIsNotASuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	for _, deviceType := range []string{"fortinet", "f5"} {
		t.Run(deviceType, func(t *testing.T) {
			_, err := NewRegistry().Identify(context.Background(),
				DeviceInfo{DeviceType: deviceType, ManagementURL: srv.URL},
				Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
			assertIdentifyCode(t, err, IdentifyUnsupportedResponse)
		})
	}

	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	_, err := NewRegistry().Identify(context.Background(),
		DeviceInfo{DeviceType: "fortinet", ManagementURL: notFound.URL},
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyUnsupportedResponse)
}

func TestRegistryIdentify_TypesWithoutAnIdentityStepAreNotSupported(t *testing.T) {
	registry := NewRegistry()
	for _, deviceType := range []string{"generic_snmp", "generic_http", "postgresql", "other", ""} {
		if registry.CanIdentify(deviceType) {
			t.Errorf("CanIdentify(%q) = true; nothing implements it", deviceType)
		}
		_, err := registry.Identify(context.Background(),
			DeviceInfo{DeviceType: deviceType, ManagementURL: "https://192.0.2.10"},
			Credentials{Username: "u", Password: "p"})
		assertIdentifyCode(t, err, IdentifyNotSupported)
	}
	// Every vendor the Add device form offers, by every alias the registry
	// accepts for it.
	for _, deviceType := range []string{"fortinet", "fortigate", "palo_alto", "paloalto", "panos", "f5", "f5_bigip", "bigip",
		"unifi", "ubiquiti", "cisco", "cisco_router", "cisco_switch", "cisco_asa"} {
		if !registry.CanIdentify(deviceType) {
			t.Errorf("CanIdentify(%q) = false", deviceType)
		}
	}
}

// The dial guard is the collector's own, so Identify refuses loopback with
// nothing sent — for the HTTP vendors and for Cisco's SSH dial alike.
func TestRegistryIdentify_RefusesLoopbackBeforeSendingAnything(t *testing.T) {
	withRealDialGuard(t)
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	for _, deviceType := range []string{"fortinet", "palo_alto", "f5", "unifi"} {
		_, err := NewRegistry().Identify(context.Background(),
			DeviceInfo{DeviceType: deviceType, ManagementURL: srv.URL},
			Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
		assertIdentifyCode(t, err, IdentifyTargetDisallowed)
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Fatalf("the loopback target received %d request(s)", n)
	}

	ssh := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{})
	_, err := NewRegistry().Identify(context.Background(),
		DeviceInfo{DeviceType: "cisco", ManagementURL: "ssh://" + ssh.addr},
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyTargetDisallowed)
	if n := len(ssh.passwords()); n != 0 {
		t.Fatalf("the loopback SSH server was offered %d password(s)", n)
	}
}

// A self-signed management certificate is its own reason, and the explicit
// opt-in is what gets past it.
func TestRegistryIdentify_UntrustedCertificateAndTheOptIn(t *testing.T) {
	rec := &pathRecorder{}
	plain := newFortinetIdentifyServer(t, rec)
	srv := httptest.NewTLSServer(plain.Config.Handler)
	defer srv.Close()

	device := DeviceInfo{DeviceType: "fortinet", ManagementURL: srv.URL}
	_, err := NewRegistry().Identify(context.Background(), device,
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyTLSUntrusted)

	got, err := NewRegistry().Identify(context.Background(), device,
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("with the opt-in: %v", err)
	}
	if got.SerialNumber != "FGT60F0000000001" {
		t.Errorf("serial = %q", got.SerialNumber)
	}
}

// The caller's deadline bounds the call: a device that accepts the connection
// and never answers fails as connection_failed, promptly.
func TestRegistryIdentify_HonoursTheCallersDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewRegistry().Identify(ctx,
		DeviceInfo{DeviceType: "fortinet", ManagementURL: srv.URL},
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyConnectionFailed)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Identify took %s against a 300ms deadline", elapsed)
	}
}

func TestRegistryIdentify_InvalidManagementURL(t *testing.T) {
	for _, raw := range []string{"https://192.0.2.10/?x=1", "https://user:pass@192.0.2.10", "ftp://192.0.2.10", "https://192.0.2.10#"} {
		_, err := NewRegistry().Identify(context.Background(),
			DeviceInfo{DeviceType: "fortinet", ManagementURL: raw},
			Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
		assertIdentifyCode(t, err, IdentifyInvalidTarget)
	}
}

// PEM-shaped text in a device-reported hostname is masked on the way out, the
// same as it is in an interrogation's identity.
func TestRegistryIdentify_SanitizesReportedStrings(t *testing.T) {
	const pemBlock = "-----BEGIN PRIVATE KEY-----MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA-----END PRIVATE KEY-----"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","results":[{"version":"v7.4.4","serial":"FGT1","hostname":"` + pemBlock + `"}]}`))
	}))
	defer srv.Close()
	got, err := NewRegistry().Identify(context.Background(),
		DeviceInfo{DeviceType: "fortinet", ManagementURL: srv.URL},
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if strings.Contains(got.Hostname, "MIIBVAIBADAN") {
		t.Fatalf("hostname was not sanitized: %q", got.Hostname)
	}
}

func TestClassifyIdentifyError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want IdentifyFailure
	}{
		{"http 401", httpStatusError("login", http.StatusUnauthorized), IdentifyAuthenticationFailed},
		{"http 403", httpStatusError("login", http.StatusForbidden), IdentifyAuthenticationFailed},
		{"http 404", httpStatusError("login", http.StatusNotFound), IdentifyUnsupportedResponse},
		{"http 500", httpStatusError("login", http.StatusInternalServerError), IdentifyFailed},
		{"pan invalid credential", panAPIError("403", "keygen"), IdentifyAuthenticationFailed},
		{"ssh password refused", errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"), IdentifyAuthenticationFailed},
		{"guard", errors.New("dial tcp: ssrf guard: refusing to connect to 127.0.0.1"), IdentifyTargetDisallowed},
		{"deadline", context.DeadlineExceeded, IdentifyConnectionFailed},
		{"no target", ErrNoTarget, IdentifyInvalidTarget},
		{"already typed", &IdentifyError{Code: IdentifyHostKeyMismatch}, IdentifyHostKeyMismatch},
		{"anything else", errors.New("something odd"), IdentifyFailed},
	} {
		if got := ClassifyIdentifyError(tc.err).Code; got != tc.want {
			t.Errorf("%s: code = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func assertIdentifyCode(t *testing.T, err error, want IdentifyFailure) {
	t.Helper()
	if err == nil {
		t.Fatalf("Identify succeeded, want %s", want)
	}
	var identifyErr *IdentifyError
	if !errors.As(err, &identifyErr) {
		t.Fatalf("error %v (%T) is not an *IdentifyError", err, err)
	}
	if identifyErr.Code != want {
		t.Fatalf("code = %s, want %s (cause: %v)", identifyErr.Code, want, identifyErr.Err)
	}
}

// A legacy software controller is not one of its managed devices. Its device
// list here starts with an access point and holds no gateway, so the only
// honest identity is the controller's own name — never the first device's
// model and serial, which is what the old discovery client recorded (
// review NB-4).
func TestRegistryIdentify_UnifiLegacyControllerIsNotItsFirstDevice(t *testing.T) {
	ok := func(w http.ResponseWriter, data []map[string]interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}, "data": data})
	}
	mux := http.NewServeMux()
	// No /api/auth/login: a legacy controller 404s it, and the JSON /api/login
	// is what selects the unprefixed paths.
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != identifyGoodUser || body["password"] != identifyGoodPass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{
			{"name": "lobby-ap", "ip": "192.0.2.21", "mac": "aa:bb:cc:00:00:21", "model": "U6LR", "type": "uap", "serial": "AP-SERIAL-21", "version": "6.6.55"},
			{"name": "core-switch", "ip": "192.0.2.22", "mac": "aa:bb:cc:00:00:22", "model": "USW48", "type": "usw", "serial": "SW-SERIAL-22", "version": "6.6.55"},
		})
	})
	mux.HandleFunc("/api/s/default/list/setting", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{{"key": "super_identity", "name": "hq-controller"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := NewRegistry().Identify(context.Background(),
		DeviceInfo{DeviceType: "unifi", ManagementURL: srv.URL},
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Hostname != "hq-controller" {
		t.Errorf("hostname = %q, want the controller's own name", got.Hostname)
	}
	if got.SerialNumber != "" || got.Model != "" || got.IPAddress != "" || got.MACAddress != "" {
		t.Fatalf("a managed device's identity was put on the controller: %+v ip=%q mac=%q", got.DeviceIdentity, got.IPAddress, got.MACAddress)
	}
}

// An address the operator typed a credential into is quoted back without it —
// in the error Identify returns, which a caller logs ( review NB-2).
func TestRegistryIdentify_RejectedAddressNeverQuotesItsCredentials(t *testing.T) {
	const secret = "hunter2-secret"
	for _, tc := range []struct{ deviceType, address string }{
		{"fortinet", "https://admin:" + secret + "@192.0.2.10"},
		{"fortinet", "https://192.0.2.10/?token=" + secret},
		{"fortinet", "https://admin:" + secret + "@192.0.2.10/%zz"},
		{"cisco", "ssh://admin:" + secret + "@192.0.2.10"},
		{"cisco", "admin:" + secret + "@192.0.2.10:22"},
		{"cisco", "ssh://admin:" + secret + "@192.0.2.10/%zz"},
	} {
		_, err := NewRegistry().Identify(context.Background(),
			DeviceInfo{DeviceType: tc.deviceType, ManagementURL: tc.address},
			Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
		assertIdentifyCode(t, err, IdentifyInvalidTarget)
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s %s: the error quotes the credential: %v", tc.deviceType, tc.address, err)
		}
	}
}

func TestDisplayAddress(t *testing.T) {
	for in, want := range map[string]string{
		"https://192.0.2.10:8443/api":           "https://192.0.2.10:8443/api",
		"https://admin:secret@192.0.2.10":       "https://[redacted]@192.0.2.10",
		"https://admin:pa/ss?w#rd@192.0.2.10/x": "https://[redacted]@192.0.2.10/x",
		"https://192.0.2.10/?token=secret":      "https://192.0.2.10/",
		"https://192.0.2.10/#frag":              "https://192.0.2.10/",
		"admin:secret@192.0.2.10:22":            "[redacted]@192.0.2.10:22",
		"  ssh://root:toor@192.0.2.10  ":        "ssh://[redacted]@192.0.2.10",
	} {
		if got := DisplayAddress(in); got != want {
			t.Errorf("DisplayAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
