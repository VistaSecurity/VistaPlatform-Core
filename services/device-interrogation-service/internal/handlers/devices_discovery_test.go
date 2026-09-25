package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// Add device (POST /devices/discover-and-create) and Test connection
// (POST /devices/:id/test-connection) driven through the real handlers against
// fake appliances. The per-vendor 401 case through the REAL router lives in
// internal/api (discovery_routes_test.go); these pin what the handler does with
// a result: what it creates, what it persists, what it reports.

const fakeFortiStatus = `{"status":"success","serial":"FGT60F0000000001","version":"v7.4.4",
 "results":[{"version":"v7.4.4","serial":"FGT60F0000000001","model_name":"FortiGate 60F","hostname":"fw-branch-01"}]}`

// newFakeFortiGate answers system/status for admin/correct-horse and 401 for
// anything else. tls selects a self-signed HTTPS listener.
func newFakeFortiGate(t *testing.T, tls bool) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "correct-horse" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fakeFortiStatus))
	})
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	devicetest.AllowListener(t, srv.Listener.Addr().String())
	return srv
}

func discoverBody(deviceType, url, password string, insecure bool) *strings.Reader {
	body, _ := json.Marshal(map[string]any{
		"device_type": deviceType, "management_url": url, "username": "admin", "password": password,
		"tls_insecure_skip_verify": insecure,
	})
	return strings.NewReader(string(body))
}

func TestContract_DiscoverAndCreate_CreatesTheIdentifiedDevice(t *testing.T) {
	sv := loadSpec(t)
	srv := newFakeFortiGate(t, true)
	store := &stubDeviceStore{created: sampleDevice()}

	w := do(newDeviceEngine(store), http.MethodPost, base+"/devices/discover-and-create",
		discoverBody("fortinet", srv.URL, "correct-horse", true))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Device", w.Body.Bytes())
	if store.createCalls != 1 {
		t.Fatalf("CreateDevice called %d times, want 1", store.createCalls)
	}
	got := store.lastCreate
	for field, pair := range map[string][2]string{
		"vendor":   {derefString(got.Vendor), "Fortinet"},
		"model":    {derefString(got.Model), "FortiGate 60F"},
		"serial":   {derefString(got.SerialNumber), "FGT60F0000000001"},
		"firmware": {derefString(got.FirmwareVersion), "v7.4.4"},
		"hostname": {derefString(got.Hostname), "fw-branch-01"},
		"ip":       {derefString(got.IPAddress), "127.0.0.1"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("created %s = %q, want %q", field, pair[0], pair[1])
		}
	}
	// The probe connected over a self-signed certificate because the operator
	// opted in. The device must be saved with that opt-in, or its first
	// interrogation fails on the certificate discovery just accepted.
	if got.TLSInsecureSkipVerify == nil || !*got.TLSInsecureSkipVerify {
		t.Fatalf("tls_insecure_skip_verify was not persisted on the created device: %v", got.TLSInsecureSkipVerify)
	}
	if got.Metadata["auto_discovered"] != true {
		t.Errorf("auto_discovered not recorded: %v", got.Metadata)
	}
}

// Without the opt-in, a self-signed certificate is its own typed reason, and
// nothing is created.
func TestContract_DiscoverAndCreate_UntrustedCertificate(t *testing.T) {
	sv := loadSpec(t)
	srv := newFakeFortiGate(t, true)
	store := &stubDeviceStore{created: sampleDevice()}

	w := do(newDeviceEngine(store), http.MethodPost, base+"/devices/discover-and-create",
		discoverBody("fortinet", srv.URL, "correct-horse", false))
	assertDiscoveryFailure(t, sv, w, http.StatusBadGateway, "tls_untrusted")
	if store.createCalls != 0 {
		t.Fatalf("a failed probe created a device (%d CreateDevice calls)", store.createCalls)
	}
}

func TestContract_DiscoverAndCreate_WrongPasswordCreatesNothing(t *testing.T) {
	sv := loadSpec(t)
	srv := newFakeFortiGate(t, false)
	store := &stubDeviceStore{created: sampleDevice()}

	w := do(newDeviceEngine(store), http.MethodPost, base+"/devices/discover-and-create",
		discoverBody("fortinet", srv.URL, "wrong", false))
	assertDiscoveryFailure(t, sv, w, http.StatusUnprocessableEntity, "authentication_failed")
	if store.createCalls != 0 {
		t.Fatalf("a failed probe created a device (%d CreateDevice calls)", store.createCalls)
	}
}

// --- Test connection ----------------------------------------------------------

func sealForTest(t *testing.T, masterKey, plain string) string {
	t.Helper()
	cipher, err := credentials.NewCipher("asset_credentials", masterKey, credentials.Policy{Fields: []string{"password"}})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.EncryptValue(plain)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func testConnectionStore(t *testing.T, managementURL string) *stubDeviceStore {
	t.Helper()
	const masterKey = "handler-test-master-key"
	t.Setenv("ENCRYPTION_MASTER_KEY", masterKey)
	device := sampleDevice()
	device.DeviceType = "fortinet"
	return &stubDeviceStore{
		device: device,
		stored: services.StoredDeviceCredentials{
			Username:          "admin",
			EncryptedPassword: sealForTest(t, masterKey, "correct-horse"),
			ManagementURL:     managementURL,
		},
	}
}

func engineWithDiscoveryTimeout(store *stubDeviceStore, timeout time.Duration) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(base)
	grp.Use(func(c *gin.Context) { c.Set("tenantID", deviceTestTenant); c.Next() })
	h := &DeviceHandlers{deviceService: store, discovery: services.NewDeviceDiscoveryService().WithTimeout(timeout)}
	grp.POST("/devices/:id/test-connection", h.TestConnection)
	grp.POST("/devices/discover-and-create", h.DiscoverAndCreateDevice)
	return r
}

// O-02: an address nothing answers on is a failed test with a typed reason —
// not the "success" the stub reported for any device whose status was unknown,
// and no latency, because nothing was measured.
func TestContract_TestConnection_UnreachableIsConnectionFailed(t *testing.T) {
	sv := loadSpec(t)
	store := testConnectionStore(t, "https://192.0.2.1:9") // TEST-NET-1, RFC 5737
	store.device.ConnectionStatus = "unknown"              // what the stub called a pass

	start := time.Now()
	w := do(engineWithDiscoveryTimeout(store, 750*time.Millisecond), http.MethodPost,
		base+"/devices/"+store.device.ID.String()+"/test-connection", strings.NewReader(`{}`))
	assertDiscoveryFailure(t, sv, w, http.StatusBadGateway, "connection_failed")
	if strings.Contains(w.Body.String(), "latency_ms") {
		t.Fatalf("a failed test reported a latency: %s", w.Body.String())
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("test-connection took %s against a 750ms bound", elapsed)
	}
}

func TestContract_TestConnection_ReachesTheDeviceWithStoredCredentials(t *testing.T) {
	sv := loadSpec(t)
	srv := newFakeFortiGate(t, false)
	store := testConnectionStore(t, srv.URL)

	w := do(engineWithDiscoveryTimeout(store, 5*time.Second), http.MethodPost,
		base+"/devices/"+store.device.ID.String()+"/test-connection", strings.NewReader(`{}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DeviceConnectionTestResult", w.Body.Bytes())
	var body struct {
		Success   bool           `json:"success"`
		LatencyMs *int64         `json:"latency_ms"`
		Identity  map[string]any `json:"identity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.LatencyMs == nil || body.Identity["serial_number"] != "FGT60F0000000001" {
		t.Fatalf("unexpected result: %s", w.Body.String())
	}
	if *body.LatencyMs == 42 {
		t.Fatalf("latency is the old hard-coded 42ms")
	}
}

// The stored password is what reaches the device: a wrong one is refused by
// the device, typed, rather than the status the record last held.
func TestContract_TestConnection_RejectedCredentials(t *testing.T) {
	sv := loadSpec(t)
	srv := newFakeFortiGate(t, false)
	store := testConnectionStore(t, srv.URL)
	store.stored.EncryptedPassword = sealForTest(t, "handler-test-master-key", "stale-password")
	store.device.ConnectionStatus = "connected"

	w := do(engineWithDiscoveryTimeout(store, 5*time.Second), http.MethodPost,
		base+"/devices/"+store.device.ID.String()+"/test-connection", strings.NewReader(`{}`))
	assertDiscoveryFailure(t, sv, w, http.StatusUnprocessableEntity, "authentication_failed")
}

func TestContract_TestConnection_NoStoredCredentials(t *testing.T) {
	sv := loadSpec(t)
	store := testConnectionStore(t, "https://192.0.2.1")
	store.stored = services.StoredDeviceCredentials{}

	w := do(engineWithDiscoveryTimeout(store, time.Second), http.MethodPost,
		base+"/devices/"+store.device.ID.String()+"/test-connection", strings.NewReader(`{}`))
	assertDiscoveryFailure(t, sv, w, http.StatusUnprocessableEntity, "credentials_missing")
}

func assertDiscoveryFailure(t *testing.T, sv *specValidator, w *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, wantStatus, w.Body.String())
	}
	sv.assertConforms(t, "DeviceDiscoveryError", w.Body.Bytes())
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != wantCode || body.Message == "" {
		t.Fatalf("error = %q (message %q), want %q", body.Error, body.Message, wantCode)
	}
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
