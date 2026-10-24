package deviceinterrogation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUnifiManagementInterfaceAsset_Probes verifies the management-interface
// asset is populated from a real TLS handshake (negotiated version, cipher,
// certificate chain) rather than fabricated, using an in-process TLS server.
func TestUnifiManagementInterfaceAsset_Probes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &unifiClient{baseURL: srv.URL, insecureSkipVerify: true}
	asset := c.getManagementInterfaceAsset()

	if asset.ProtocolVersion == nil || *asset.ProtocolVersion == "" {
		t.Fatalf("expected a probed TLS version, got nil/empty")
	}
	if asset.CipherSuite == nil || *asset.CipherSuite == "" {
		t.Errorf("expected a negotiated cipher suite")
	}
	if len(asset.Certificates) == 0 {
		t.Errorf("expected a certificate chain from the probe")
	}
	if asset.Certificate == nil {
		t.Errorf("expected the leaf certificate to be set")
	}
	if asset.Metadata["interface_type"] != "management" {
		t.Errorf("expected interface_type=management marker, got %v", asset.Metadata["interface_type"])
	}
	if asset.Metadata["source"] != "unifi_controller" {
		t.Errorf("expected source=unifi_controller marker, got %v", asset.Metadata["source"])
	}
	if asset.ServiceHints == nil || asset.ServiceHints.ServiceName != "UniFi Controller" {
		t.Errorf("expected UniFi Controller service hint")
	}
}

// TestUnifiManagementInterfaceAsset_ProbeFailureFallback verifies that when the
// probe fails we still inventory the interface but never fabricate crypto.
func TestUnifiManagementInterfaceAsset_ProbeFailureFallback(t *testing.T) {
	// Port 1 is not listening; the handshake must fail.
	c := &unifiClient{baseURL: "https://127.0.0.1:1", insecureSkipVerify: true}
	asset := c.getManagementInterfaceAsset()

	if asset.ProtocolVersion != nil {
		t.Errorf("expected no fabricated protocol version on probe failure, got %q", *asset.ProtocolVersion)
	}
	if asset.CipherSuite != nil {
		t.Errorf("expected no fabricated cipher suite on probe failure")
	}
	if asset.Metadata["interface_type"] != "management" {
		t.Errorf("expected the interface to still be inventoried on probe failure")
	}
	if asset.Port != 1 {
		t.Errorf("expected port 1 from the base URL, got %d", asset.Port)
	}
}

func TestUnifiHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"https://10.0.0.1:8443", "10.0.0.1", 8443},
		{"https://udm.example.com", "udm.example.com", 443},
		{"https://controller:8443", "controller", 8443},
		{"http://host:8080", "host", 8080},
		{"unifi.local", "unifi.local", 443},
	}
	for _, tc := range cases {
		host, port := unifiHostPort(tc.in)
		if host != tc.host || port != tc.port {
			t.Errorf("unifiHostPort(%q) = %q, %d; want %q, %d", tc.in, host, port, tc.host, tc.port)
		}
	}
}

// TestUnifiInterrogate_ClaimsNoTLSItDidNotMeasure is the guard for the
// fabricated TLS:8443 endpoints.
//
// The controller's device list says a device EXISTS; it says nothing about
// what the device listens on. The collector used to turn every managed device
// into a CryptoAsset with Protocol "TLS", Port 8443 — no handshake, whatever
// the device's state — and ingest recorded each as a measured endpoint with a
// crypto configuration whose protocol_version was unmeasured ("partially
// assessed", unscored), so every access point read as having cryptography
// nobody had observed. An emptied Protocol/Port would not fix it either: the
// result processor defaults a missing protocol to TLS and a missing port to
// 443.
//
// So: no asset at a managed device's address, and every TLS asset the
// collector does emit carries a version it negotiated. The devices still
// reach inventory, as subject-bound sightings.
//
// To mutation-test: re-add a per-device CryptoAsset in interrogate() and
// this fails on both assertions.
func TestUnifiInterrogate_ClaimsNoTLSItDidNotMeasure(t *testing.T) {
	devices := []map[string]interface{}{
		{"name": "Living Room AP", "ip": "192.0.2.21", "mac": "78:8a:20:00:00:21", "model": "U6LR",
			"type": "uap", "adopted": true, "state": 1, "x_authkey": poison},
		{"name": "Garage AP", "ip": "192.0.2.22", "mac": "78:8a:20:00:00:22", "model": "U6LR",
			"type": "uap", "adopted": true, "state": 0, "x_authkey": poison},
		{"name": "Office Switch", "ip": "192.0.2.23", "mac": "78:8a:20:00:00:23", "model": "USW24",
			"type": "usw", "adopted": false, "state": 1, "syslog_key": poison},
	}
	srv := newMockUnifiOSControllerWithDevices(t, devices)
	defer srv.Close()

	c := newUnifiClient(srv.URL, "admin", "secret", "", true)
	result, err := c.interrogate(t.Context())
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	assertNoPoison(t, "unifi interrogation", result)

	deviceIPs := map[string]bool{}
	for _, d := range devices {
		deviceIPs[d["ip"].(string)] = true
	}
	sawTLS := false
	for _, a := range result.Assets {
		if deviceIPs[a.IPAddress] {
			t.Errorf("managed device %s was emitted as a crypto asset (%s:%d); the controller's device list measures no listener on it",
				a.IPAddress, a.Protocol, a.Port)
		}
		if p := strings.ToUpper(a.Protocol); p == "TLS" || p == "HTTPS" || p == "" {
			sawTLS = true
			if a.ProtocolVersion == nil || *a.ProtocolVersion == "" {
				t.Errorf("asset %s/%s:%d claims %q with no negotiated version: a TLS listener nothing measured",
					a.Hostname, a.IPAddress, a.Port, a.Protocol)
			}
		}
	}
	if !sawTLS {
		t.Fatal("no TLS asset at all: the controller's probed management interface is missing, so this proves nothing")
	}

	// The devices are not lost: each is the subject of the facts the
	// controller reported about it.
	for ip := range deviceIPs {
		found := false
		for _, f := range result.Facts {
			for _, id := range f.Subject.Identifiers {
				found = found || (id.Kind == IdentifierIPAddress && id.Value == ip)
			}
		}
		if !found {
			t.Errorf("managed device %s is the subject of no fact; it would not reach inventory", ip)
		}
	}
}
