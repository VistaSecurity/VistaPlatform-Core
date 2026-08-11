package deviceinterrogation

import (
	"net/http"
	"net/http/httptest"
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
