package api

import (
	"net/http"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

// http.ProxyFromEnvironment caches the environment for the life of the
// process, so this asserts the transport is proxy-aware (non-nil Proxy); the
// behaviour of the function itself is covered in shared/httpclient.
//
// After enrolment every sensor transport is an mTLS transport. Each must still
// honour HTTPS_PROXY, or the sensor goes dark behind a corporate proxy the
// moment it registers.
func assertUsesProxyEnvironment(t *testing.T, name string, rt http.RoundTripper) {
	t.Helper()
	tr, ok := rt.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("%s: transport is %T, want *http.Transport", name, rt)
	}
	if tr.Proxy == nil {
		t.Fatalf("%s: transport has nil Proxy; HTTPS_PROXY is ignored", name)
	}
}

func TestMTLSTransportsHonourProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	certPEM, keyPEM := selfSignedPEM(t)
	newCfg := func() *config.Config {
		return &config.Config{
			ControlPlaneURL: "https://cp.example.test",
			Security:        config.SecurityConfig{UseTLS: true, ClientCert: certPEM, ClientKey: keyPEM, ServerCACert: certPEM},
		}
	}

	t.Run("outbound client at construction", func(t *testing.T) {
		assertUsesProxyEnvironment(t, "NewOutboundClient", NewOutboundClient(newCfg()).httpClient.Transport)
	})
	t.Run("outbound client after ActivateMTLS", func(t *testing.T) {
		cfg := &config.Config{ControlPlaneURL: "https://cp.example.test"}
		c := NewOutboundClient(cfg)
		cfg.Security = newCfg().Security
		c.ActivateMTLS()
		assertUsesProxyEnvironment(t, "ActivateMTLS", c.httpClient.Transport)
	})
	t.Run("sensor manager at construction", func(t *testing.T) {
		assertUsesProxyEnvironment(t, "NewSensorManagerClient", NewSensorManagerClient(newCfg()).httpClient.Transport)
	})
	t.Run("sensor manager after rotation", func(t *testing.T) {
		c := NewSensorManagerClient(newCfg())
		c.httpClient.Transport = &http.Transport{} // as if built without proxy support
		if err := c.reconfigureTLS(); err != nil {
			t.Fatal(err)
		}
		assertUsesProxyEnvironment(t, "SensorManagerClient.reconfigureTLS", c.httpClient.Transport)
	})
}
