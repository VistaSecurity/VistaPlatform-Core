package services

import (
	"os"
	"strings"
	"testing"
)

// The platform agents ("Platform Discovery Sensor" and "Platform Device
// Interrogation Agent") are reported online by polling each service's /health.
// That poll uses a plain http.Client with no client certificate, so it MUST
// target the plaintext port.
//
// It previously derived the URL from PeerURL(svc, MTLSEnabled()), which becomes
// https://<svc>:8443 under mTLS. 8443 requires a client cert, the handshake
// failed, and the failure was mapped to "offline" — so both agents showed
// permanently offline on every cluster with serviceMtls.enabled, while their
// last_heartbeat kept updating because the same pass writes it either way.
//
// This pins the port, not the plumbing: if someone reintroduces the mTLS-derived
// URL here without also giving the poller a client certificate, this fails.
func TestSystemSensorHealthProbesPlaintextPortUnderMTLS(t *testing.T) {
	t.Setenv("USE_MTLS", "true")

	svc := NewSystemSensorHealthService(nil, "", "")

	for name, got := range map[string]string{
		"cluster-sensor-service":       svc.clusterSensorServiceURL,
		"device-interrogation-service": svc.deviceInterrogationServiceURL,
	} {
		if strings.HasPrefix(got, "https://") || strings.Contains(got, ":8443") {
			t.Errorf("%s health URL is %q; the poller has no client certificate, so an "+
				"mTLS URL makes every probe fail the handshake and report the agent offline", name, got)
		}
		if !strings.Contains(got, ":8080") {
			t.Errorf("%s health URL is %q; want the plaintext :8080 port that exists for probes", name, got)
		}
	}
}

// An explicit override must still win — operators pointing these at a mirror or
// a sidecar should not have the plaintext default forced on them.
func TestSystemSensorHealthRespectsExplicitURLs(t *testing.T) {
	t.Setenv("USE_MTLS", "true")

	svc := NewSystemSensorHealthService(nil, "http://custom-cluster:9999", "http://custom-device:9999")

	if svc.clusterSensorServiceURL != "http://custom-cluster:9999" {
		t.Errorf("explicit cluster URL was overridden: got %q", svc.clusterSensorServiceURL)
	}
	if svc.deviceInterrogationServiceURL != "http://custom-device:9999" {
		t.Errorf("explicit device URL was overridden: got %q", svc.deviceInterrogationServiceURL)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
