package services

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// Bootstrap discovery accepts a tenant-supplied management URL. These tests
// pin it to the shared on-prem appliance transport: customer RFC1918 addresses
// are usable, while addresses that can only reach the platform itself are
// rejected after DNS resolution and before an HTTP request is sent.
func TestDiscoverDeviceRefusesLoopbackTarget(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewDeviceDiscoveryService(false)
	_, err := svc.DiscoverDevice("unifi", srv.URL, "test-user", "not-a-secret")
	if err == nil || !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("DiscoverDevice(%q) error = %v, want ssrf guard rejection", srv.URL, err)
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("loopback target received %d request(s), want 0", got)
	}
}

func TestDeviceDiscoveryClientRefusesLoopbackTarget(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := NewDeviceDiscoveryService(false).httpClient.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("httpClient reached loopback; the guarded appliance transport is not installed")
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("loopback server received %d request(s), want 0", got)
	}
}

func TestDiscoveryAddressPolicyAllowsRFC1918ButBlocksMetadata(t *testing.T) {
	if sharednetwork.IsNeverReachable(net.ParseIP("192.168.10.1")) {
		t.Fatal("RFC1918 appliance address must be reachable by the on-prem discovery client")
	}
	if !sharednetwork.IsNeverReachable(net.ParseIP("169.254.169.254")) {
		t.Fatal("cloud metadata address must remain blocked")
	}
}

func TestDeviceDiscoveryTLSVerificationIsExplicit(t *testing.T) {
	verified := NewDeviceDiscoveryService(false).httpClient.Transport.(*http.Transport).TLSClientConfig
	insecure := NewDeviceDiscoveryService(true).httpClient.Transport.(*http.Transport).TLSClientConfig
	if verified == nil || verified.InsecureSkipVerify {
		t.Fatal("default discovery client must verify TLS certificates")
	}
	if insecure == nil || !insecure.InsecureSkipVerify { //nolint:gosec // asserting the explicit operator opt-in
		t.Fatal("explicit TLS override was not applied")
	}
}

func TestDeviceDiscoveryErrorDoesNotExposeResponseBody(t *testing.T) {
	const targetControlledBody = "upstream-secret-diagnostic"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, targetControlledBody, http.StatusUnauthorized)
	}))
	defer srv.Close()

	svc := newDeviceDiscoveryServiceWithClient(srv.Client())
	_, err := svc.DiscoverDevice("unifi", srv.URL, "test-user", "wrong-password")
	if err == nil {
		t.Fatal("discovery unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), targetControlledBody) {
		t.Fatalf("error exposed the target-controlled response body: %v", err)
	}
	var discoveryErr *DeviceDiscoveryError
	if !errors.As(err, &discoveryErr) || discoveryErr.Code != "authentication_failed" {
		t.Fatalf("error = %v, want authentication_failed", err)
	}
}
