package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// CodeQL flags the three s.httpClient.Do calls in device_discovery_service.go
// (lines 109/146/233) as go/request-forgery, because managementURL arrives
// straight from the POST /devices/discover-and-create request body. They are
// false positives ONLY because NewDeviceDiscoveryService installs
// network.SafeDialContext as the transport's DialContext, which refuses
// loopback / RFC1918 / link-local / cloud-metadata addresses in the
// net.Dialer.Control hook — after DNS resolution, on the concrete IP.
//
// That mitigation is invisible to the scanner and equally invisible to a future
// reader refactoring the constructor. Delete the DialContext line and the three
// alerts become true positives with nothing failing to say so. This test is the
// thing that says so.
//
// It asserts the strong property, not merely that an error came back: the
// target server must receive ZERO requests, proving the guard fires before the
// connection rather than after a response was already fetched.
func TestDiscoverDeviceRefusesInternalTarget(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// httptest binds 127.0.0.1, which isPrivateIP treats as internal — the same
	// verdict it reaches for a 192.168.x.x appliance.
	svc := NewDeviceDiscoveryService()
	_, err := svc.DiscoverDevice("unifi", srv.URL, "admin", "hunter2")

	if err == nil {
		t.Fatalf("DiscoverDevice(%q) succeeded; the SSRF dial guard did not fire. "+
			"Has DialContext: network.SafeDialContext been removed from "+
			"NewDeviceDiscoveryService? CodeQL alerts 20/21/22 depend on it.", srv.URL)
	}
	if !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("DiscoverDevice(%q) failed with %v, want an 'ssrf guard' rejection. "+
			"A different error means the request was attempted and failed for some "+
			"other reason, so the guard is no longer covering this sink.", srv.URL, err)
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("target server received %d request(s); the guard must refuse the "+
			"connection before any request reaches the target", got)
	}
}

// The same guard applied to the constructor's client, asserted directly. This
// pins the wiring even if DiscoverDevice's vendor dispatch changes shape.
func TestDeviceDiscoveryClientRefusesInternalTarget(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	svc := NewDeviceDiscoveryService()
	resp, err := svc.httpClient.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("httpClient reached a loopback server; SafeDialContext is not installed on the transport")
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("loopback server received %d request(s), want 0", got)
	}
}

// Documents the OTHER half of the finding, and the reason this file is not a
// clean bill of health: the guard is a blanket private-IP denylist, so the
// operator-facing "auto-discover a device" flow cannot reach an appliance on
// the customer's own LAN — which is where essentially every F5, UniFi, Palo
// Alto and Fortinet management interface lives.
//
// Ongoing interrogation of an ALREADY-CREATED device does not go through this
// client (it runs via shared/deviceinterrogation, which has no dial guard), so
// this is a bootstrap-path-only regression, not a total product outage.
//
// Deliberately a characterization test: it pins today's behaviour so the
// tradeoff is visible and any future change to it is a conscious one. Whether
// the denylist should stay is an owner decision, not a local patch.
func TestDiscoverDeviceCannotReachRFC1918Appliance(t *testing.T) {
	svc := NewDeviceDiscoveryService()

	// One address from each RFC1918 block, plus the cloud-metadata address.
	//
	// These are chosen to be inert if the guard REGRESSES, not merely while it
	// works. The distinction matters: a previous version of this test used
	// 192.168.1.1 with credentials "admin"/"hunter2" and called them safe
	// because "nothing is dialled" — which is only true for as long as the test
	// passes. Removing the guard makes it dial for real, and the CI runners sit
	// on 192.168.2.x / 192.168.99.x, so a regression would have sprayed
	// plausible credentials at whatever answered on the lab LAN and hung the
	// job for minutes per address. The test would have been most dangerous at
	// exactly the moment it was most needed.
	//
	// So: top-of-block host addresses that are valid RFC1918 (the guard must
	// still match them) but are not the addresses anything is conventionally
	// assigned, and a credential pair that is self-evidently not a secret.
	for _, target := range []string{
		"https://10.255.255.1",    // RFC1918 10/8
		"https://172.31.255.254",  // RFC1918 172.16/12
		"https://192.168.255.254", // RFC1918 192.168/16
		"https://169.254.169.254", // cloud metadata — this one SHOULD be refused
	} {
		_, err := svc.DiscoverDevice("unifi", target, "ssrf-guard-probe", "not-a-real-credential")
		if err == nil {
			t.Errorf("DiscoverDevice(%q) unexpectedly succeeded", target)
			continue
		}
		if !strings.Contains(err.Error(), "ssrf guard") {
			t.Errorf("DiscoverDevice(%q) failed with %v, want an 'ssrf guard' rejection", target, err)
		}
	}
}
