package network

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The private-endpoint opt-in lifts exactly one half of the SSRF guard. These
// tests pin BOTH polarities, because an opt-in that quietly lifted the other
// half would look identical from the outside — and the other half is the one
// that protects our own cluster.

func TestIsNeverReachable(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
		why  string
	}{
		{"127.0.0.1", true, "loopback"},
		{"127.0.0.53", true, "loopback resolver"},
		{"::1", true, "v6 loopback"},
		{"0.0.0.0", true, "unspecified"},
		{"169.254.169.254", true, "AWS/GCP/Azure metadata"},
		{"169.254.1.1", true, "link-local"},
		{"fe80::1", true, "v6 link-local"},
		{"224.0.0.1", true, "multicast"},
		{"10.0.0.5", false, "RFC1918 — negotiable, not never"},
		{"192.168.1.10", false, "RFC1918"},
		{"172.16.4.4", false, "RFC1918"},
		{"100.64.0.1", false, "CGNAT — private, but not never-reachable"},
		{"fd00::1", false, "ULA"},
		{"93.184.216.34", false, "public"},
	} {
		if got := IsNeverReachable(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsNeverReachable(%s) = %v, want %v (%s)", tc.ip, got, tc.want, tc.why)
		}
	}
	if !IsNeverReachable(nil) {
		t.Error("a nil IP must be refused, not permitted")
	}
}

// isPrivateIP — what the DEFAULT guard uses — must still refuse everything it
// refused before the split, RFC1918 included.
func TestDefaultGuardStillRefusesRFC1918(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "192.168.1.1", "172.20.0.1", "fd00::1", "127.0.0.1", "169.254.169.254"} {
		if !isPrivateIP(net.ParseIP(ip)) {
			t.Errorf("isPrivateIP(%s) = false; the default guard must still refuse it", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "93.184.216.34", "2606:4700::1111"} {
		if isPrivateIP(net.ParseIP(ip)) {
			t.Errorf("isPrivateIP(%s) = true; a public address must stay reachable", ip)
		}
	}
}

// The opt-in client must still refuse loopback. This is the assertion that
// makes the opt-in narrow rather than a blanket disable — mutate
// onPremDialGuard to `return nil` and this is what goes red.
func TestSafeHTTPClientAllowingPrivate_StillRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := SafeHTTPClientAllowingPrivate(2 * time.Second).Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the private-endpoint opt-in reached a loopback server; loopback is never reachable")
	}
	if !strings.Contains(err.Error(), "never reachable") {
		t.Errorf("error does not say why: %v", err)
	}
}

// And the metadata endpoint, which is the address an SSRF is usually after.
func TestSafeHTTPClientAllowingPrivate_RefusesCloudMetadata(t *testing.T) {
	// No server: the guard must refuse before any connection is attempted, so
	// a refusal here is the guard and not a timeout. A 1s timeout keeps the
	// test fast if the guard were removed.
	resp, err := SafeHTTPClientAllowingPrivate(time.Second).Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the private-endpoint opt-in reached the cloud metadata endpoint")
	}
	if !strings.Contains(err.Error(), "never reachable") {
		t.Errorf("metadata refusal came from something other than the guard: %v", err)
	}
}

// The opt-in must actually opt in — a guard that refuses everything would pass
// the two tests above while making the connector useless, which is the
// over-strict polarity of the same bug.
func TestOnPremGuardPermitsRFC1918(t *testing.T) {
	for _, addr := range []string{"10.0.0.5:443", "192.168.1.10:8000", "172.16.9.9:80", "[fd00::1]:443"} {
		if err := onPremDialGuard("tcp", addr, nil); err != nil {
			t.Errorf("onPremDialGuard(%s) refused a private target the opt-in exists to allow: %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:443", "169.254.169.254:80", "[::1]:443", "0.0.0.0:80"} {
		if err := onPremDialGuard("tcp", addr, nil); err == nil {
			t.Errorf("onPremDialGuard(%s) permitted an address that is never reachable", addr)
		}
	}
	// A public address is still fine: a hosted NetBox behind a real hostname
	// is a legitimate configuration.
	if err := onPremDialGuard("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("onPremDialGuard refused a public target: %v", err)
	}
}

func TestIsPrivateReachableWithOptIn(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"10.0.0.5", true},
		{"192.168.50.4", true},
		{"fd00::1", true},
		{"127.0.0.1", false}, // never reachable, not "private with opt-in"
		{"169.254.169.254", false},
		{"93.184.216.34", false}, // public
		{"not an ip and not resolvable.invalid", false},
	} {
		if got := IsPrivateReachableWithOptIn(tc.host); got != tc.want {
			t.Errorf("IsPrivateReachableWithOptIn(%s) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
