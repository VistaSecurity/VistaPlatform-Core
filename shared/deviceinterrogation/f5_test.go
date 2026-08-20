package deviceinterrogation

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestF5CertName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/Common/default.crt", "~Common~default.crt"},
		{"default.crt", "default.crt"},
		{"/Common/Partition/cert.crt", "~Common~Partition~cert.crt"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := f5CertName(tc.in); got != tc.want {
			t.Errorf("f5CertName(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestF5ParseDestination covers the `destination` forms iControl actually
// returns. Every non-empty IP this yields MUST survive a Postgres ::inet cast:
// it lands in discovery_findings.resolved_ip and in the $6::inet bind of
// writeSensorDiscovery, and a failed cast discards the finding while the device
// page still reports a successful interrogation.
func TestF5ParseDestination(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantIP   string
		wantPort int
	}{
		{"common partition ipv4", "/Common/198.51.100.10:443", "198.51.100.10", 443},
		{"non-common partition", "/Prod-Partition/203.0.113.25:8443", "203.0.113.25", 8443},
		{"nested folder", "/Common/apps/198.51.100.11:443", "198.51.100.11", 443},
		{"ipv6 uses dot as port separator", "/Common/2001:db8::1.443", "2001:db8::1", 443},
		{"ipv6 in another partition", "/DMZ/2001:db8:abcd::25.8443", "2001:db8:abcd::25", 8443},
		{"ipv6 without a port", "/Common/2001:db8::1", "2001:db8::1", 0},
		{"ipv4 route domain", "/Common/198.51.100.10%2:443", "198.51.100.10", 443},
		{"ipv6 route domain", "/Common/2001:db8::1%3.443", "2001:db8::1", 443},
		{"no partition prefix", "198.51.100.10:443", "198.51.100.10", 443},
		{"wildcard address and port", "/Common/0.0.0.0:0", "0.0.0.0", 0},
		{"non-numeric port", "/Common/198.51.100.10:any", "198.51.100.10", 0},
		{"ipv4-mapped ipv6 without port", "/Common/::ffff:198.51.100.10", "::ffff:198.51.100.10", 0},
		{"named virtual-address is not an IP", "/Common/vip-web-prod:443", "", 443},
		{"empty", "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotIP, gotPort := f5ParseDestination(tc.in)
			if gotIP != tc.wantIP || gotPort != tc.wantPort {
				t.Fatalf("f5ParseDestination(%q) = (%q, %d); want (%q, %d)",
					tc.in, gotIP, gotPort, tc.wantIP, tc.wantPort)
			}
			// The contract the inet columns depend on: an address is returned
			// only when it is a real IP literal.
			if gotIP != "" && net.ParseIP(gotIP) == nil {
				t.Fatalf("f5ParseDestination(%q) returned %q, which is not an IP literal and cannot be cast to inet", tc.in, gotIP)
			}
		})
	}
}

// TestF5Interrogate_VIPAddressesAreInetCastable drives the whole VIP→asset path
// against a fake iControl REST endpoint. It pins the two regressions B-13
// covered: the partition prefix reaching CryptoAsset.IPAddress, and IPv6 VIPs
// being dropped outright by the old `len(split(":")) != 2` guard.
func TestF5Interrogate_VIPAddressesAreInetCastable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mgmt/shared/authn/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":{"token":"fake-token"}}`))
	})
	mux.HandleFunc("/mgmt/tm/sys/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":{}}`))
	})
	mux.HandleFunc("/mgmt/tm/ltm/virtual", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"kind":"tm:ltm:virtual:virtualcollectionstate","items":[
			{"name":"vs_web_https","destination":"/Common/198.51.100.10:443","enabled":true,
			 "profiles":[{"name":"clientssl_secure"}]},
			{"name":"vs_web_https_v6","destination":"/Common/2001:db8::1.443","enabled":true,
			 "profiles":[{"name":"clientssl_secure"}]},
			{"name":"vs_partitioned","destination":"/Prod-Partition/203.0.113.25:8443","enabled":true,
			 "profiles":[{"name":"clientssl_secure"}]},
			{"name":"vs_disabled","destination":"/Common/198.51.100.99:443","enabled":false,
			 "profiles":[{"name":"clientssl_secure"}]}
		]}`))
	})
	mux.HandleFunc("/mgmt/tm/ltm/profile/client-ssl", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"kind":"tm:ltm:profile:client-ssl:client-sslcollectionstate","items":[
			{"name":"clientssl_secure","kind":"tm:ltm:profile:client-ssl:client-sslstate",
			 "ciphers":"ECDHE-RSA-AES256-GCM-SHA384","tlsVersion":"1.2"}
		]}`))
	})
	mux.HandleFunc("/mgmt/tm/ltm/profile/server-ssl", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newF5Client(srv.URL, "admin", "admin", "", true)
	result, err := c.interrogate(context.Background())
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}

	byHost := make(map[string]CryptoAsset, len(result.Assets))
	for _, a := range result.Assets {
		byHost[a.Hostname] = a
	}

	want := map[string]struct {
		ip   string
		port int
	}{
		"vs_web_https":    {"198.51.100.10", 443},
		"vs_web_https_v6": {"2001:db8::1", 443},
		"vs_partitioned":  {"203.0.113.25", 8443},
	}
	if len(result.Assets) != len(want) {
		t.Fatalf("expected %d assets (disabled VIP excluded), got %d: %+v", len(want), len(result.Assets), result.Assets)
	}
	for host, exp := range want {
		asset, ok := byHost[host]
		if !ok {
			t.Fatalf("VIP %q produced no asset", host)
		}
		if asset.IPAddress != exp.ip {
			t.Errorf("%s: IPAddress = %q; want %q", host, asset.IPAddress, exp.ip)
		}
		if asset.Port != exp.port {
			t.Errorf("%s: Port = %d; want %d", host, asset.Port, exp.port)
		}
		if net.ParseIP(asset.IPAddress) == nil {
			t.Errorf("%s: IPAddress %q is not an IP literal and would fail the ::inet cast", host, asset.IPAddress)
		}
	}
}
