package processor

// The Inventory → 3rd Party lens showed bare IP:port rows
// (e.g. "40.84.85.40:443") for third-party TLS connections the sensor's
// passive capture had already tied to a name — the ClientHello's SNI
// (e.g. "settings-win.data.microsoft.com") — because the only hostname
// fallback here was reverse DNS, and most cloud/CDN addresses have no PTR
// record. Where a PTR record DOES exist, it is often a worse name than the
// SNI: an internal load-balancer alias (e.g. "lax31s06-in-f14.1e100.net")
// rather than the name the client actually asked for.
//
// The fix reorders the fallback: hostname reported by the sensor -> SNI
// captured off the wire -> reverse DNS. The SNI is a measured fact about the
// connection; a PTR answer is hearsay about the address from a third party.
//
// sniHostnameFromDiscoveryMetadata and resolveMissingHostname are pure
// functions (no DB, no network) precisely so this ordering can be pinned
// without a live resolver.

import "testing"

func TestSniHostnameFromDiscoveryMetadata(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "sensor-manager envelope: sni lives under nested raw_metadata",
			raw:  `{"version":"TLS 1.3","raw_metadata":{"sni":"settings-win.data.microsoft.com"}}`,
			want: "settings-win.data.microsoft.com",
		},
		{
			name: "sni_server_name spelling (STARTTLS sessions) is also read",
			raw:  `{"raw_metadata":{"sni_server_name":"smtp.example.com"}}`,
			want: "smtp.example.com",
		},
		{
			name: "sni wins over sni_server_name when both are nested",
			raw:  `{"raw_metadata":{"sni":"canonical.example.com","sni_server_name":"canonical.example.com"}}`,
			want: "canonical.example.com",
		},
		{
			name: "pcap-processor shape: no envelope, sni at the top level",
			raw:  `{"sni":"flat.example.com","cipher_suite":"TLS_AES_128_GCM_SHA256"}`,
			want: "flat.example.com",
		},
		{
			name: "mixed case is lower-cased",
			raw:  `{"raw_metadata":{"sni":"API.Example.COM"}}`,
			want: "api.example.com",
		},
		{
			name: "an IPv4 literal in the SNI field is not a hostname",
			raw:  `{"raw_metadata":{"sni":"40.84.85.40"}}`,
			want: "",
		},
		{
			name: "empty nested sni falls through to sni_server_name",
			raw:  `{"raw_metadata":{"sni":"","sni_server_name":"fallback.example.com"}}`,
			want: "fallback.example.com",
		},
		{
			name: "no sni anywhere",
			raw:  `{"raw_metadata":{"cipher_suite":"TLS_AES_128_GCM_SHA256"}}`,
			want: "",
		},
		{
			name: "empty metadata",
			raw:  ``,
			want: "",
		},
		{
			name: "not JSON",
			raw:  `not json`,
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sniHostnameFromDiscoveryMetadata([]byte(tc.raw)); got != tc.want {
				t.Errorf("sniHostnameFromDiscoveryMetadata(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestResolveMissingHostname_SNIBeatsReverseDNS pins the ordering: when the
// discovery carries a usable SNI, the injected PTR lookup must not even be
// consulted — reverse DNS is a fallback, not a competitor.
func TestResolveMissingHostname_SNIBeatsReverseDNS(t *testing.T) {
	lookupCalled := false
	lookupPTR := func(ip string) string {
		lookupCalled = true
		return "lax31s06-in-f14.1e100.net" // the worse, PTR-derived name
	}

	metadata := []byte(`{"raw_metadata":{"sni":"settings-win.data.microsoft.com"}}`)
	got := resolveMissingHostname(metadata, "203.0.113.40", lookupPTR)

	if got != "settings-win.data.microsoft.com" {
		t.Errorf("resolveMissingHostname = %q, want the SNI", got)
	}
	if lookupCalled {
		t.Errorf("reverse DNS was consulted even though the SNI already resolved the hostname")
	}
}

// TestResolveMissingHostname_FallsBackToReverseDNSWhenNoSNI pins the other
// half: the reverse-DNS fallback must still fire for discoveries that never
// carried an SNI (non-TLS protocols, or a TLS session where the ClientHello
// was not captured).
func TestResolveMissingHostname_FallsBackToReverseDNSWhenNoSNI(t *testing.T) {
	lookupCalled := false
	lookupPTR := func(ip string) string {
		lookupCalled = true
		if ip == "203.0.113.41" {
			return "ptr.example.net"
		}
		return ""
	}

	metadata := []byte(`{"raw_metadata":{"cipher_suite":"TLS_AES_128_GCM_SHA256"}}`)
	got := resolveMissingHostname(metadata, "203.0.113.41", lookupPTR)

	if !lookupCalled {
		t.Fatalf("reverse DNS was never consulted despite no SNI being present")
	}
	if got != "ptr.example.net" {
		t.Errorf("resolveMissingHostname = %q, want the PTR result", got)
	}
}

// TestResolveMissingHostname_IPLiteralSNIFallsBackToReverseDNS pins that an
// SNI value which is not a usable DNS name (an IP literal, RFC 6066 forbids
// this but a malformed ClientHello could still carry one) is treated the same
// as "no SNI" rather than being written verbatim.
func TestResolveMissingHostname_IPLiteralSNIFallsBackToReverseDNS(t *testing.T) {
	lookupPTR := func(ip string) string { return "ptr.example.net" }

	metadata := []byte(`{"raw_metadata":{"sni":"203.0.113.41"}}`)
	got := resolveMissingHostname(metadata, "203.0.113.41", lookupPTR)

	if got != "ptr.example.net" {
		t.Errorf("resolveMissingHostname = %q, want the reverse-DNS fallback (SNI was an IP literal)", got)
	}
}

// A PTR lookup from inside the cluster is only meaningful evidence for a
// PUBLIC destination address. For a private/LAN address the cluster's own
// resolver is the wrong vantage point (usually unreachable for that address,
// or answering a different network's idea of it) and is weaker evidence than
// the sensor's own passive mDNS/NBNS/LLDP observations besides — so the
// lookup must never even be attempted for one. Both polarities are pinned:
// a public address is still looked up (the existing behavior must survive),
// and a private one is not.
//
// Mutation that proves it: delete the `if !isPublicAddress(destIP)` guard in
// resolveMissingHostname — the private-address subtests go red (lookupPTR
// gets called for an RFC 1918 address).
func TestResolveMissingHostname_OnlyLooksUpPublicAddresses(t *testing.T) {
	metadata := []byte(`{"raw_metadata":{"cipher_suite":"TLS_AES_128_GCM_SHA256"}}`) // no SNI

	tests := []struct {
		name       string
		destIP     string
		wantLookup bool
	}{
		{"RFC 1918 private (10.x)", "10.0.0.5", false},
		{"RFC 1918 private (192.168.x)", "192.168.1.20", false},
		{"RFC 1918 private (172.16-31.x)", "172.20.0.9", false},
		{"RFC 4193 unique local (fd00::/8)", "fd12:3456:789a::1", false},
		{"link-local", "169.254.1.1", false},
		{"loopback", "127.0.0.1", false},
		{"carrier-grade NAT (RFC 6598, 100.64.0.0/10)", "100.64.0.1", false},
		{"unspecified", "0.0.0.0", false},
		{"genuinely public", "203.0.113.41", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			lookupPTR := func(ip string) string {
				called = true
				return "ptr.example.net"
			}

			got := resolveMissingHostname(metadata, tc.destIP, lookupPTR)

			if called != tc.wantLookup {
				t.Fatalf("%s: reverse DNS called=%v, want %v", tc.destIP, called, tc.wantLookup)
			}
			if tc.wantLookup && got != "ptr.example.net" {
				t.Errorf("%s: resolveMissingHostname = %q, want the PTR result", tc.destIP, got)
			}
			if !tc.wantLookup && got != "" {
				t.Errorf("%s: resolveMissingHostname = %q, want empty (no lookup, no fabricated name)", tc.destIP, got)
			}
		})
	}
}

func TestIsPublicAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"203.0.113.41", true}, // TEST-NET-3, publicly routable documentation range
		{"8.8.8.8", true},
		{"2001:db8::1", true}, // publicly routable documentation range (IPv6)
		{"10.1.2.3", false},
		{"172.16.5.5", false},
		{"192.168.0.1", false},
		{"fd00::1", false},
		{"100.64.5.5", false}, // carrier-grade NAT
		{"169.254.0.1", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			if got := isPublicAddress(tc.addr); got != tc.want {
				t.Errorf("isPublicAddress(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}
