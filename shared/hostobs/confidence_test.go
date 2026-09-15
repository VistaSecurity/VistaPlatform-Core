package hostobs

import "testing"

// The ladder is the one thing the sensor and pcap-processor must agree on, so
// it is pinned by value rather than only by ordering: pcap-processor used to
// write a flat 0.85 and the drift was invisible precisely because nothing
// asserted a number.
func TestConfidenceLadder(t *testing.T) {
	cases := []struct {
		name    string
		sources []string
		want    float64
	}{
		{"lldp", []string{SourceLLDP}, 0.95},
		{"cdp", []string{SourceCDP}, 0.95},
		{"dhcp", []string{SourceDHCP}, 0.95},
		{"arp", []string{SourceARP}, 0.85},
		{"nbns", []string{SourceNBNS}, 0.85},
		{"mdns", []string{SourceMDNS}, 0.80},
		{"dns", []string{SourceDNS}, 0.60},
		// The strongest contributing source wins: a host seen over ARP and then
		// over DHCP is graded on the DHCP exchange.
		{"best of several", []string{SourceARP, SourceDHCP, SourceMDNS}, 0.95},
		{"dns and mdns", []string{SourceDNS, SourceMDNS}, 0.80},
		// The floor, not zero. Zero on this scale means NOT ASSESSED, and a
		// decoded frame has been assessed.
		{"unrecognised", []string{"smoke-signal"}, 0.60},
		{"no sources at all", nil, 0.60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &HostObservation{Sources: tc.sources}
			if got := Confidence(o); got != tc.want {
				t.Errorf("Confidence(%v) = %v, want %v", tc.sources, got, tc.want)
			}
		})
	}
}

// A freshly-decoded observation carries Source and not Sources — Finalize is
// what fills the second. Grading must not depend on which half of the pair the
// caller happens to be holding.
func TestConfidenceReadsSourceBeforeFinalize(t *testing.T) {
	o := &HostObservation{Source: SourceLLDP, MAC: "00:1a:2f:11:22:33"}
	if got := Confidence(o); got != 0.95 {
		t.Errorf("Confidence before Finalize = %v, want 0.95", got)
	}
	o.Finalize()
	if got := Confidence(o); got != 0.95 {
		t.Errorf("Confidence after Finalize = %v, want 0.95", got)
	}
}

// Nil is the one input that grades zero, because nothing was assessed.
func TestConfidenceNilIsNotAssessed(t *testing.T) {
	if got := Confidence(nil); got != 0 {
		t.Errorf("Confidence(nil) = %v, want 0 (NOT ASSESSED)", got)
	}
}
