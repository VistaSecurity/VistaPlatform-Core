package hostobs

import (
	"slices"
	"strings"
	"testing"
)

// allKinds is every decoder this package dispatches to. Adding a Kind without
// adding it here fails TestDecodeCoversEveryKind, which is the point: a kind
// wired into the classifier but not the decode switch is a decoder that never
// runs, and a kind with no BPF term is one that never receives a frame.
var allKinds = []Kind{
	KindARP, KindDHCP, KindMDNS, KindNBNS, KindDNS, KindLLDP, KindCDP,
}

func TestClassifyEther(t *testing.T) {
	cases := []struct {
		name      string
		etherType uint16
		payload   []byte
		want      Kind
	}{
		{"ARP", EtherTypeARP, []byte{0x00, 0x01}, KindARP},
		{"LLDP", EtherTypeLLDP, []byte{0x02, 0x07}, KindLLDP},
		{"IPv4 is not ours", 0x0800, []byte{0x45, 0x00}, KindNone},
		{"IPv6 is not ours", 0x86dd, []byte{0x60, 0x00}, KindNone},
		{
			name: "802.3 with a CDP SNAP header",
			// A length below 1500, so the payload starts with LLC/SNAP.
			etherType: 64,
			payload:   append([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}, 0x02, 0xb4, 0x00, 0x00),
			want:      KindCDP,
		},
		{
			name:      "802.3 with a non-Cisco SNAP header",
			etherType: 64,
			payload:   []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45},
			want:      KindNone,
		},
		{"802.3 with an STP LLC header", 38, []byte{0x42, 0x42, 0x03, 0x00}, KindNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, body := ClassifyEther(tc.etherType, tc.payload)
			if got != tc.want {
				t.Fatalf("ClassifyEther = %v, want %v", got, tc.want)
			}
			if tc.want != KindNone && len(body) == 0 {
				t.Error("classified but returned an empty payload")
			}
		})
	}
}

func TestClassifyUDP(t *testing.T) {
	cases := []struct {
		src, dst uint16
		want     Kind
	}{
		{68, 67, KindDHCP}, // client → server
		{67, 68, KindDHCP}, // server → client, the OFFER/ACK direction
		{5353, 5353, KindMDNS},
		{137, 137, KindNBNS},
		{53, 40000, KindDNS}, // the answer direction
		{40000, 53, KindDNS},
		{443, 40000, KindNone}, // QUIC: a crypto path, not ours
		{0, 0, KindNone},
	}
	for _, tc := range cases {
		if got := ClassifyUDP(tc.src, tc.dst); got != tc.want {
			t.Errorf("ClassifyUDP(%d, %d) = %v, want %v", tc.src, tc.dst, got, tc.want)
		}
	}
}

func TestDecodeCoversEveryKind(t *testing.T) {
	// Decode must route every kind to a real decoder. A kind that falls through
	// to the default returns ErrNotApplicable for every frame, which is
	// indistinguishable from a quiet network — the failure mode that has
	// already cost this codebase two fixes for the same bug.
	for _, k := range allKinds {
		t.Run(k.String(), func(t *testing.T) {
			// Empty input: a real decoder rejects it as malformed or
			// inapplicable, which is enough to prove it was reached. What must
			// NOT happen is a panic or a nil-decoder silence.
			_, err := Decode(k, Frame{Payload: nil})
			if err == nil {
				t.Fatalf("Decode(%v) accepted an empty frame", k)
			}
		})
	}
	if _, err := Decode(KindNone, Frame{}); err == nil {
		t.Error("Decode(KindNone) returned no error")
	}
}

func TestKindStringsAreSourceValues(t *testing.T) {
	// Kind.String feeds metrics and logs; it has to agree with the Source value
	// the observation itself carries, or an operator correlating the two gets
	// two vocabularies for one thing.
	want := map[Kind]string{
		KindARP: SourceARP, KindDHCP: SourceDHCP, KindMDNS: SourceMDNS,
		KindNBNS: SourceNBNS, KindDNS: SourceDNS, KindLLDP: SourceLLDP,
		KindCDP: SourceCDP,
	}
	for k, w := range want {
		if got := k.String(); got != w {
			t.Errorf("Kind(%d).String() = %q, want %q", k, got, w)
		}
	}
}

func TestBPFTermsCoverEveryKind(t *testing.T) {
	// Every ENABLED decoder needs a filter term, or the live sensor runs it
	// against frames that never arrive. Checked with every decoder on, so the
	// coverage assertion measures the term list rather than the default set.
	filter := strings.Join(BPFTerms(Config{DNS: true}), " or ")
	need := map[Kind]string{
		KindARP:  "arp",
		KindDHCP: "udp port 67",
		KindMDNS: "udp port 5353",
		KindNBNS: "udp port 137",
		KindDNS:  "udp port 53",
		KindLLDP: "ether proto 0x88cc",
		KindCDP:  "01:00:0c:cc:cc:cc",
	}
	for _, k := range allKinds {
		term, ok := need[k]
		if !ok {
			t.Errorf("kind %v has no expected BPF term in this test", k)
			continue
		}
		if !strings.Contains(filter, term) {
			t.Errorf("BPFTerms is missing the term for %v (%q): %s", k, term, filter)
		}
	}
	// DHCP travels in both directions and needs both ports.
	if !strings.Contains(filter, "udp port 68") {
		t.Errorf("BPFTerms omits the DHCP client port, so client→server messages never arrive: %s", filter)
	}
}

// TestDNSIsOptIn pins the decision that the unicast-DNS decoder is off unless
// somebody turned it on.
//
// Both halves matter and neither is sufficient. The filter half is what keeps
// UDP 53 from reaching the worker pool at all on a busy segment; the Enabled
// half is what stops the decoder running if the packets arrive anyway — from a
// pcap file, from an operator-widened filter, from a future caller. A change
// that dropped either one would leave the other looking like the feature still
// worked.
func TestDNSIsOptIn(t *testing.T) {
	var off Config // the zero value is the default set

	if off.Enabled(KindDNS) {
		t.Error("DNS is enabled in the zero Config; it must be opt-in")
	}
	// Compared term by term, not against the joined string: "udp port 53" is a
	// substring of "udp port 5353", so a Contains check here would pass on the
	// mDNS term and never be able to fail.
	for _, term := range BPFTerms(off) {
		if term == "udp port 53" {
			t.Errorf("the default capture filter asks for UDP 53: %v", BPFTerms(off))
		}
	}

	on := Config{DNS: true}
	if !on.Enabled(KindDNS) {
		t.Error("Config{DNS: true} did not enable the DNS decoder")
	}
	if !slices.Contains(BPFTerms(on), "udp port 53") {
		t.Errorf("the opt-in capture filter omits UDP 53: %v", BPFTerms(on))
	}

	// Nothing else moves. mDNS in particular stays on: a multicast
	// announcement is a device advertising itself, not a lookup somebody
	// performed, and conflating the two would switch off the richest passive
	// identity source on a modern LAN.
	for _, k := range allKinds {
		if k == KindDNS {
			continue
		}
		if !off.Enabled(k) {
			t.Errorf("%v is disabled by default; only DNS may be", k)
		}
	}
	if off.Enabled(KindNone) {
		t.Error("KindNone reported as enabled")
	}

	defaultFilter := strings.Join(BPFTerms(off), " or ")
	for _, term := range []string{"arp", "udp port 67", "udp port 68", "udp port 5353", "udp port 137", "ether proto 0x88cc"} {
		if !strings.Contains(defaultFilter, term) {
			t.Errorf("the default filter lost %q: %s", term, defaultFilter)
		}
	}
}
