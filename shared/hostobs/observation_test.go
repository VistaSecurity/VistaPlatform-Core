package hostobs

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/facts"
)

func TestNormalizeMAC(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"00:1A:2F:11:22:33", "00:1a:2f:11:22:33"},
		{"00-1a-2f-11-22-33", "00:1a:2f:11:22:33"},
		{"001a.2f11.2233", "00:1a:2f:11:22:33"},
		{"001a2f112233", "00:1a:2f:11:22:33"},
		// Broadcast and multicast are destinations, never a host's identity.
		{"ff:ff:ff:ff:ff:ff", ""},
		{"01:00:5e:00:00:fb", ""},
		{"33:33:00:00:00:fb", ""},
		{"00:00:00:00:00:00", ""},
		{"", ""},
		{"not a mac", ""},
		{"00:1a:2f:11:22", ""},
		{"00:1a:2f:11:22:33:44", ""},
		{"00:1a:2f:11:22:3", ""},
	}
	for _, tc := range cases {
		if got := NormalizeMAC(tc.in); got != tc.out {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

func TestLocallyAdministeredMACIsFlagged(t *testing.T) {
	// A randomised iOS/Android Wi-Fi MAC. Keying an asset on it creates a new
	// asset every time the device rotates, so the consumer has to be told.
	o := &HostObservation{MAC: "7a:1b:2c:3d:4e:5f", Source: SourceARP}
	o.Finalize()
	if !o.MACLocallyAdministered {
		t.Error("locally-administered MAC was not flagged")
	}
	if o.Vendor != "" {
		t.Errorf("Vendor = %q; a randomised MAC has no manufacturer", o.Vendor)
	}

	u := &HostObservation{MAC: "00:1a:2f:11:22:33", Source: SourceARP}
	u.Finalize()
	if u.MACLocallyAdministered {
		t.Error("a universally-administered MAC was flagged as local")
	}
}

func TestVendorForMAC(t *testing.T) {
	if n := OUICount(); n < 200 {
		t.Fatalf("compiled OUI table holds %d prefixes; a generator that emitted an empty map would make every lookup silently return \"\"", n)
	}
	cases := []struct{ mac, vendor string }{
		{"00:1a:2f:11:22:33", "Cisco Systems"},
		{"28:CF:DA:01:02:03", "Apple"},
		{"b8:27:eb:ff:ee:dd", "Raspberry Pi"},
		{"52:54:00:12:34:56", "QEMU virtual NIC"},
		{"00:50:56:aa:bb:cc", "VMware"},
		// Not in the curated table: "" means NOT DETERMINED, never "Unknown".
		{"aa:bb:cc:dd:ee:f0", ""},
		{"", ""},
		{"garbage", ""},
	}
	for _, tc := range cases {
		if got := VendorForMAC(tc.mac); got != tc.vendor {
			t.Errorf("VendorForMAC(%q) = %q, want %q", tc.mac, got, tc.vendor)
		}
	}
}

func TestNameClassification(t *testing.T) {
	o := &HostObservation{Source: SourceMDNS}
	o.addName("Printer.Local.")
	o.addName("laptop")
	o.addName("_ipp._tcp.local")
	o.addName("bad\x01name")
	o.addName(strings.Repeat("a", MaxNameLen+1))
	o.Finalize()

	if !slices.Equal(o.FQDNs, []string{"printer.local", "_ipp._tcp.local"}) {
		t.Errorf("FQDNs = %v", o.FQDNs)
	}
	// "printer" derived from the qualified name; "laptop" taken as given;
	// "_ipp" NOT derived, because an underscore label is DNS-SD structure.
	if !slices.Equal(o.Hostnames, []string{"printer", "laptop"}) {
		t.Errorf("Hostnames = %v", o.Hostnames)
	}
}

func TestBoundsAreEnforced(t *testing.T) {
	o := &HostObservation{Source: SourceARP, MAC: "00:1a:2f:11:22:33"}
	for i := 0; i < 100; i++ {
		o.addAddr(netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}))
		o.addHostname("host" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
		o.addFQDN("h" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example")
		o.addService("_svc" + string(rune('a'+i%26)) + "._tcp")
	}
	o.Finalize()

	if len(o.Addresses) > MaxAddresses {
		t.Errorf("Addresses = %d, bound %d", len(o.Addresses), MaxAddresses)
	}
	if len(o.Hostnames) > MaxHostnames {
		t.Errorf("Hostnames = %d, bound %d", len(o.Hostnames), MaxHostnames)
	}
	if len(o.FQDNs) > MaxFQDNs {
		t.Errorf("FQDNs = %d, bound %d", len(o.FQDNs), MaxFQDNs)
	}
	if len(o.Services) > MaxServices {
		t.Errorf("Services = %d, bound %d", len(o.Services), MaxServices)
	}
}

// TestFactsAreRegisteredAndWritable is the guard that keeps this package's
// Facts map honest. A key the `sensor` producer is not registered for is
// rejected at the consumer's write — silently, from this side — so a decoder
// that starts emitting one would lose the fact with nothing failing.
func TestFactsAreRegisteredAndWritable(t *testing.T) {
	o := &HostObservation{
		Source:   SourceLLDP,
		MAC:      "00:1a:2f:11:22:33",
		Services: []string{"_ipp._tcp"},
		Model:    "WS-C2960-24TT-L",
	}
	o.Finalize()

	if len(o.Facts) == 0 {
		t.Fatal("no facts derived; the observation carried a vendor, a service and a model")
	}
	for key, value := range o.Facts {
		if _, ok := facts.Get(key); !ok {
			t.Errorf("fact key %q is not in standards/fact-keys.yaml", key)
			continue
		}
		if !facts.MayWrite(facts.ProducerSensor, key) {
			t.Errorf("fact key %q: the sensor is not a registered producer", key)
		}
		if !facts.MayWrite(facts.ProducerPlatformSensor, key) {
			t.Errorf("fact key %q: the platform sensor is not a registered producer (pcap-processor writes the same shape)", key)
		}
		// The value has to survive the same validation the consumer runs, and
		// it crosses a JSON boundary first — so validate the round-tripped
		// form, not the in-memory one.
		blob, err := json.Marshal(value)
		if err != nil {
			t.Errorf("fact %q: not JSON-marshalable: %v", key, err)
			continue
		}
		var decoded any
		if err := json.Unmarshal(blob, &decoded); err != nil {
			t.Errorf("fact %q: not JSON-unmarshalable: %v", key, err)
			continue
		}
		if err := facts.ValidateValue(key, decoded); err != nil {
			t.Errorf("fact %q: value rejected by facts.ValidateValue: %v", key, err)
		}
	}
}

// TestPassiveDecodeEmitsNoNeighborFact is the guard for the decision that a
// captured advertisement identifies its ADVERTISER and nothing else.
//
// An LLDP or CDP frame reaching a sensor says the advertiser exists. It does
// not say the advertiser is attached to the sensor's host: a mirror or SPAN
// port copies frames from links the sensor is not on, which makes
// "advertiser ←→ sensor host" wrong in the common deployment rather than the
// rare one. `net.neighbors` remains a device-interrogation fact, written after
// reading a device's own LLDP/CDP/ARP table.
//
// This runs the real decoders over the real fixtures, not a hand-built
// observation, so a decoder that started constructing neighbours again would
// fail it.
func TestPassiveDecodeEmitsNoNeighborFact(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind Kind
		hex  string
	}{
		{"lldp", KindLLDP, lldpHex},
		{"cdp", KindCDP, cdpHex},
		{"arp", KindARP, arpGratuitousHex},
		{"mdns", KindMDNS, mdnsResponseHex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := Decode(tc.kind, Frame{
				Payload:   mustHex(t, tc.hex),
				SrcMAC:    "00:1a:2f:11:22:33",
				SrcAddr:   netip.MustParseAddr("192.168.10.9"),
				Interface: "eth0",
				At:        fixedTime,
			})
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if _, present := obs.Facts[facts.KeyNetNeighbors]; present {
				t.Errorf("passive %s decode wrote net.neighbors: %v", tc.name, obs.Facts)
			}
			blob, err := json.Marshal(obs)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(blob), "\"neighbors\"") {
				t.Errorf("observation carries a neighbors field: %s", blob)
			}
		})
	}
}

// TestCaptureInterfaceIsAnAttributeNotAnAdjacency pins where the capture
// interface goes. It is provenance — which interface the frame was seen on —
// and provenance is evidence, not a registered fact about the subject.
func TestCaptureInterfaceIsAnAttributeNotAnAdjacency(t *testing.T) {
	obs, err := DecodeLLDP(Frame{Payload: mustHex(t, lldpHex), Interface: "eth0", At: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if got := obs.Attributes["capture_interface"]; got != "eth0" {
		t.Errorf("capture_interface = %v, want eth0", got)
	}
	for key := range obs.Facts {
		if key == facts.KeyNetNeighbors {
			t.Errorf("the capture interface reached a neighbour fact")
		}
	}

	// A runtime with no interface name (a pcap file) writes no attribute at
	// all, rather than an empty one that reads as "seen on interface ''".
	obs, err = DecodeLLDP(Frame{Payload: mustHex(t, lldpHex), At: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := obs.Attributes["capture_interface"]; present {
		t.Errorf("an unnamed capture interface was recorded anyway: %v", obs.Attributes)
	}
}

func TestCoalesceEmptyNeverWins(t *testing.T) {
	c := NewCoalescer(time.Minute, 16)

	dhcp := &HostObservation{
		Source:     SourceDHCP,
		MAC:        "00:1e:4f:aa:bb:cc",
		Hostnames:  []string{"acct-ws-14"},
		Addresses:  addrs(t, "10.20.30.40"),
		ObservedAt: fixedTime,
	}
	dhcp.Finalize()
	if !c.Add(dhcp) {
		t.Fatal("first Add refused")
	}

	// A later ARP frame from the same host knows the MAC and the address but
	// no hostname. An unconditional last-writer-wins merge would erase the
	// name the DHCP told us — the exact bug that put NULL protocol versions
	// on fully-populated external_connections rows.
	arp := &HostObservation{
		Source:     SourceARP,
		MAC:        "00:1e:4f:aa:bb:cc",
		Addresses:  addrs(t, "10.20.30.40"),
		ObservedAt: fixedTime.Add(5 * time.Second),
	}
	arp.Finalize()
	if !c.Add(arp) {
		t.Fatal("second Add refused")
	}

	out := c.Drain()
	if len(out) != 1 {
		t.Fatalf("Drain returned %d observations, want 1 — the two frames name one host", len(out))
	}
	got := out[0]
	if !slices.Equal(got.Hostnames, []string{"acct-ws-14"}) {
		t.Errorf("Hostnames = %v; the ARP frame erased the DHCP hostname", got.Hostnames)
	}
	if !slices.Equal(got.Sources, []string{"arp", "dhcp"}) {
		t.Errorf("Sources = %v, want both decoders listed", got.Sources)
	}
	// Last seen, not first seen: an inventory's freshness is the latest frame.
	if !got.ObservedAt.Equal(fixedTime.Add(5 * time.Second)) {
		t.Errorf("ObservedAt = %v, want the later frame's time", got.ObservedAt)
	}
}

func TestCoalesceKeysOnMACThenAddress(t *testing.T) {
	c := NewCoalescer(time.Minute, 16)

	withMAC := &HostObservation{Source: SourceARP, MAC: "00:1a:2f:11:22:33", ObservedAt: fixedTime}
	withMAC.Finalize()
	c.Add(withMAC)

	// A DNS answer has no MAC, so it keys on its address and stays separate.
	dnsOnly := &HostObservation{
		Source:     SourceDNS,
		Addresses:  addrs(t, "10.1.2.3"),
		FQDNs:      []string{"app.corp.example"},
		ObservedAt: fixedTime,
	}
	dnsOnly.Finalize()
	c.Add(dnsOnly)

	if got := c.Pending(); got != 2 {
		t.Fatalf("Pending = %d, want 2 distinct subjects", got)
	}
}

func TestCoalesceWindowAndCapacity(t *testing.T) {
	c := NewCoalescer(30*time.Second, 2)
	// The coalescer measures an entry's age against the clock it is DRIVEN
	// with, not against the capture timestamp on the observation. Drive both
	// ends from the same fake clock, which is what the sensor does with
	// time.Now().
	clock := fixedTime
	c.now = func() time.Time { return clock }

	for i := range 4 {
		o := &HostObservation{
			Source:     SourceARP,
			MAC:        NormalizeMAC("00:1a:2f:11:22:0" + string(rune('0'+i))),
			ObservedAt: fixedTime,
		}
		o.Finalize()
		c.Add(o)
	}
	if got := c.Pending(); got != 2 {
		t.Errorf("Pending = %d, want the capacity of 2", got)
	}
	if c.Dropped() != 2 {
		t.Errorf("Dropped = %d, want 2 — a coalescer discarding half the segment must say so", c.Dropped())
	}

	// Nothing is due before the window closes.
	if out := c.Expired(fixedTime.Add(10 * time.Second)); len(out) != 0 {
		t.Errorf("Expired returned %d before the window closed", len(out))
	}
	if out := c.Expired(fixedTime.Add(31 * time.Second)); len(out) != 2 {
		t.Errorf("Expired returned %d after the window closed, want 2", len(out))
	}
	if c.Pending() != 0 {
		t.Error("Expired did not drain what it returned")
	}
}

// The window is measured against the clock the coalescer is driven with, and
// NOT against the capture timestamp on the observation.
//
// Mixing the two made the window's length a function of the drift between two
// clocks. The failure this pins is the one that actually happened: an NTP step
// BACKWARDS on the sensor host — or a capture timestamp running ahead of the
// host clock, which a tap that stamps its own time produces — left every
// subject sitting in the map until the wall clock caught up, with
// host_observations_pending climbing and nothing anywhere saying why.
//
// Mutation check: put `opened: obs.ObservedAt` back in Add and this fails,
// because the capture timestamps below are an hour ahead of the driving clock.
func TestCoalesceExpiryIgnoresCaptureTimestampSkew(t *testing.T) {
	c := NewCoalescer(30*time.Second, 8)
	clock := fixedTime
	c.now = func() time.Time { return clock }

	// The frame says it was captured an hour from now. That is a statement
	// about the capture, not about how long we have been accumulating.
	skewed := &HostObservation{
		Source:     SourceARP,
		MAC:        NormalizeMAC("00:1a:2f:11:22:33"),
		ObservedAt: fixedTime.Add(time.Hour),
	}
	skewed.Finalize()
	if !c.Add(skewed) {
		t.Fatal("Add refused a well-formed observation")
	}

	if out := c.Expired(clock.Add(10 * time.Second)); len(out) != 0 {
		t.Errorf("Expired returned %d before the window closed", len(out))
	}

	clock = clock.Add(31 * time.Second)
	out := c.Expired(clock)
	if len(out) != 1 {
		t.Fatalf("Expired returned %d after the window closed, want 1 — the capture timestamp must not stall expiry", len(out))
	}
	// The observation keeps the capture time it was given: only the coalescer's
	// bookkeeping uses the wall clock.
	if !out[0].ObservedAt.Equal(fixedTime.Add(time.Hour)) {
		t.Errorf("ObservedAt = %v, want the capture timestamp unchanged", out[0].ObservedAt)
	}
}

func TestCoalesceRefusesUnidentifiedObservations(t *testing.T) {
	c := NewCoalescer(time.Minute, 16)
	// Parsed cleanly, names nothing. Storing it would create an asset with no
	// identifiers, which nothing can ever match against again.
	if c.Add(&HostObservation{Source: SourceMDNS}) {
		t.Error("Add accepted an observation with no identity")
	}
	if c.Add(nil) {
		t.Error("Add accepted nil")
	}
}

func TestObservationJSONShape(t *testing.T) {
	// The wire contract names these keys. A rename here is a breaking change
	// for the inventory-service consumer.
	o := &HostObservation{
		Source:     SourceLLDP,
		MAC:        "00:1a:2f:11:22:33",
		Addresses:  addrs(t, "10.0.0.1"),
		Hostnames:  []string{"sw1"},
		FQDNs:      []string{"sw1.corp.example"},
		Services:   []string{"_ipp._tcp"},
		Model:      "WS-C2960-24TT-L",
		ObservedAt: fixedTime,
	}
	o.setAttr("lldp_capabilities", []string{"bridge"})
	o.Finalize()

	blob, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"observed_at", "mac", "addresses", "hostnames", "fqdns",
		"vendor", "model", "source", "sources", "services",
		"attributes", "facts",
	} {
		if _, ok := m[k]; !ok {
			t.Errorf("serialised observation is missing %q: %s", k, blob)
		}
	}
	// And this must NOT be there. `neighbors` was removed deliberately: a
	// passively captured advertisement identifies its advertiser, not an
	// adjacency to the capture point.
	if _, ok := m["neighbors"]; ok {
		t.Errorf("serialised observation still carries \"neighbors\": %s", blob)
	}
	// Addresses serialise as strings, not as netip's internal shape.
	if got := m["addresses"].([]any)[0]; got != "10.0.0.1" {
		t.Errorf("addresses[0] = %#v, want the dotted string", got)
	}
}
