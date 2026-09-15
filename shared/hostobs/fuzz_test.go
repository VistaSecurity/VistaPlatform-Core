package hostobs

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Every decoder is handed frames straight off a hostile network. The length
// fields in them are attacker-controlled, DNS name compression can point at
// itself, a CDP address TLV can claim four billion entries, and a NetBIOS
// node-status response can claim 255 names in eighteen bytes.
//
// The contract each fuzz target checks is the same three things:
//
//  1. No panic, ever. A panic in a decoder takes the sensor's capture goroutine
//     with it, and a sensor that dies on one malformed frame reports nothing
//     about the whole segment afterwards.
//  2. Every returned observation satisfies the package's own bounds. A parser
//     that returns a result has to return a result the consumer can store.
//  3. Every returned observation is JSON-marshalable, because that is the only
//     way it leaves this process.
//
// `errors.Is` on the returned error is deliberately NOT asserted: a decoder
// may legitimately report either flavour for a given pile of random bytes, and
// pinning that would test the fuzzer rather than the decoder.

type decoder struct {
	name string
	fn   func(Frame) (*HostObservation, error)
}

func fuzzFrame(payload []byte) Frame {
	return Frame{
		Payload:   payload,
		SrcMAC:    "00:1a:2f:11:22:33",
		SrcAddr:   netip.MustParseAddr("192.168.10.9"),
		Interface: "eth0",
		At:        time.Unix(1789000000, 0).UTC(),
	}
}

// assertUsable is the post-condition every decoder owes its caller.
func assertUsable(t *testing.T, name string, obs *HostObservation, err error) {
	t.Helper()
	if obs == nil {
		if err == nil {
			t.Fatalf("%s returned (nil, nil): a decoder must say which", name)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s returned both an observation and an error %v", name, err)
	}
	if !obs.Identifies() {
		t.Fatalf("%s returned an observation with no identity: %#v", name, obs)
	}
	if len(obs.Addresses) > MaxAddresses {
		t.Fatalf("%s: %d addresses exceeds bound %d", name, len(obs.Addresses), MaxAddresses)
	}
	if len(obs.Hostnames) > MaxHostnames {
		t.Fatalf("%s: %d hostnames exceeds bound %d", name, len(obs.Hostnames), MaxHostnames)
	}
	if len(obs.FQDNs) > MaxFQDNs {
		t.Fatalf("%s: %d fqdns exceeds bound %d", name, len(obs.FQDNs), MaxFQDNs)
	}
	if len(obs.Services) > MaxServices {
		t.Fatalf("%s: %d services exceeds bound %d", name, len(obs.Services), MaxServices)
	}
	if len(obs.Model) > MaxIdentifierLen {
		t.Fatalf("%s: model of %d bytes exceeds bound %d", name, len(obs.Model), MaxIdentifierLen)
	}
	for _, n := range obs.Hostnames {
		if len(n) > MaxNameLen {
			t.Fatalf("%s: hostname of %d bytes exceeds bound %d", name, len(n), MaxNameLen)
		}
	}
	for _, n := range obs.FQDNs {
		if len(n) > MaxNameLen {
			t.Fatalf("%s: fqdn of %d bytes exceeds bound %d", name, len(n), MaxNameLen)
		}
	}
	for k, v := range obs.Attributes {
		switch tv := v.(type) {
		case string:
			if len(tv) > MaxDescriptionLen {
				t.Fatalf("%s: attribute %q of %d bytes exceeds bound %d", name, k, len(tv), MaxDescriptionLen)
			}
		case []string:
			if len(tv) > MaxCapabilities {
				t.Fatalf("%s: attribute %q has %d entries, bound is %d", name, k, len(tv), MaxCapabilities)
			}
		case []int:
			// The DHCP parameter-request fingerprint is the only []int, and it
			// is the one list whose length a single crafted option controls.
			if len(tv) > MaxDHCPParams {
				t.Fatalf("%s: attribute %q has %d entries, bound is %d", name, k, len(tv), MaxDHCPParams)
			}
		}
	}
	// No decoder may emit a neighbour fact from a passive frame — an
	// advertisement proves the advertiser exists, not that it is adjacent to
	// the capture point.
	if _, present := obs.Facts["net.neighbors"]; present {
		t.Fatalf("%s: passive decode produced a net.neighbors fact", name)
	}
	if _, err := json.Marshal(obs); err != nil {
		t.Fatalf("%s: observation is not JSON-marshalable: %v", name, err)
	}
}

func seedFrom(f *testing.F, hexes ...string) {
	f.Helper()
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			f.Fatalf("bad seed hex: %v", err)
		}
		f.Add(b)
	}
	// Shapes a random mutator is unlikely to reach on its own.
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add(make([]byte, 1500))
}

func FuzzDecodeARP(f *testing.F) {
	seedFrom(f, arpGratuitousHex, arpRequestHex, arpProbeHex)
	f.Fuzz(func(t *testing.T, b []byte) {
		obs, err := DecodeARP(fuzzFrame(b))
		assertUsable(t, "DecodeARP", obs, err)
	})
}

func FuzzDecodeDHCP(f *testing.F) {
	seedFrom(f, dhcpRequestHex, dhcpAckHex)
	f.Fuzz(func(t *testing.T, b []byte) {
		obs, err := DecodeDHCP(fuzzFrame(b))
		assertUsable(t, "DecodeDHCP", obs, err)
	})
}

func FuzzDecodeMDNS(f *testing.F) {
	seedFrom(f, mdnsResponseHex, dnsResponseHex, dnsQueryHex)
	f.Fuzz(func(t *testing.T, b []byte) {
		obs, err := DecodeMDNS(fuzzFrame(b))
		assertUsable(t, "DecodeMDNS", obs, err)
	})
}

func FuzzDecodeDNS(f *testing.F) {
	seedFrom(f, dnsResponseHex, dnsQueryHex, dnsMultiOwnerHex, mdnsResponseHex)
	// A self-referential compression pointer: the classic DNS decompression
	// loop. Header, then a pointer at offset 12 aimed at offset 12.
	f.Add([]byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,
		0x0a, 0x00, 0x00, 0x01,
	})
	f.Fuzz(func(t *testing.T, b []byte) {
		obs, err := DecodeDNS(fuzzFrame(b))
		assertUsable(t, "DecodeDNS", obs, err)
	})
}

func FuzzDecodeNBNS(f *testing.F) {
	seedFrom(f, nbnsStatusHex, nbnsNameQueryHex)
	f.Fuzz(func(t *testing.T, b []byte) {
		obs, err := DecodeNBNS(fuzzFrame(b))
		assertUsable(t, "DecodeNBNS", obs, err)
	})
}

func FuzzDecodeLLDP(f *testing.F) {
	seedFrom(f, lldpHex, lldpMaxDescHex, lldpPemDescHex)
	f.Fuzz(func(t *testing.T, b []byte) {
		obs, err := DecodeLLDP(fuzzFrame(b))
		assertUsable(t, "DecodeLLDP", obs, err)
	})
}

func FuzzDecodeCDP(f *testing.F) {
	seedFrom(f, cdpHex, cdpBigSoftwareHex, cdpPemSoftwareHex)
	// An address TLV claiming four billion entries in eight bytes.
	f.Add([]byte{
		0x02, 0xb4, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x0c, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0xcc, 0x00,
	})
	f.Fuzz(func(t *testing.T, b []byte) {
		obs, err := DecodeCDP(fuzzFrame(b))
		assertUsable(t, "DecodeCDP", obs, err)
	})
}

// FuzzCoalesce drives the merge path with decoder output, so the invariants
// hold after a merge and not only after a single decode.
func FuzzCoalesce(f *testing.F) {
	seedFrom(f, arpGratuitousHex, dhcpRequestHex, lldpHex)
	f.Fuzz(func(t *testing.T, b []byte) {
		c := NewCoalescer(time.Minute, 8)
		decoders := []decoder{
			{"arp", DecodeARP}, {"dhcp", DecodeDHCP}, {"mdns", DecodeMDNS},
			{"dns", DecodeDNS}, {"nbns", DecodeNBNS}, {"lldp", DecodeLLDP},
			{"cdp", DecodeCDP},
		}
		for _, d := range decoders {
			obs, err := d.fn(fuzzFrame(b))
			if err != nil && obs != nil {
				t.Fatalf("%s returned both", d.name)
			}
			if errors.Is(err, ErrMalformed) || errors.Is(err, ErrNotApplicable) {
				continue
			}
			c.Add(obs)
		}
		for _, merged := range c.Drain() {
			assertUsable(t, "Coalesce", merged, nil)
		}
	})
}
