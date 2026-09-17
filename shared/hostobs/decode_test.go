package hostobs

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

var fixedTime = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	return b
}

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test address %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

// want describes the parts of an observation a case asserts on. A nil slice
// means "not asserted"; an empty non-nil slice means "must be empty".
type want struct {
	mac       string
	local     bool
	vendor    string
	addresses []netip.Addr
	hostnames []string
	fqdns     []string
	services  []string
	model     string
	attrs     map[string]any
	noAttrs   []string
}

func check(t *testing.T, got *HostObservation, w want) {
	t.Helper()
	if got.MAC != w.mac {
		t.Errorf("MAC = %q, want %q", got.MAC, w.mac)
	}
	if got.MACLocallyAdministered != w.local {
		t.Errorf("MACLocallyAdministered = %v, want %v", got.MACLocallyAdministered, w.local)
	}
	if got.Vendor != w.vendor {
		t.Errorf("Vendor = %q, want %q", got.Vendor, w.vendor)
	}
	if w.addresses != nil && !slices.Equal(got.Addresses, w.addresses) {
		t.Errorf("Addresses = %v, want %v", got.Addresses, w.addresses)
	}
	if w.hostnames != nil && !slices.Equal(got.Hostnames, w.hostnames) {
		t.Errorf("Hostnames = %v, want %v", got.Hostnames, w.hostnames)
	}
	if w.fqdns != nil && !slices.Equal(got.FQDNs, w.fqdns) {
		t.Errorf("FQDNs = %v, want %v", got.FQDNs, w.fqdns)
	}
	if w.services != nil && !slices.Equal(got.Services, w.services) {
		t.Errorf("Services = %v, want %v", got.Services, w.services)
	}
	if got.Model != w.model {
		t.Errorf("Model = %q, want %q", got.Model, w.model)
	}
	// No decoder in this package may produce a neighbour fact: a captured
	// advertisement identifies the advertiser, not an adjacency to the
	// capture point. Asserted on EVERY case rather than in one test of its
	// own, so a decoder that grew one back fails wherever it did so.
	if _, present := got.Facts[facts.KeyNetNeighbors]; present {
		t.Errorf("decoder produced a net.neighbors fact: %v", got.Facts)
	}
	for k, v := range w.attrs {
		gv, ok := got.Attributes[k]
		if !ok {
			t.Errorf("Attributes[%q] missing; have %v", k, got.Attributes)
			continue
		}
		if !equalAttr(gv, v) {
			t.Errorf("Attributes[%q] = %#v, want %#v", k, gv, v)
		}
	}
	for _, k := range w.noAttrs {
		if _, ok := got.Attributes[k]; ok {
			t.Errorf("Attributes[%q] present, must not be", k)
		}
	}
}

func equalAttr(a, b any) bool {
	switch bv := b.(type) {
	case []string:
		av, ok := a.([]string)
		return ok && slices.Equal(av, bv)
	case []int:
		av, ok := a.([]int)
		return ok && slices.Equal(av, bv)
	default:
		return a == b
	}
}

func TestDecodeARP(t *testing.T) {
	cases := []struct {
		name  string
		hex   string
		frame Frame
		want  want
		err   error
	}{
		{
			name: "gratuitous reply announces a binding",
			hex:  arpGratuitousHex,
			want: want{
				mac:       "28:cf:da:11:22:33",
				vendor:    "Apple",
				addresses: addrs(t, "192.168.10.50"),
				attrs:     map[string]any{"arp_gratuitous": true, "arp_operation": "reply"},
			},
		},
		{
			name: "request records the sender, never the target",
			hex:  arpRequestHex,
			want: want{
				mac:       "00:14:22:aa:bb:cc",
				vendor:    "Dell",
				addresses: addrs(t, "192.168.10.20"),
				attrs:     map[string]any{"arp_operation": "request"},
				noAttrs:   []string{"arp_gratuitous"},
			},
		},
		{
			name: "probe keeps the MAC and records no address",
			hex:  arpProbeHex,
			want: want{
				mac:       "b8:27:eb:01:02:03",
				vendor:    "Raspberry Pi",
				addresses: []netip.Addr{},
				attrs:     map[string]any{"arp_probe": true},
			},
		},
		{name: "truncated", hex: "0001080006", err: ErrMalformed},
		{name: "empty", hex: "", err: ErrMalformed},
		{
			// Token Ring hardware type: a real ARP variant, not one we decode.
			name: "non-ethernet hardware type",
			hex:  "0006080006040001001422aabbccc0a80a14000000000000c0a80a01",
			err:  ErrNotApplicable,
		},
		{
			// Sender hardware address with the multicast bit set. A host
			// cannot have one; the frame is forged or broken.
			name: "multicast sender hardware address",
			hex:  "0001080006040001011422aabbccc0a80a14000000000000c0a80a01",
			err:  ErrNotApplicable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.frame
			f.Payload = mustHex(t, tc.hex)
			f.At = fixedTime
			got, err := DecodeARP(f)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Source != SourceARP {
				t.Errorf("Source = %q, want %q", got.Source, SourceARP)
			}
			if !got.ObservedAt.Equal(fixedTime) {
				t.Errorf("ObservedAt = %v, want %v", got.ObservedAt, fixedTime)
			}
			check(t, got, tc.want)
		})
	}
}

func TestDecodeDHCP(t *testing.T) {
	t.Run("request carries hostname, client id and fingerprint", func(t *testing.T) {
		got, err := DecodeDHCP(Frame{Payload: mustHex(t, dhcpRequestHex), At: fixedTime})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "00:1e:4f:aa:bb:cc",
			vendor:    "Dell",
			hostnames: []string{"acct-ws-14"},
			// Option 50 only: a DHCPREQUEST's ciaddr and yiaddr are both zero,
			// so the requested address is all the message states.
			addresses: addrs(t, "10.20.30.40"),
			attrs: map[string]any{
				"dhcp_message_type":           "request",
				"dhcp_vendor_class":           "MSFT 5.0",
				"dhcp_address_requested_only": true,
				"dhcp_param_request_list":     []int{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252},
			},
		})

		// The RFC 3118 authentication option is in the fixture, carrying the
		// sentinel "AUTHSENTINEL-HMAC" where a real message carries an HMAC.
		// Two guards, because either alone has a way of going quiet:
		//
		//  1. The sentinel must not appear anywhere in the serialised form.
		//  2. The attribute key set must be EXACTLY the allowlisted one. This
		//     is the guard that does the work: a string search only catches a
		//     leak whose bytes happen to be printable, and the first version
		//     of this test searched for a binary value that JSON had already
		//     escaped beyond recognition — it could not fail. Pinning the key
		//     set catches any option this decoder was not taught, whatever
		//     shape its value takes.
		blob, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(blob), "AUTHSENTINEL") {
			t.Errorf("DHCP option 90 authentication material reached the observation: %s", blob)
		}
		gotKeys := make([]string, 0, len(got.Attributes))
		for k := range got.Attributes {
			gotKeys = append(gotKeys, k)
		}
		slices.Sort(gotKeys)
		wantKeys := []string{
			"dhcp_address_requested_only",
			"dhcp_message_type",
			"dhcp_param_request_list",
			"dhcp_vendor_class",
		}
		if !slices.Equal(gotKeys, wantKeys) {
			t.Errorf("attributes = %v, want exactly %v — an unlisted DHCP option was collected", gotKeys, wantKeys)
		}
	})

	t.Run("ack attributes the assigned address to the client", func(t *testing.T) {
		got, err := DecodeDHCP(Frame{Payload: mustHex(t, dhcpAckHex), At: fixedTime})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "28:cf:da:01:02:03",
			vendor:    "Apple",
			hostnames: []string{"studio-mac"},
			addresses: addrs(t, "10.20.30.41"),
			attrs:     map[string]any{"dhcp_message_type": "ack"},
			// yiaddr was present, so the requested-only marker must NOT be set.
			noAttrs: []string{"dhcp_address_requested_only"},
		})
	})

	t.Run("vendor class is not hw.vendor", func(t *testing.T) {
		got, err := DecodeDHCP(Frame{Payload: mustHex(t, dhcpRequestHex), At: fixedTime})
		if err != nil {
			t.Fatal(err)
		}
		// "MSFT 5.0" identifies the DHCP client software. Letting it become
		// hw.vendor would file a Dell workstation under Microsoft.
		if got.Facts[facts.KeyHWVendor] != "Dell" {
			t.Errorf("hw.vendor = %v, want the OUI-derived Dell", got.Facts[facts.KeyHWVendor])
		}
	})

	t.Run("rejects", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			hex  string
			err  error
		}{
			{"short", "0101", ErrMalformed},
			// A valid-length BOOTP with no magic cookie: no options section.
			{"bootp without magic cookie", strings.Repeat("00", 240), ErrNotApplicable},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := DecodeDHCP(Frame{Payload: mustHex(t, tc.hex)})
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
			})
		}
	})
}

func TestDecodeMDNS(t *testing.T) {
	got, err := DecodeMDNS(Frame{
		Payload: mustHex(t, mdnsResponseHex),
		SrcMAC:  "00:1E:8F:AA:BB:CC",
		SrcAddr: netip.MustParseAddr("192.168.10.77"),
		At:      fixedTime,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	check(t, got, want{
		mac:       "00:1e:8f:aa:bb:cc",
		vendor:    "Canon",
		addresses: addrs(t, "192.168.10.77"),
		fqdns:     []string{"hp-printer.local"},
		hostnames: []string{"hp-printer"},
		services:  []string{"_ipp._tcp"},
	})

	// The fixture carries a TXT record. Nothing from it may appear.
	blob, _ := json.Marshal(got)
	if strings.Contains(string(blob), "ty=HP") {
		t.Errorf("mDNS TXT record content reached the observation: %s", blob)
	}
	// The service INSTANCE name is a user-chosen string ("HP LaserJet"); only
	// the service TYPE is kept.
	if strings.Contains(string(blob), "LaserJet") {
		t.Errorf("mDNS service instance name reached the observation: %s", blob)
	}

	if got.Relayed() {
		t.Errorf("a self-announcement was marked relayed: %v", got.Attributes)
	}
	if c := Confidence(got); c != 0.80 {
		t.Errorf("Confidence = %v, want 0.80 for a self-announcement", c)
	}

	t.Run("a query with known answers is refused", func(t *testing.T) {
		// Same load-bearing case as the DNS side: QR clear, answer section
		// populated. An mDNS decoder that read answers out of a query would be
		// recording what a device is searching for.
		got, err := DecodeMDNS(Frame{
			Payload: mustHex(t, dnsQueryWithAnswersHex),
			SrcMAC:  "00:1e:8f:aa:bb:cc",
			At:      fixedTime,
		})
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("err = %v, want ErrNotApplicable (got %#v)", err, got)
		}
	})

	// The reflector case. The SAME announcement, re-originated by a gateway
	// running an mDNS reflector: the frame now carries the gateway's MAC and
	// the gateway's address on this VLAN, and the printer's A record no longer
	// names the address the frame came from. Under the old sender rule the
	// gateway was inventoried as the printer — and, on a real network, as
	// every other host on every other VLAN too.
	t.Run("a relayed response is hearsay about the named host", func(t *testing.T) {
		got, err := DecodeMDNS(Frame{
			Payload: mustHex(t, mdnsResponseHex),
			SrcMAC:  "d8:b3:70:91:3b:87",              // the reflector's MAC
			SrcAddr: netip.MustParseAddr("192.0.2.1"), // the reflector's address
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "", // NOT the reflector's
			vendor:    "",
			addresses: addrs(t, "192.168.10.77"), // the record's, not the frame's
			fqdns:     []string{"hp-printer.local"},
			hostnames: []string{"hp-printer"},
			services:  []string{"_ipp._tcp"},
			attrs:     map[string]any{"mdns_relayed": true},
		})
		if !got.Relayed() {
			t.Error("Relayed() = false for a relayed response")
		}
		if c := Confidence(got); c != 0.60 {
			t.Errorf("Confidence = %v, want 0.60 (hearsay) for a relayed response", c)
		}
		if got.Key() != "ip:192.168.10.77" {
			t.Errorf("Key = %q; a relayed observation must coalesce on the named host, never on the reflector", got.Key())
		}
	})

	t.Run("no IP layer cannot prove self-origin", func(t *testing.T) {
		// A frame the caller could not attach a source address to gives the
		// decoder nothing to check the records against, and "unverifiable"
		// must land on the safe side: hearsay, not attribution.
		got, err := DecodeMDNS(Frame{
			Payload: mustHex(t, mdnsResponseHex),
			SrcMAC:  "00:1e:8f:aa:bb:cc",
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.MAC != "" {
			t.Errorf("MAC = %q attached without a source address to verify against", got.MAC)
		}
		if !got.Relayed() {
			t.Error("unverifiable response was not marked relayed")
		}
	})

	t.Run("a relayed response naming two hosts is refused, not merged", func(t *testing.T) {
		// Two owner names in one relayed message: the DNS rule applies. One
		// observation has one subject, and folding two hosts' addresses into
		// one hearsay observation would create a host that does not exist.
		got, err := DecodeMDNS(Frame{
			Payload: mustHex(t, dnsMultiOwnerHex),
			SrcMAC:  "d8:b3:70:91:3b:87",
			SrcAddr: netip.MustParseAddr("192.0.2.1"),
			At:      fixedTime,
		})
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("err = %v, want ErrNotApplicable (got %#v)", err, got)
		}
	})

	t.Run("a self-announcement naming two hosts keeps both", func(t *testing.T) {
		// The same two-owner message sent by a host whose address one of the
		// records names: the sender vouches for the message, and a host that
		// answers to two names is a host with two names.
		got, err := DecodeMDNS(Frame{
			Payload: mustHex(t, dnsMultiOwnerHex),
			SrcMAC:  "00:1e:8f:aa:bb:cc",
			SrcAddr: netip.MustParseAddr("10.1.2.3"),
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "00:1e:8f:aa:bb:cc",
			vendor:    "Canon",
			addresses: addrs(t, "10.1.2.3", "10.1.2.4"),
			fqdns:     []string{"a.corp.example", "b.corp.example"},
		})
	})
}

func TestDecodeDNS(t *testing.T) {
	t.Run("response yields one name to two addresses", func(t *testing.T) {
		got, err := DecodeDNS(Frame{
			Payload: mustHex(t, dnsResponseHex),
			// The DNS SERVER's MAC and address are deliberately supplied and
			// deliberately ignored: a resolver answer is hearsay about a third
			// party, and attributing it to the server would inventory the
			// resolver under every name it ever answered for.
			SrcMAC:  "00:15:5d:01:02:03",
			SrcAddr: netip.MustParseAddr("10.0.0.53"),
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "",
			addresses: addrs(t, "10.1.2.3", "10.1.2.4"),
			fqdns:     []string{"app.corp.example"},
			hostnames: []string{"app"},
		})
	})

	t.Run("a query is refused", func(t *testing.T) {
		_, err := DecodeDNS(Frame{Payload: mustHex(t, dnsQueryHex)})
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("err = %v, want ErrNotApplicable", err)
		}
	})

	t.Run("a query WITH answers is refused", func(t *testing.T) {
		// The load-bearing case. A query with an empty answer section is
		// refused whether or not the QR bit is checked, so the plain-query case
		// above cannot tell a working guard from a missing one. This message
		// has the QR bit clear and an answer section that would otherwise be
		// read — which is exactly mDNS known-answer suppression, a shape that
		// really appears on the wire.
		got, err := DecodeDNS(Frame{Payload: mustHex(t, dnsQueryWithAnswersHex)})
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("err = %v, want ErrNotApplicable (got %#v)", err, got)
		}
	})

	t.Run("a query never leaks the looked-up name", func(t *testing.T) {
		// Mutation guard: if parseDNSMessage ever started returning the
		// question section, this is what would catch it.
		msg, err := parseDNSMessage(mustHex(t, dnsQueryHex))
		if err != nil {
			t.Fatal(err)
		}
		for _, rr := range msg.Records {
			if strings.Contains(rr.Name, "secret-lookup") {
				t.Fatalf("question section surfaced as a record: %q", rr.Name)
			}
		}
	})

	t.Run("two owner names are refused, not merged", func(t *testing.T) {
		_, err := DecodeDNS(Frame{Payload: mustHex(t, dnsMultiOwnerHex)})
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("err = %v, want ErrNotApplicable", err)
		}
	})
}

func TestDecodeNBNS(t *testing.T) {
	t.Run("node status yields the name table and the adapter MAC", func(t *testing.T) {
		got, err := DecodeNBNS(Frame{
			Payload: mustHex(t, nbnsStatusHex),
			SrcMAC:  "00:11:22:33:44:55",
			SrcAddr: netip.MustParseAddr("192.168.10.80"),
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			// The in-protocol adapter unit ID wins over the Ethernet source.
			mac:       "00:15:5d:0a:0b:0c",
			vendor:    "Microsoft Hyper-V",
			addresses: addrs(t, "192.168.10.80"),
			hostnames: []string{"filesrv01"},
		})
		// The GROUP name is the domain, not this host. Taking it would name
		// every machine in the domain after the domain.
		if slices.Contains(got.Hostnames, "corpdomain") {
			t.Errorf("group name recorded as a host name: %v", got.Hostnames)
		}
	})

	t.Run("name query response yields name and address", func(t *testing.T) {
		got, err := DecodeNBNS(Frame{
			Payload: mustHex(t, nbnsNameQueryHex),
			SrcMAC:  "00:07:4d:11:22:33",
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "00:07:4d:11:22:33",
			vendor:    "Zebra Technologies",
			addresses: addrs(t, "192.168.10.90"),
			hostnames: []string{"printsrv"},
		})
	})
}

func TestDecodeLLDP(t *testing.T) {
	t.Run("switch advertisement", func(t *testing.T) {
		got, err := DecodeLLDP(Frame{
			Payload:   mustHex(t, lldpHex),
			SrcMAC:    "00:1a:2f:11:22:33",
			Interface: "eth0",
			At:        fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "00:1a:2f:11:22:33",
			vendor:    "Cisco Systems",
			addresses: addrs(t, "192.168.10.2"),
			fqdns:     []string{"access-sw-3.corp.example"},
			hostnames: []string{"access-sw-3"},
			attrs: map[string]any{
				// Only the ENABLED capability word is decoded: what a device
				// can do is a datasheet fact, what it has turned on is a fact
				// about this deployment.
				"lldp_capabilities":       []string{"bridge", "router"},
				"lldp_port_description":   "Uplink to core",
				"lldp_system_description": "Cisco IOS Software, C3750E Software",
				// The advertiser's OWN port, and the interface the frame was
				// captured on. Both evidence; neither an adjacency.
				"lldp_port_id":      "GigabitEthernet1/0/24",
				"capture_interface": "eth0",
			},
		})
	})

	t.Run("a maximum-length banner is truncated", func(t *testing.T) {
		got, err := DecodeLLDP(Frame{Payload: mustHex(t, lldpMaxDescHex), At: fixedTime})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		desc, _ := got.Attributes["lldp_system_description"].(string)
		if len(desc) == 0 {
			t.Fatal("system description missing")
		}
		if len(desc) > MaxDescriptionLen {
			t.Errorf("system description kept %d bytes, bound is %d", len(desc), MaxDescriptionLen)
		}
		if !strings.HasPrefix(desc, "Cisco IOS Software") {
			t.Errorf("truncation lost the identifying prefix: %q", desc)
		}
	})

	t.Run("a PEM private key in the banner is masked", func(t *testing.T) {
		got, err := DecodeLLDP(Frame{Payload: mustHex(t, lldpPemDescHex), At: fixedTime})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		desc, _ := got.Attributes["lldp_system_description"].(string)
		if strings.Contains(desc, "PRIVATE KEY") || strings.Contains(desc, "MIIBOgIBAAJBAKj") {
			t.Errorf("private key survived in the system description: %q", desc)
		}
		if !strings.Contains(desc, redact.Marker) {
			t.Errorf("redaction left no visible marker, so a firing scrubber is unobservable: %q", desc)
		}
		if !strings.HasPrefix(desc, "Device banner") {
			t.Errorf("text around the key should survive: %q", desc)
		}
	})

	t.Run("a snaplen-truncated frame keeps what parsed", func(t *testing.T) {
		// The identity TLVs come first and the long banner comes last, so a
		// capture cut short still contains the switch's identity. Discarding
		// the frame because its final TLV overruns would throw away a
		// measurement we have on account of one we do not.
		full := mustHex(t, lldpMaxDescHex)
		cut := full[:len(full)/2]

		got, err := DecodeLLDP(Frame{Payload: cut, Interface: "eth0", At: fixedTime})
		if err != nil {
			t.Fatalf("truncated LLDPDU rejected entirely: %v", err)
		}
		if got.MAC != "00:1a:2f:11:22:33" {
			t.Errorf("MAC = %q; the chassis ID is in the surviving prefix", got.MAC)
		}
		if got.Vendor != "Cisco Systems" {
			t.Errorf("Vendor = %q", got.Vendor)
		}
		if got.Attributes["lldp_port_id"] != "GigabitEthernet1/0/24" {
			t.Errorf("port ID lost: %#v", got.Attributes)
		}
	})

	t.Run("LLDP-MED states a model as a field, so hw.model is writable", func(t *testing.T) {
		// The only structured model an LLDP frame ever carries. Everything
		// else LLDP says about hardware is prose in the system description,
		// and this package does not mine prose for a fact that joins the
		// end-of-support catalogue.
		got, err := DecodeLLDP(Frame{Payload: mustHex(t, lldpMEDInventoryHex), At: fixedTime})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Model != "SIP-T46G" {
			t.Errorf("Model = %q, want SIP-T46G", got.Model)
		}
		if got.Facts[facts.KeyHWModel] != "SIP-T46G" {
			t.Errorf("hw.model = %v, want SIP-T46G", got.Facts[facts.KeyHWModel])
		}
		// The MED manufacturer is evidence only. hw.vendor stays OUI-derived,
		// so one fact keeps one source: this MAC is Cisco's prefix even though
		// the firmware says Yealink, and a device filed under two vendors is
		// the failure the single-source rule exists to prevent.
		if got.Attributes["lldp_med_manufacturer"] != "Yealink" {
			t.Errorf("lldp_med_manufacturer = %v", got.Attributes["lldp_med_manufacturer"])
		}
		if got.Facts[facts.KeyHWVendor] != "Cisco Systems" {
			t.Errorf("hw.vendor = %v, want the OUI-derived value", got.Facts[facts.KeyHWVendor])
		}
		// Both 802.1 organisationally specific TLVs are stepped over
		// structurally, like an unlisted DHCP option — including the one whose
		// SUBTYPE matches the model's. Pinned as an exact key set, because a
		// search for a value that was never written is a check that cannot
		// fail.
		gotKeys := make([]string, 0, len(got.Attributes))
		for k := range got.Attributes {
			gotKeys = append(gotKeys, k)
		}
		slices.Sort(gotKeys)
		if wantKeys := []string{"lldp_med_manufacturer", "lldp_port_id"}; !slices.Equal(gotKeys, wantKeys) {
			t.Errorf("attributes = %v, want exactly %v", gotKeys, wantKeys)
		}
	})

	t.Run("a TLV stream with no chassis ID is not an LLDPDU", func(t *testing.T) {
		// TTL TLV alone (type 3, length 2).
		_, err := DecodeLLDP(Frame{Payload: mustHex(t, "0602007800")})
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("err = %v, want ErrNotApplicable", err)
		}
	})
}

func TestDecodeCDP(t *testing.T) {
	t.Run("catalyst advertisement", func(t *testing.T) {
		got, err := DecodeCDP(Frame{
			Payload:   mustHex(t, cdpHex),
			SrcMAC:    "00:0f:23:aa:bb:cc",
			Interface: "eth1",
			At:        fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		check(t, got, want{
			mac:       "00:0f:23:aa:bb:cc",
			vendor:    "Cisco Systems",
			addresses: addrs(t, "192.168.10.3"),
			fqdns:     []string{"core-sw-1.corp.example"},
			hostnames: []string{"core-sw-1"},
			// The platform string with its vendor word stripped: hw.model
			// joins the hardware end-of-support catalogue alongside
			// hw.vendor, and "cisco WS-C2960-24TT-L" matches nothing there.
			model: "WS-C2960-24TT-L",
			attrs: map[string]any{
				"cdp_capabilities":  []string{"router", "switch", "igmp_capable"},
				"cdp_platform":      "cisco WS-C2960-24TT-L",
				"cdp_port_id":       "GigabitEthernet0/1",
				"capture_interface": "eth1",
			},
		})
		if got.Facts[facts.KeyHWModel] != "WS-C2960-24TT-L" {
			t.Errorf("hw.model = %v, want the platform string", got.Facts[facts.KeyHWModel])
		}
	})

	t.Run("LLC/SNAP header is stripped", func(t *testing.T) {
		body, ok := CDPFromLLCSNAP(mustHex(t, cdpSnapHex))
		if !ok {
			t.Fatal("CDPFromLLCSNAP did not recognise the SNAP header")
		}
		if hex.EncodeToString(body) != cdpHex {
			t.Errorf("stripped body does not match the bare CDP fixture")
		}
	})

	t.Run("a non-CDP SNAP header is refused", func(t *testing.T) {
		// Same LLC/SNAP shape but OUI 00-00-00 and protocol ID 0x0800.
		if _, ok := CDPFromLLCSNAP(mustHex(t, "aaaa03000000080045000000")); ok {
			t.Error("CDPFromLLCSNAP accepted a non-Cisco SNAP header")
		}
	})

	t.Run("a 10 KB banner is truncated", func(t *testing.T) {
		got, err := DecodeCDP(Frame{
			Payload: mustHex(t, cdpBigSoftwareHex),
			SrcMAC:  "00:0f:23:aa:bb:cc",
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sw, _ := got.Attributes["cdp_software_version"].(string)
		if len(sw) > MaxDescriptionLen {
			t.Errorf("software version kept %d bytes, bound is %d", len(sw), MaxDescriptionLen)
		}
		if !strings.HasPrefix(sw, "Cisco IOS Software") {
			t.Errorf("truncation lost the identifying prefix: %q", sw)
		}
	})

	t.Run("a snaplen-truncated frame keeps what parsed", func(t *testing.T) {
		// CDP's length field is 16 bits, so its software-version banner really
		// can be kilobytes — and it sits after the device ID. This is the case
		// the sensor's own 2 KB payload cap creates on every jumbo CDP frame.
		full := mustHex(t, cdpBigSoftwareHex)
		cut := full[:200]

		got, err := DecodeCDP(Frame{Payload: cut, SrcMAC: "00:0f:23:aa:bb:cc", At: fixedTime})
		if err != nil {
			t.Fatalf("truncated CDP frame rejected entirely: %v", err)
		}
		if len(got.FQDNs) == 0 || got.FQDNs[0] != "core-sw-1.corp.example" {
			t.Errorf("device ID lost to truncation: %#v", got.FQDNs)
		}
		// The overrunning TLV contributes nothing, which is correct — half a
		// banner is not a banner.
		if _, present := got.Attributes["cdp_software_version"]; present {
			t.Errorf("a truncated banner was recorded: %v", got.Attributes["cdp_software_version"])
		}
	})

	t.Run("a TLV shorter than its own header is malformed", func(t *testing.T) {
		// Distinct from truncation: the bytes are present and the length is
		// impossible, so the frame is rejected rather than salvaged.
		_, err := DecodeCDP(Frame{Payload: mustHex(t, "02b40000000100020000")})
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("a PEM private key in the banner is masked", func(t *testing.T) {
		got, err := DecodeCDP(Frame{
			Payload: mustHex(t, cdpPemSoftwareHex),
			SrcMAC:  "00:0f:23:aa:bb:cc",
			At:      fixedTime,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sw, _ := got.Attributes["cdp_software_version"].(string)
		if strings.Contains(sw, "PRIVATE KEY") || strings.Contains(sw, "MIIBOgIBAAJBAKj") {
			t.Errorf("private key survived in the software version: %q", sw)
		}
		if !strings.Contains(sw, redact.Marker) {
			t.Errorf("redaction left no visible marker: %q", sw)
		}
	})
}
