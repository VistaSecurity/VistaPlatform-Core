package hostobs

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// boundText and boundIdentifier redact BEFORE they truncate, and the ordering
// is the whole guard: cutting a PEM block in half first leaves a fragment with
// no END line, which redact.TextPEM's regex cannot match, and the fragment then
// ships as the device's banner.
//
// The two orderings agree on every input except that one, which is why the
// existing PEM tests — whose banners fit inside the bound — stayed green when
// the gate-2 sweep swapped the two lines. An LLDP system description is free
// text a device operator controls and a full IOS version block runs to several
// kilobytes, so a banner longer than MaxDescriptionLen is the ordinary case,
// not a contrived one.
func TestBoundTextRedactsBeforeItTruncates(t *testing.T) {
	const key = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIBOgIBAAJBAKjMUSTNOTSHIPabcdefghijklmnopqrstuvwxyz0123456789\n" +
		"-----END RSA PRIVATE KEY-----"

	for _, tc := range []struct {
		name  string
		bound int
		fn    func(string) string
	}{
		{"boundText", MaxDescriptionLen, boundText},
		{"boundIdentifier", MaxIdentifierLen, boundIdentifier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The key starts just inside the bound and its END line falls well
			// outside it, so truncate-first would keep a headless fragment.
			prefix := "Device banner " + strings.Repeat("x", tc.bound-60)
			in := prefix + " " + key + " trailing text"
			// The BEGIN line has to land INSIDE the bound and the END line
			// outside it, or the input does not straddle the cut and the test
			// would pass under either ordering — which is exactly the shape
			// that let this regression hide.
			if begin := len(prefix) + len(" -----BEGIN RSA PRIVATE KEY-----"); begin >= tc.bound {
				t.Fatalf("the BEGIN line ends at %d, outside the bound %d: nothing straddles the cut", begin, tc.bound)
			}
			if len(in) <= tc.bound {
				t.Fatalf("the input (%d bytes) fits inside the bound %d, so no truncation happens at all", len(in), tc.bound)
			}

			got := tc.fn(in)
			if len(got) > tc.bound {
				t.Errorf("result kept %d bytes, bound is %d", len(got), tc.bound)
			}
			for _, fragment := range []string{"PRIVATE KEY", "MIIBOgIBAAJBA"} {
				if strings.Contains(got, fragment) {
					t.Errorf("key material survived the bound: %q contains %q", got, fragment)
				}
			}
			if !strings.Contains(got, redact.Marker) {
				t.Errorf("no redaction marker, so a firing scrubber is unobservable: %q", got)
			}
			if !strings.HasPrefix(got, "Device banner") {
				t.Errorf("the identifying prefix was lost: %q", got)
			}
		})
	}

	// Inverse polarity: a CERTIFICATE block is posture, and a scrubber that ate
	// it would be the same bug pointed the other way.
	cert := "Platform " + strings.Repeat("y", 20) + " -----BEGIN CERTIFICATE-----\nMIIBpublicKeepMe\n-----END CERTIFICATE-----"
	if kept := boundText(cert); !strings.Contains(kept, "MIIBpublicKeepMe") {
		t.Errorf("a public certificate block was scrubbed: %q", kept)
	}
}

// A truncated mDNS announcement yields what parsed, not a parse fault.
//
// This is the case the sensor produces on its own: captured payloads are capped
// at 2 KB, and a printer announcing a dozen service types goes past that
// routinely. Every one of those frames was reported as ErrMalformed —
// "there is a broken speaker on this segment" — when the truth was "we cut the
// packet off", and the records that HAD parsed were discarded with the rest.
//
// Mutation check: change any of parseDNSMessage's `return msg, nil` salvage
// arms back to `return nil, ErrMalformed` and this fails.
func TestMDNSTruncatedMessageIsSalvaged(t *testing.T) {
	full := mustHex(t, mdnsResponseHex)
	whole, err := parseDNSMessage(full)
	if err != nil {
		t.Fatalf("the fixture itself does not parse: %v", err)
	}
	if len(whole.Records) != 4 {
		t.Fatalf("fixture has %d records, the cases below assume 4", len(whole.Records))
	}

	// Cut ONE byte off the end. The fixture's last record is a TXT with six
	// bytes of rdata, so this lands mid-rdata — inside a record, not on a
	// boundary.
	//
	// The distinction matters and is why this test does not search for a cut
	// point: a prefix that happens to end exactly ON a record boundary was
	// always accepted (the walk simply runs out of buffer and stops), so a test
	// that let itself find one would assert nothing at all. It has to be a cut
	// that leaves a record half-read.
	cut := full[:len(full)-1]

	partial, err := parseDNSMessage(cut)
	if err != nil {
		t.Fatalf("a message cut mid-record was refused: %v", err)
	}
	if len(partial.Records) != 3 {
		t.Fatalf("salvaged %d records, want the 3 that parsed before the cut", len(partial.Records))
	}

	got, err := DecodeMDNS(Frame{
		Payload: cut,
		SrcMAC:  "00:1e:8f:aa:bb:cc",
		SrcAddr: netip.MustParseAddr("192.168.10.77"),
		At:      fixedTime,
	})
	if err != nil {
		t.Fatalf("a truncated announcement was refused: %v", err)
	}
	if got.MAC != "00:1e:8f:aa:bb:cc" {
		t.Errorf("MAC = %q, want the frame's source MAC", got.MAC)
	}
	// The A record at the front of the fixture names the host, and the PTR
	// names the service. Both are exactly what a whole-message refusal threw
	// away.
	if len(got.FQDNs) == 0 || got.FQDNs[0] != "hp-printer.local" {
		t.Errorf("FQDNs = %v, want the name the surviving prefix carried", got.FQDNs)
	}
	if len(got.Services) == 0 || got.Services[0] != "_ipp._tcp" {
		t.Errorf("Services = %v, want the service type the surviving prefix carried", got.Services)
	}
}

// Truncation with NOTHING readable is ErrNotApplicable, not ErrMalformed.
//
// The frame was well formed; we hold a prefix of it too short to say anything.
// "This carries no host observation" is true. "This is malformed" is not, and
// it is the sentence that puts a count on the heartbeat's malformed metric and
// sends somebody looking for a broken device.
func TestTruncatedToNothingIsNotMalformed(t *testing.T) {
	full := mustHex(t, mdnsResponseHex)
	// Header only: flags survive, no record does.
	_, err := DecodeMDNS(Frame{
		Payload: full[:dnsHeaderLen],
		SrcMAC:  "00:1e:8f:aa:bb:cc",
		At:      fixedTime,
	})
	if errors.Is(err, ErrMalformed) {
		t.Fatalf("a header-only prefix was reported as malformed: %v", err)
	}
	if !errors.Is(err, ErrNotApplicable) {
		t.Fatalf("err = %v, want ErrNotApplicable", err)
	}
}

// A message shorter than a header has no flags word to trust and no record
// boundary to find. It stays malformed — there is nothing to salvage FROM.
func TestSubHeaderIsStillMalformed(t *testing.T) {
	_, err := parseDNSMessage([]byte{0x12, 0x34})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// A message that CONTRADICTS ITSELF is still refused whole. Salvage is for
// "the bytes ran out", never for "the bytes disagree" — a reader that carried
// on past a forward compression pointer would be choosing which half of a
// self-inconsistent message to believe.
func TestStructuralFaultsAreStillMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		// Header, qd=0 an=1, then a name whose first byte is a compression
		// pointer to offset 0x3FFF — forwards, and past the end.
		{"forward compression pointer", "12348000000000010000000" + "0" + "cfff" + "000100010000007800040a010203"},
		// Reserved label type 0x40.
		{"reserved label type", "1234800000000001000000004001020300010001000000780004"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := mustHex(t, tc.hex)
			if _, err := parseDNSMessage(b); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// The NetBIOS and DNS readers must refuse the same compression-pointer chains.
// Two parsers of one construct that disagree about what they refuse is how one
// of them ends up being the wrong one.
func TestNBNSPointerChainIsBounded(t *testing.T) {
	// The chain terminates at a VALID name, so the only thing that can refuse it
	// is the jump counter. A chain ending in garbage would be refused either
	// way, and a test built on one asserts nothing — that is the shape the first
	// draft of this test had.
	//
	// Mutation check: drop `jumps >= dnsMaxJumps ||` from readNBNSNameAt and
	// this fails, because the chain resolves to WS1.
	b := nbnsPointerChain(dnsMaxJumps + 2)

	if _, _, _, err := readNBNSNameWithSuffix(b, len(b)-2); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a %d-jump NetBIOS pointer chain was accepted: err = %v", dnsMaxJumps+2, err)
	}

	// And the DNS reader refuses the same shape, which is the whole point of
	// giving the two parsers the same pair of guards.
	if _, _, err := readDNSName(b, len(b)-2); !errors.Is(err, ErrMalformed) {
		t.Fatalf("the DNS reader accepted the same chain: err = %v", err)
	}
}

// A short backwards chain is still legal in both readers — the bound must not
// have been implemented by refusing compression outright.
func TestNBNSShortPointerChainStillWorks(t *testing.T) {
	for _, jumps := range []int{1, dnsMaxJumps - 1} {
		b := nbnsPointerChain(jumps)
		got, _, _, err := readNBNSNameWithSuffix(b, len(b)-2)
		if err != nil {
			t.Fatalf("a %d-jump backwards chain was refused: %v", jumps, err)
		}
		if !strings.EqualFold(got, "WS1") {
			t.Errorf("%d jumps: name = %q, want WS1", jumps, got)
		}
	}
}

// nbnsPointerChain builds a buffer holding a valid encoded NetBIOS name at
// offset 0 followed by `jumps` strictly-backwards compression pointers, each
// aimed at the one before it and the first aimed at the name. Reading from the
// last pointer therefore follows exactly `jumps` hops and lands on a name that
// decodes.
func nbnsPointerChain(jumps int) []byte {
	b := encodeNBNSForTest("WS1", 0x00)
	b = append(b, 0x00) // scope terminator
	prev := 0
	for i := 0; i < jumps; i++ {
		at := len(b)
		b = append(b, byte(0xc0|prev>>8), byte(prev))
		prev = at
	}
	return b
}

// encodeNBNSForTest first-level-encodes a NetBIOS name: the 15-byte padded name
// plus a suffix byte, each octet split into two nibbles offset from 'A'.
func encodeNBNSForTest(name string, suffix byte) []byte {
	padded := make([]byte, 16)
	for i := range padded[:15] {
		padded[i] = ' '
	}
	copy(padded, strings.ToUpper(name))
	padded[15] = suffix

	out := make([]byte, 0, 1+nbnsNameLen)
	out = append(out, byte(nbnsNameLen))
	for _, c := range padded {
		out = append(out, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	return out
}
