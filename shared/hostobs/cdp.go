package hostobs

import (
	"net/netip"
	"strings"
)

// Cisco Discovery Protocol. The frame is LLC/SNAP-encapsulated; the body is
//
//	version(1) ttl(1) checksum(2) then TLVs of type(2) length(2) value,
//
// where length INCLUDES the four header bytes — the single most common CDP
// parsing bug, because every other TLV format in this package excludes it.
const (
	cdpTLVDeviceID    = 0x0001
	cdpTLVAddresses   = 0x0002
	cdpTLVPortID      = 0x0003
	cdpTLVCapability  = 0x0004
	cdpTLVSoftware    = 0x0005
	cdpTLVPlatform    = 0x0006
	cdpTLVMgmtAddress = 0x0016

	cdpMaxTLVs      = 64
	cdpMaxAddresses = 8
)

// cdpCapabilityNames indexes the CDP capability bitmask.
var cdpCapabilityNames = []string{
	"router", "transparent_bridge", "source_route_bridge", "switch",
	"host", "igmp_capable", "repeater", "voip_phone",
	"remotely_managed", "cvta_phone", "two_port_mac_relay",
}

// CDPCapabilityNames is the vocabulary this decoder emits, as a copy.
//
// Exported because it is a vocabulary two packages must agree on, not an
// implementation detail: the `cdp_capabilities` rules in
// standards/classification-rules.yaml are written in these words, and a rule
// naming anything else matches nothing and SAYS nothing — the classifier simply
// never proposes that class. shared/classify's parity test is what stands
// between a typo and that silence.
func CDPCapabilityNames() []string {
	return append([]string(nil), cdpCapabilityNames...)
}

// CDPFromLLCSNAP strips the 802.2 LLC/SNAP header from an 802.3 frame payload
// and returns the CDP body, reporting whether the header was a CDP one.
//
// CDP is not an EtherType protocol: the frame is 802.3 with LLC
// DSAP/SSAP/control AA AA 03, SNAP OUI 00-00-0C (Cisco) and protocol ID
// 0x2000. Callers that have already stripped LLC/SNAP (gopacket does, when it
// decodes the layer) pass the body to [DecodeCDP] directly.
func CDPFromLLCSNAP(b []byte) ([]byte, bool) {
	if len(b) < 8 {
		return nil, false
	}
	if b[0] != 0xaa || b[1] != 0xaa || b[2] != 0x03 {
		return nil, false
	}
	if b[3] != 0x00 || b[4] != 0x00 || b[5] != 0x0c {
		return nil, false
	}
	if b[6] != 0x20 || b[7] != 0x00 {
		return nil, false
	}
	return b[8:], true
}

// DecodeCDP extracts the advertising device's identity, mirroring [DecodeLLDP].
//
// The device ID is a name, not a MAC — Cisco gear sends its hostname, often
// fully qualified — so the subject's MAC comes from the Ethernet source
// address. The platform string ("cisco WS-C3750G-24TS-S") becomes hw.model,
// which is the one hardware fact a passive frame states as a field rather than
// leaving to be inferred from a banner.
//
// NO adjacency is recorded. A captured advertisement proves the advertiser
// exists; it does not prove the advertiser is attached to the host running the
// sensor, which is normally fed by a mirror or SPAN port. See the note above
// [HostObservation].
func DecodeCDP(f Frame) (*HostObservation, error) {
	b := f.Payload
	if len(b) < 4 {
		return nil, ErrMalformed
	}
	version := b[0]
	if version != 1 && version != 2 {
		return nil, ErrNotApplicable
	}

	obs := f.newObservation(SourceCDP)
	obs.MAC = NormalizeMAC(f.SrcMAC)

	sawTLV := false
	off := 4
	for n := 0; n < cdpMaxTLVs; n++ {
		if off+4 > len(b) {
			break
		}
		ttype, _ := be16(b, off)
		tlen, _ := be16(b, off+2)
		// Length includes the 4-byte header; a length below that is malformed
		// and a length of exactly 4 is an empty TLV.
		if tlen < 4 {
			// A length below its own header cannot be a truncation artefact —
			// the bytes are there and they are wrong. Genuinely malformed.
			return nil, ErrMalformed
		}
		if off+int(tlen) > len(b) {
			// A TLV whose value runs past the end. Stop and keep what parsed,
			// the same as LLDP and for the same reason: CDP's length field is
			// 16 bits, so the software-version banner really can be kilobytes,
			// and it sits AFTER the device ID and port ID. Discarding the frame
			// would lose the switch's identity because its banner did not fit
			// in the snaplen.
			break
		}
		val := b[off+4 : off+int(tlen)]
		off += int(tlen)
		sawTLV = true

		switch ttype {
		case cdpTLVDeviceID:
			obs.addName(string(val))

		case cdpTLVPortID:
			// The advertiser's OWN port ("GigabitEthernet0/1"). Evidence about
			// that switch, not an adjacency to anything.
			if s := boundIdentifier(string(val)); s != "" {
				obs.setAttr("cdp_port_id", s)
			}

		case cdpTLVAddresses, cdpTLVMgmtAddress:
			for _, a := range decodeCDPAddresses(val) {
				obs.addAddr(a)
			}

		case cdpTLVCapability:
			mask, ok := be32(val, 0)
			if !ok {
				continue
			}
			if caps := decodeCapabilityBits(mask, cdpCapabilityNames); len(caps) > 0 {
				obs.setAttr("cdp_capabilities", caps)
			}

		case cdpTLVSoftware:
			// A full "Cisco IOS Software, C3750E Software…" banner. Truncated
			// and PEM-scrubbed like the LLDP system description.
			if s := boundText(string(val)); s != "" {
				obs.setAttr("cdp_software_version", s)
			}

		case cdpTLVPlatform:
			if s := boundIdentifier(string(val)); s != "" {
				obs.setAttr("cdp_platform", s)
				obs.Model = cdpPlatformModel(s)
			}
		}
	}

	if !sawTLV {
		return nil, ErrNotApplicable
	}

	obs.Finalize()
	if !obs.Identifies() {
		return nil, ErrNotApplicable
	}
	return obs, nil
}

// decodeCDPAddresses reads the CDP address TLV body:
//
//	count(4) then count × { ptype(1) plen(1) protocol(plen)
//	                        alen(2) address(alen) }
//
// The count is attacker-controlled and can claim four billion entries, so it
// is clamped and the loop is bounded by the buffer as well.
func decodeCDPAddresses(val []byte) []netip.Addr {
	count, ok := be32(val, 0)
	if !ok {
		return nil
	}
	n := int(min(uint32(cdpMaxAddresses), count))
	out := make([]netip.Addr, 0, n)
	off := 4
	for i := 0; i < n; i++ {
		if off+2 > len(val) {
			break
		}
		plen := int(val[off+1])
		off += 2
		if off+plen > len(val) {
			break
		}
		proto := val[off : off+plen]
		off += plen
		alen, ok := be16(val, off)
		if !ok {
			break
		}
		off += 2
		if off+int(alen) > len(val) {
			break
		}
		raw := val[off : off+int(alen)]
		off += int(alen)

		// NLPID 0xcc is IPv4; the 8-byte 802.2 form ending 0x86dd is IPv6.
		// Anything else (CLNS, DECnet, AppleTalk) is a protocol we do not
		// inventory addresses for.
		switch {
		case plen == 1 && proto[0] == 0xcc && len(raw) == 4:
		case plen == 8 && proto[6] == 0x86 && proto[7] == 0xdd && len(raw) == 16:
		default:
			continue
		}
		if a, ok := addrFromBytes(raw); ok {
			out = append(out, a)
		}
	}
	return out
}

// cdpPlatformModel turns a CDP platform string into the hw.model value.
//
// The string is the device's own statement of its platform, and on Cisco gear
// it is the model with the vendor word in front: "cisco WS-C2960-24TT-L". That
// leading token is stripped, and ONLY that one — hw.model is the join key into
// the hardware end-of-support catalogue alongside hw.vendor, so carrying the
// vendor inside the model would fail every lookup. No other rewriting is done:
// a platform string this function does not recognise is passed through whole
// rather than pattern-matched into a shape it may not have.
func cdpPlatformModel(platform string) string {
	for _, prefix := range cdpVendorPrefixes {
		rest, ok := strings.CutPrefix(platform, prefix)
		if !ok {
			continue
		}
		if rest = strings.TrimSpace(rest); rest != "" {
			return rest
		}
		return platform
	}
	return platform
}

// cdpVendorPrefixes are the leading vendor tokens stripped from a platform
// string. Cisco's own spellings only: CDP is Cisco's protocol, and a
// third-party implementation's platform string is left exactly as sent rather
// than guessed at.
var cdpVendorPrefixes = []string{"cisco ", "Cisco "}
