package hostobs

import "strings"

// NetBIOS Name Service (RFC 1002), UDP 137. The message framing is DNS-like —
// the same 12-byte header and the same RR layout — but names are carried in
// NetBIOS "first-level encoding": the 16-byte NetBIOS name is split into
// nibbles, each nibble added to 'A', giving 32 ASCII bytes.
const (
	nbnsTypeNB     = 0x0020
	nbnsTypeNBSTAT = 0x0021

	// nbnsNameLen is the encoded length of a NetBIOS name: 16 raw bytes as 32
	// ASCII characters.
	nbnsNameLen = 32

	// nbnsMaxNames bounds the name table walked out of a node-status response.
	// A Windows host advertises a handful; a crafted response can claim 255.
	nbnsMaxNames = 16
)

// NetBIOS name suffixes worth taking as a host name. The suffix is the 16th
// byte of the name and says what the name IS:
//
//	0x00  workstation service — the machine name
//	0x20  server service      — the machine name again, as a file server
//
// Everything else is a group name, a browser election name, a messenger name
// or a domain name (0x1b, 0x1c, 0x1e…), none of which identifies this host.
// Taking them all is how a NetBIOS collector ends up naming every machine in
// the domain after the domain.
func nbnsSuffixIsHostName(suffix byte) bool {
	return suffix == 0x00 || suffix == 0x20
}

// DecodeNBNS extracts a host name and, from a node-status response, the
// adapter's hardware address.
//
// The node-status response (NBSTAT) is the valuable one: it carries the full
// name table AND the six-byte adapter "unit ID", which is the MAC. That makes
// NetBIOS the one legacy protocol that volunteers a MAC↔name binding for hosts
// that are two switches away and never ARP where the sensor can see it.
func DecodeNBNS(f Frame) (*HostObservation, error) {
	b := f.Payload
	if len(b) < dnsHeaderLen {
		return nil, ErrMalformed
	}
	flags, _ := be16(b, 2)
	if flags&0x8000 == 0 {
		// A query. As with DNS, the question section is not decoded.
		return nil, ErrNotApplicable
	}
	qd, _ := be16(b, 4)
	an, _ := be16(b, 6)

	off := dnsHeaderLen
	for i := 0; i < int(qd); i++ {
		var err error
		_, off, err = readNBNSName(b, off)
		if err != nil {
			return nil, err
		}
		if off+4 > len(b) {
			return nil, ErrMalformed
		}
		off += 4
	}

	obs := f.newObservation(SourceNBNS)
	obs.MAC = NormalizeMAC(f.SrcMAC)
	obs.addAddr(f.SrcAddr)

	found := false
	records := min(int(an), dnsMaxRecords)
	for i := 0; i < records && off < len(b); i++ {
		name, suffix, next, err := readNBNSNameWithSuffix(b, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(b) {
			return nil, ErrMalformed
		}
		rtype, _ := be16(b, off)
		rdlen, _ := be16(b, off+8)
		off += 10
		if off+int(rdlen) > len(b) {
			return nil, ErrMalformed
		}
		rdata := b[off : off+int(rdlen)]
		off += int(rdlen)

		switch rtype {
		case nbnsTypeNB:
			// rdata is a sequence of flags(2) + IPv4(4).
			if nbnsSuffixIsHostName(suffix) && name != "" {
				obs.addName(name)
				found = true
			}
			for j := 0; j+6 <= len(rdata); j += 6 {
				if a, ok := addrFromBytes(rdata[j+2 : j+6]); ok {
					obs.addAddr(a)
					found = true
				}
			}

		case nbnsTypeNBSTAT:
			if !decodeNBStat(rdata, obs) {
				continue
			}
			found = true
		}
	}

	if !found {
		return nil, ErrNotApplicable
	}

	obs.Finalize()
	if !obs.Identifies() {
		return nil, ErrNotApplicable
	}
	return obs, nil
}

// decodeNBStat reads a node-status response body:
//
//	numnames(1) then numnames × { name(15) suffix(1) flags(2) }
//	then the statistics block, whose first 6 bytes are the adapter's unit ID.
func decodeNBStat(rdata []byte, obs *HostObservation) bool {
	if len(rdata) < 1 {
		return false
	}
	count := int(rdata[0])
	if count > nbnsMaxNames {
		count = nbnsMaxNames
	}
	off := 1
	any := false
	for i := 0; i < count; i++ {
		if off+18 > len(rdata) {
			return any
		}
		raw := rdata[off : off+15]
		suffix := rdata[off+15]
		flags := rdata[off+16]
		off += 18
		// Bit 15 of the name flags (the high bit of the first flags byte) is
		// the group-name bit. A group name is a workgroup or domain, not this
		// machine.
		if flags&0x80 != 0 {
			continue
		}
		if !nbnsSuffixIsHostName(suffix) {
			continue
		}
		if name := normalizeName(strings.TrimRight(string(raw), " \x00")); name != "" {
			obs.addName(name)
			any = true
		}
	}
	// The statistics block follows the name table; its first field is the
	// 6-byte adapter unit ID. Only read when the whole field is present —
	// a truncated response must not contribute a half MAC.
	if off+6 <= len(rdata) {
		if mac := MACFromBytes(rdata[off : off+6]); mac != "" {
			// The in-protocol adapter ID outranks the Ethernet source address:
			// the frame may have been relayed, the unit ID names the adapter.
			obs.MAC = mac
			any = true
		}
	}
	return any
}

// readNBNSName decodes a NetBIOS name, discarding the suffix.
func readNBNSName(b []byte, off int) (string, int, error) {
	name, _, next, err := readNBNSNameWithSuffix(b, off)
	return name, next, err
}

// readNBNSNameWithSuffix decodes a first-level-encoded NetBIOS name and its
// suffix byte, following any DNS-style scope labels that trail it.
func readNBNSNameWithSuffix(b []byte, off int) (string, byte, int, error) {
	return readNBNSNameAt(b, off, 0)
}

// readNBNSNameAt is readNBNSNameWithSuffix carrying the compression-pointer
// jump count.
//
// The strictly-backwards rule below already makes a pointer LOOP impossible, so
// this counter is not closing an exploitable hole — the sensor's payload cap
// bounds the chain long before it matters. It is here because the DNS reader in
// this same package has both guards (dnsMaxJumps AND strictly-backwards) and
// this one had only the second, and two parsers of the same construct that
// disagree about what they refuse is how one of them ends up being the one that
// is wrong. The chain is also genuine recursion here rather than a loop, so a
// long backwards chain in a large buffer grows the stack in proportion to the
// message; the counter bounds that too.
func readNBNSNameAt(b []byte, off, jumps int) (string, byte, int, error) {
	if off < 0 || off >= len(b) {
		return "", 0, 0, ErrMalformed
	}
	l := int(b[off])
	if l&0xc0 == 0xc0 {
		// NetBIOS reuses DNS compression pointers for the scope. The pointed-at
		// name is decoded the same way.
		if off+2 > len(b) {
			return "", 0, 0, ErrMalformed
		}
		target := (l&0x3f)<<8 | int(b[off+1])
		// Strictly backwards, and bounded — the same pair of rules readDNSName
		// applies, spelled the same way.
		if jumps >= dnsMaxJumps || target >= off {
			return "", 0, 0, ErrMalformed
		}
		name, suffix, _, err := readNBNSNameAt(b, target, jumps+1)
		return name, suffix, off + 2, err
	}
	if l != nbnsNameLen {
		return "", 0, 0, ErrMalformed
	}
	if off+1+nbnsNameLen > len(b) {
		return "", 0, 0, ErrMalformed
	}
	decoded, suffix, ok := decodeNBNSLabel(b[off+1 : off+1+nbnsNameLen])
	if !ok {
		return "", 0, 0, ErrMalformed
	}
	off += 1 + nbnsNameLen

	// Skip the scope: zero or more ordinary DNS labels ending in a zero byte.
	for {
		if off >= len(b) {
			return "", 0, 0, ErrMalformed
		}
		sl := int(b[off])
		if sl == 0 {
			off++
			break
		}
		if sl&0xc0 == 0xc0 {
			if off+2 > len(b) {
				return "", 0, 0, ErrMalformed
			}
			off += 2
			break
		}
		if off+1+sl > len(b) {
			return "", 0, 0, ErrMalformed
		}
		off += 1 + sl
	}

	return decoded, suffix, off, nil
}

// decodeNBNSLabel reverses first-level encoding: each pair of ASCII bytes in
// 'A'..'P' carries one nibble.
func decodeNBNSLabel(enc []byte) (string, byte, bool) {
	if len(enc) != nbnsNameLen {
		return "", 0, false
	}
	var raw [16]byte
	for i := 0; i < 16; i++ {
		hi := enc[2*i]
		lo := enc[2*i+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return "", 0, false
		}
		raw[i] = (hi-'A')<<4 | (lo - 'A')
	}
	name := strings.TrimRight(string(raw[:15]), " \x00")
	return name, raw[15], true
}
