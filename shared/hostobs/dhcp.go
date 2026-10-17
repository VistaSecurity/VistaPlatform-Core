package hostobs

import (
	"net/netip"
	"strings"
)

// DHCP / BOOTP fixed header (RFC 2131 §2):
//
//	op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
//	ciaddr(4) yiaddr(4) siaddr(4) giaddr(4)
//	chaddr(16) sname(64) file(128) magic(4) options(var)
const (
	dhcpFixedLen   = 236
	dhcpMagic      = 0x63825363
	dhcpOffCIAddr  = 12
	dhcpOffYIAddr  = 16
	dhcpOffCHAddr  = 28
	dhcpOptPad     = 0
	dhcpOptSubnet  = 1
	dhcpOptRouter  = 3
	dhcpOptEnd     = 255
	dhcpOptHostnm  = 12
	dhcpOptReqIP   = 50
	dhcpOptMsgType = 53
	dhcpOptParams  = 55
	dhcpOptVendor  = 60
	dhcpOptClientI = 61
	dhcpOptFQDN    = 81
	// dhcpOptAuth (RFC 3118) carries an HMAC over the message plus a key
	// identifier. It is the one standard DHCP option that holds credential
	// material, and it is skipped by number below — named here so the reason
	// is in the code and not only in the package doc.
	dhcpOptAuth = 90
)

// The attributes an ACK's lease options yield (DecodeDHCP).
const (
	// AttrDHCPSubnet is the leased address's network, CIDR ("192.0.2.0/24").
	AttrDHCPSubnet = "dhcp_subnet"
	// AttrDHCPPrefixLength is the leased address's configured length.
	AttrDHCPPrefixLength = "dhcp_prefix_length"
	// AttrDHCPRouter is the default gateway the server handed out.
	AttrDHCPRouter = "dhcp_router"
)

// maskBits is the length of a contiguous IPv4 netmask; a non-contiguous one
// is not a prefix and is refused.
func maskBits(mask []byte) (int, bool) {
	if len(mask) != 4 {
		return 0, false
	}
	m := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	bits := 0
	for m&0x80000000 != 0 {
		bits++
		m <<= 1
	}
	if m != 0 {
		return 0, false
	}
	return bits, true
}

var dhcpMessageTypes = map[byte]string{
	1: "discover", 2: "offer", 3: "request", 4: "decline",
	5: "ack", 6: "nak", 7: "release", 8: "inform",
}

// DecodeDHCP extracts the client's identity from a DHCP exchange.
//
// The SUBJECT is always the client, whichever direction the message travels:
// chaddr is the client's hardware address in a server's OFFER just as much as
// in the client's own REQUEST, and yiaddr in an OFFER/ACK is the address being
// given to that client. A DHCP server is therefore a rich source of
// observations about hosts that never talk to the sensor directly.
//
// Options are read from a positive allowlist. Everything not listed —
// including option 90, the RFC 3118 authentication option — is stepped over
// structurally, so an option this decoder has never seen cannot leak into the
// payload the way an assigned-whole-response object once leaked a UniFi mesh
// PSK.
func DecodeDHCP(f Frame) (*HostObservation, error) {
	b := f.Payload
	if len(b) < dhcpFixedLen+4 {
		return nil, ErrMalformed
	}
	magic, _ := be32(b, dhcpFixedLen)
	if magic != dhcpMagic {
		// BOOTP without the vendor-extension magic cookie: no options to read.
		return nil, ErrNotApplicable
	}
	htype := b[1]
	hlen := int(b[2])

	obs := f.newObservation(SourceDHCP)

	if htype == arpHTypeEthernet && hlen == 6 {
		obs.MAC = MACFromBytes(b[dhcpOffCHAddr : dhcpOffCHAddr+6])
	}

	ciaddr, _ := addrFromBytes(b[dhcpOffCIAddr : dhcpOffCIAddr+4])
	yiaddr, _ := addrFromBytes(b[dhcpOffYIAddr : dhcpOffYIAddr+4])

	var requestedIP netip.Addr
	var msgType byte
	var subnetMask []byte
	var router netip.Addr

	// Options are TLV: code(1) len(1) value(len), with 0 = pad (no length
	// byte) and 255 = end.
	for i := dhcpFixedLen + 4; i < len(b); {
		code := b[i]
		if code == dhcpOptPad {
			i++
			continue
		}
		if code == dhcpOptEnd {
			break
		}
		if i+2 > len(b) {
			return nil, ErrMalformed
		}
		length := int(b[i+1])
		if i+2+length > len(b) {
			return nil, ErrMalformed
		}
		val := b[i+2 : i+2+length]
		i += 2 + length

		switch code {
		case dhcpOptMsgType:
			if len(val) == 1 {
				msgType = val[0]
			}
		case dhcpOptHostnm, dhcpOptFQDN:
			name := string(val)
			if code == dhcpOptFQDN {
				// RFC 4702: flags(1) rcode1(1) rcode2(1) then the name, which
				// may be in DNS wire form. Only the plain-ASCII form is read;
				// the wire form is left alone rather than half-decoded.
				if len(val) <= 3 {
					continue
				}
				name = string(val[3:])
			}
			obs.addName(strings.TrimRight(name, "\x00"))
		case dhcpOptSubnet:
			// Subnet mask (RFC 2132 §3.3): the length of the network the
			// server leased the address on. Read only into the prefix below.
			if len(val) == 4 {
				subnetMask = val
			}
		case dhcpOptRouter:
			// Router list (RFC 2132 §3.5): the first is the default gateway.
			if len(val) >= 4 {
				if a, ok := addrFromBytes(val[:4]); ok {
					router = a
				}
			}
		case dhcpOptReqIP:
			if a, ok := addrFromBytes(val); ok {
				requestedIP = a
			}
		case dhcpOptVendor:
			// The vendor CLASS ("MSFT 5.0", "udhcp 1.30", "Cisco Systems, Inc.
			// IP Phone CP-8841") identifies the DHCP client software, not the
			// hardware manufacturer. It is a classification signal, never
			// hw.vendor — that fact is OUI-derived, resolved by the platform at
			// ingestion from the MAC, as the fact registry says.
			if v := boundIdentifier(string(val)); v != "" {
				obs.setAttr("dhcp_vendor_class", v)
			}
		case dhcpOptClientI:
			// Client identifier (RFC 2132 §9.14). Type 1 means "the value is
			// an Ethernet MAC"; anything else is an opaque vendor blob (a DUID,
			// a serial, a subscriber id) that is not ours to store.
			if len(val) == 7 && val[0] == arpHTypeEthernet {
				if mac := MACFromBytes(val[1:]); mac != "" && obs.MAC == "" {
					obs.MAC = mac
				}
			}
		case dhcpOptParams:
			// The parameter request list is the DHCP fingerprint: the ORDER
			// and set of options a client asks for is characteristic of its OS
			// (this is what Fingerbank matches on). Numbers only, bounded.
			if len(val) == 0 {
				continue
			}
			n := min(len(val), MaxDHCPParams)
			params := make([]int, 0, n)
			for _, p := range val[:n] {
				params = append(params, int(p))
			}
			obs.setAttr("dhcp_param_request_list", params)
		case dhcpOptAuth:
			// Deliberately ignored: RFC 3118 authentication information.
		}
	}

	// Address precedence, strongest statement first:
	//   yiaddr  — the server has ASSIGNED this address to this client
	//   ciaddr  — the client says it currently HOLDS this address
	//   opt 50  — the client would LIKE this address; it may not get it
	// Only one is taken, so a DISCOVER's wish is never recorded as a binding.
	switch {
	case yiaddr.IsValid() && !yiaddr.IsUnspecified():
		obs.addAddr(yiaddr)
	case ciaddr.IsValid() && !ciaddr.IsUnspecified():
		obs.addAddr(ciaddr)
	case requestedIP.IsValid() && !requestedIP.IsUnspecified():
		obs.addAddr(requestedIP)
		obs.setAttr("dhcp_address_requested_only", true)
	}

	if name, ok := dhcpMessageTypes[msgType]; ok {
		obs.setAttr("dhcp_message_type", name)
	}

	// The network the lease is on. Only a server's ACK states it: the address
	// is then committed to the client, and the subnet-mask option is the
	// server's statement of the prefix it hands addresses out of — a
	// measurement of the NETWORK by the network's own DHCP service, which is
	// what makes the platform record the prefix as DHCP-managed (DCIM row
	// 1.5e). An OFFER the client may decline, and a client's own REQUEST
	// carries no mask.
	if msgType == 5 && yiaddr.IsValid() && !yiaddr.IsUnspecified() && yiaddr.Is4() {
		if bits, ok := maskBits(subnetMask); ok && bits > 0 && bits < 32 {
			obs.setAttr(AttrDHCPSubnet, netip.PrefixFrom(yiaddr, bits).Masked().String())
			obs.setAttr(AttrDHCPPrefixLength, bits)
			if router.IsValid() && !router.IsUnspecified() {
				obs.setAttr(AttrDHCPRouter, router.String())
			}
		}
	}

	obs.Finalize()
	if !obs.Identifies() {
		return nil, ErrNotApplicable
	}
	return obs, nil
}
