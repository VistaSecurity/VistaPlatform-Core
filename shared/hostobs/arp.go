package hostobs

// ARP packet layout (RFC 826), Ethernet/IPv4 case:
//
//	 0                   1                   2                   3
//	+-------------------------------+-------------------------------+
//	|          htype (2)            |          ptype (2)            |
//	+-------+-------+---------------+-------------------------------+
//	| hlen  | plen  |            oper (2)                           |
//	+-------+-------+-----------------------------------------------+
//	|                 sender hardware address (hlen)                |
//	|                 sender protocol address (plen)                |
//	|                 target hardware address (hlen)                |
//	|                 target protocol address (plen)                |
//	+---------------------------------------------------------------+
const (
	arpHTypeEthernet = 1
	arpPTypeIPv4     = 0x0800
	arpOpRequest     = 1
	arpOpReply       = 2
)

// DecodeARP extracts the MAC↔IP binding a host asserts about itself.
//
// Only the SENDER is recorded. The target fields of an ARP request are a
// question ("who has 10.0.0.5?") — the asker does not know the answer, and
// treating the target address as an observed host would inventory every
// address anybody ever looked for, including the ones nothing answers to.
//
// A sender protocol address of 0.0.0.0 is an ARP probe (RFC 5227): the host is
// asking whether an address it wants is free. The MAC is still real and is
// kept; no address is recorded, because the host does not have one yet.
//
// ARP produces no [Neighbor] entry. Passive ARP says a host is on this
// segment, not what it is attached to. The `arp` value in the registered
// net.neighbors fact is for device-interrogation reading a device's OWN ARP
// table, which really is a statement about that device's neighbours.
func DecodeARP(f Frame) (*HostObservation, error) {
	b := f.Payload
	if len(b) < 8 {
		return nil, ErrMalformed
	}
	htype, _ := be16(b, 0)
	ptype, _ := be16(b, 2)
	hlen := int(b[4])
	plen := int(b[5])
	oper, _ := be16(b, 6)

	if htype != arpHTypeEthernet || ptype != arpPTypeIPv4 || hlen != 6 || plen != 4 {
		// Token Ring, ATM, RARP-over-something — well-formed ARP variants we
		// do not decode rather than guess at.
		return nil, ErrNotApplicable
	}
	if oper != arpOpRequest && oper != arpOpReply {
		return nil, ErrNotApplicable
	}
	if len(b) < 8+2*(hlen+plen) {
		return nil, ErrMalformed
	}

	sha := b[8 : 8+hlen]
	spa := b[8+hlen : 8+hlen+plen]
	tpa := b[8+2*hlen+plen : 8+2*hlen+2*plen]

	obs := f.newObservation(SourceARP)
	obs.MAC = MACFromBytes(sha)
	if obs.MAC == "" {
		// A multicast or all-zero sender hardware address identifies nothing.
		return nil, ErrNotApplicable
	}

	senderAddr, ok := addrFromBytes(spa)
	if ok {
		obs.addAddr(senderAddr)
	}
	targetAddr, tok := addrFromBytes(tpa)

	// Gratuitous ARP: sender and target protocol addresses are the same, which
	// is a host announcing "this address is mine now" rather than asking about
	// somebody else's. It is the single most reliable passive signal that a
	// host has just come up or changed address.
	if ok && tok && senderAddr == targetAddr && !senderAddr.IsUnspecified() {
		obs.setAttr("arp_gratuitous", true)
	}
	if ok && senderAddr.IsUnspecified() {
		obs.setAttr("arp_probe", true)
	}
	switch oper {
	case arpOpRequest:
		obs.setAttr("arp_operation", "request")
	case arpOpReply:
		obs.setAttr("arp_operation", "reply")
	}

	obs.Finalize()
	if !obs.Identifies() {
		return nil, ErrNotApplicable
	}
	return obs, nil
}
