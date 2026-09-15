package hostobs

import (
	"errors"
	"net/netip"
	"time"
)

// ErrNotApplicable is returned by a decoder when the bytes are well-formed but
// carry nothing this package collects: a DNS query rather than an answer, an
// mDNS message whose only records are TXT, an LLDP frame with nothing but a
// TTL.
//
// It also covers a TRUNCATED message whose surviving prefix held nothing —
// where the frame was cut short (the sensor caps captured payloads) rather than
// contradicting itself. That is deliberately not [ErrMalformed]: we cut the
// packet off, the speaker did nothing wrong, and counting it as malformed
// reports a broken device on the segment. See parseDNSMessage.
//
// It is distinct from a parse error on purpose. "This frame said nothing we
// record" and "this frame was malformed" are different facts about the
// segment, and a caller that counts them together cannot tell a quiet network
// from a broken decoder.
var ErrNotApplicable = errors.New("hostobs: frame carries no host observation")

// ErrMalformed is returned when the bytes do not parse as the protocol the
// decoder was told they are. Callers count these; they never panic.
var ErrMalformed = errors.New("hostobs: malformed frame")

// Frame is the already-parsed context a decoder needs from the layers beneath
// it. It exists so the decoders can stay free of gopacket and of CGO: the
// caller has a parsed packet, the decoder wants six fields out of it.
type Frame struct {
	// Payload is the protocol body: the ARP packet for [DecodeARP], the UDP
	// payload for [DecodeDHCP] / [DecodeMDNS] / [DecodeNBNS] / [DecodeDNS],
	// the LLDPDU for [DecodeLLDP], the CDP body after the LLC/SNAP header for
	// [DecodeCDP] (see [CDPFromLLCSNAP]).
	Payload []byte

	// SrcMAC is the Ethernet source address of the frame, in any common
	// spelling; "" when unknown. It is the subject's MAC for every decoder
	// except ARP and DHCP, which carry the hardware address inside the
	// protocol and are trusted over the Ethernet header.
	SrcMAC string

	// SrcAddr is the IP source of the frame; the zero Addr for a frame with no
	// IP layer (ARP, LLDP, CDP).
	SrcAddr netip.Addr

	// Interface is the capture interface the frame arrived on, or "" when the
	// runtime has no name for it (a pcap file). It is recorded as the
	// `capture_interface` attribute — provenance for where the observation was
	// made, NOT a statement that the subject is attached to that interface.
	// A mirror or SPAN port carries frames from links the sensor is not on.
	Interface string

	// At is the capture timestamp. A zero value is replaced with time.Now() by
	// the decoder, because an observation with no time cannot be aged out.
	At time.Time
}

func (f Frame) at() time.Time {
	if f.At.IsZero() {
		return time.Now().UTC()
	}
	return f.At.UTC()
}

// newObservation starts an observation with the frame's context applied.
func (f Frame) newObservation(source string) *HostObservation {
	obs := &HostObservation{
		ObservedAt: f.at(),
		Source:     source,
	}
	if iface := boundIdentifier(f.Interface); iface != "" {
		obs.setAttr("capture_interface", iface)
	}
	return obs
}

// be16 reads a big-endian uint16 at off, reporting whether it fit.
func be16(b []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(b) {
		return 0, false
	}
	return uint16(b[off])<<8 | uint16(b[off+1]), true
}

// be32 reads a big-endian uint32 at off, reporting whether it fit.
func be32(b []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(b) {
		return 0, false
	}
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3]), true
}

// addrFromBytes builds a netip.Addr from 4 or 16 raw octets.
func addrFromBytes(b []byte) (netip.Addr, bool) {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)), true
	case 16:
		return netip.AddrFrom16([16]byte(b)).Unmap(), true
	}
	return netip.Addr{}, false
}
