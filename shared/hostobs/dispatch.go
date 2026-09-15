package hostobs

// Dispatch: which frame goes to which decoder, and what a capture filter has to
// admit for those frames to arrive at all.
//
// This lives beside the decoders rather than in each runtime because SHARED
// DECODE CODE WITH PER-RUNTIME DISPATCH is a bug this codebase has already paid
// for twice. The OT probers were shared while the decision of when to run them
// was not, so the UDP probers ended up gated on an open TCP port and reported a
// clean bill of health for devices nobody had asked (then again).
// The sensor and pcap-processor each have their own gopacket plumbing — that
// part is unavoidable — but neither of them decides which protocol matters or
// which port it is on.
//
// gopacket is deliberately NOT imported here. Adding it to the shared module
// would put a packet library in the dependency graph of nineteen services that
// will never decode a frame. The runtimes pass primitives instead: an
// EtherType, two UDP ports. That is the whole of what the decision needs, and
// keeping the signature at that level is what lets this package stay pure Go.

// EtherType values the link-layer classifier recognises.
const (
	// EtherTypeARP is 0x0806.
	EtherTypeARP = 0x0806
	// EtherTypeLLDP is 0x88cc.
	EtherTypeLLDP = 0x88cc
	// EtherTypeMaxLength is the boundary between an 802.3 length field and an
	// EtherType (IEEE 802.3 clause 3.2.6). At or below it the field is a
	// length and an LLC/SNAP header follows, which is where CDP lives.
	EtherTypeMaxLength = 1500
)

// UDP ports the transport classifier recognises.
const (
	PortDHCPServer = 67
	PortDHCPClient = 68
	PortNBNS       = 137
	PortMDNS       = 5353
	PortDNS        = 53
)

// Kind names the decoder a classified frame belongs to.
type Kind uint8

// Decoder kinds. KindNone means "not a frame this package decodes".
const (
	KindNone Kind = iota
	KindARP
	KindDHCP
	KindMDNS
	KindNBNS
	KindDNS
	KindLLDP
	KindCDP
)

// String renders a Kind as its Source constant, for logs and metrics.
func (k Kind) String() string {
	switch k {
	case KindARP:
		return SourceARP
	case KindDHCP:
		return SourceDHCP
	case KindMDNS:
		return SourceMDNS
	case KindNBNS:
		return SourceNBNS
	case KindDNS:
		return SourceDNS
	case KindLLDP:
		return SourceLLDP
	case KindCDP:
		return SourceCDP
	}
	return "none"
}

// ClassifyEther decides what an Ethernet frame's payload is, from its EtherType
// alone plus, for the 802.3 case, a look at the LLC/SNAP header.
//
// The returned payload is a sub-slice of ethPayload and is NOT copied — a
// caller that hands the frame to another goroutine must copy it first, because
// libpcap reuses the buffer these bytes live in.
func ClassifyEther(etherType uint16, ethPayload []byte) (Kind, []byte) {
	switch {
	case etherType == EtherTypeLLDP:
		return KindLLDP, ethPayload
	case etherType == EtherTypeARP:
		return KindARP, ethPayload
	case etherType <= EtherTypeMaxLength:
		// 802.3 framing. CDP is the only LLC/SNAP protocol decoded here, and
		// the SNAP header validates itself, so no destination-MAC check is
		// needed to tell it apart from IPX or STP.
		if body, ok := CDPFromLLCSNAP(ethPayload); ok {
			return KindCDP, body
		}
	}
	return KindNone, nil
}

// ClassifyUDP decides what a UDP payload is from its ports. Either direction
// counts: a DHCP OFFER travels server→client and a DNS answer server→resolver,
// and both name a host.
func ClassifyUDP(srcPort, dstPort uint16) Kind {
	for _, p := range [2]uint16{srcPort, dstPort} {
		switch p {
		case PortDHCPServer, PortDHCPClient:
			return KindDHCP
		case PortMDNS:
			return KindMDNS
		case PortNBNS:
			return KindNBNS
		case PortDNS:
			return KindDNS
		}
	}
	return KindNone
}

// Decode runs the decoder for a kind.
//
// The switch is here rather than in each runtime for the same reason the
// classification is: a decoder added to this package but wired into only one of
// the two capture paths is a decoder the other silently never runs.
func Decode(kind Kind, f Frame) (*HostObservation, error) {
	switch kind {
	case KindARP:
		return DecodeARP(f)
	case KindDHCP:
		return DecodeDHCP(f)
	case KindMDNS:
		return DecodeMDNS(f)
	case KindNBNS:
		return DecodeNBNS(f)
	case KindDNS:
		return DecodeDNS(f)
	case KindLLDP:
		return DecodeLLDP(f)
	case KindCDP:
		return DecodeCDP(f)
	}
	return nil, ErrNotApplicable
}

// Config selects which of this package's decoders a runtime runs.
//
// It lives here, beside the classifier and the BPF terms, for the same reason
// the dispatch does: a decoder switched off in one runtime's plumbing and left
// on in the other's is exactly the shape that gated the OT UDP probers on an
// open TCP port. A runtime states its Config once and this package decides both
// what the capture filter asks for and what the classifier admits.
//
// The zero value is the DEFAULT set — everything except DNS.
type Config struct {
	// DNS enables the unicast-DNS decoder on UDP 53. OFF by default, and
	// opt-in per sensor, for two reasons that both point the same way:
	//
	//   Volume. UDP 53 on a busy segment is orders of magnitude more packets
	//   than every other protocol here put together, and each one has to reach
	//   the worker pool before anything can decide it is uninteresting.
	//
	//   Privacy. The decoder reads ANSWERS only and never the question
	//   section — but an answer names what was asked. A stream of A-record
	//   answers is a record of which names this network resolved, which is a
	//   materially different collection from "these devices are on this
	//   segment", and it should be a decision somebody made rather than a
	//   default they inherited.
	//
	// mDNS (5353) is unaffected: a multicast announcement is a device
	// advertising itself, not a lookup somebody performed.
	DNS bool
}

// Enabled reports whether a classified kind should be decoded under c.
//
// Both capture runtimes call this after classification and before Decode, so
// a kind that is filtered out of the BPF expression is also refused if it
// arrives by some other route — a pcap file, a filter an operator widened by
// hand, a second decoder's port overlapping.
func (c Config) Enabled(k Kind) bool {
	if k == KindDNS {
		return c.DNS
	}
	return k != KindNone
}

// BPFTerms are the capture-filter terms the frames this package decodes need
// under c, as `or`-able libpcap expressions.
//
// A live sensor's filter is a list of crypto ports; ARP, LLDP and CDP are not
// even IP. Enabling the decoders without widening the filter gives a pipeline
// that runs, reports success and never sees a frame — so the terms are derived
// from the same constants the classifier uses, and TestBPFTermsCoverEveryKind
// fails if a kind is added without one.
//
// A pcap FILE needs no filter: the capture is already on disk and everything in
// it is offered to the classifier. This is a live-capture concern only — but
// [Config.Enabled] still applies there, so a file's DNS packets are skipped for
// the same reasons a live segment's are.
func BPFTerms(c Config) []string {
	terms := []string{
		"arp",
		"udp port 67",
		"udp port 68",
		"udp port 5353",
		"udp port 137",
		// LLDP's EtherType.
		"ether proto 0x88cc",
		// CDP is 802.3/SNAP framed, so there is no EtherType to match on; its
		// well-known multicast destination is the only handle BPF has.
		"ether dst 01:00:0c:cc:cc:cc",
	}
	// Asked for only when the decoder is on. The filter is the cheapest place
	// to shed DNS — a packet the kernel never copies costs nothing at all,
	// where one refused after classification has already crossed into
	// userspace and through the worker pool.
	if c.DNS {
		terms = append(terms, "udp port 53")
	}
	return terms
}
