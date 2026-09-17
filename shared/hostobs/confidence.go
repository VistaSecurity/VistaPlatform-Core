package hostobs

// Confidence grades how directly the subject stated its own identity.
//
// It is the ONE ladder behind every host observation's confidence, wherever the
// observation was made:
//
//   - the live sensor stamps it on `CryptoDiscovery.Confidence`
//   - pcap-processor stamps it on the `sensor_discoveries` row
//   - inventory-service's consumer reads the stored value, and recomputes it
//     from the payload when a row carries none
//
// It lives here rather than in the sensor for the same reason the decoders and
// the classifier do: pcap-processor wrote a flat 0.85 for every row while the
// sensor graded 0.60–0.95, so the same capture replayed through the two
// runtimes produced two different confidences for one host — and an
// auto-approval rule reading `confidence >= 0.9` fired on one and not the
// other. Two spellings of one measurement is the failure this package exists
// to prevent.
//
// # The ladder
//
// A device advertising itself over LLDP or CDP, or asking a DHCP server for a
// lease by name, is telling us who it is in a message whose whole purpose is
// identity. An ARP or NetBIOS frame is the host speaking for itself too, but
// with less of its identity in one message. An mDNS announcement is the host
// speaking for itself about its SERVICES, and the name is incidental. A DNS
// answer is a third party's claim about a host that may not be on this segment
// at all, so it is graded lowest.
//
//	lldp, cdp, dhcp  0.95
//	arp, nbns        0.85
//	mdns             0.80
//	dns              0.60
//
// The best contributing source wins: a subject seen over both ARP and DHCP is
// graded on the DHCP exchange, because that is the strongest statement of
// identity we hold about it.
//
// An observation whose sources are all unrecognised grades 0.60 — the floor, not
// zero. Zero on this scale means NOT ASSESSED (the same convention risk scoring
// and `asset_facts.confidence` use), and a decoded frame HAS been assessed; it
// is simply the weakest thing we could have been told.
//
// The column is `numeric(3,2)`, and these are the only five values written.
func Confidence(o *HostObservation) float64 {
	if o == nil {
		return 0
	}
	best := 0.0
	for _, src := range o.sourcesOrSelf() {
		var c float64
		switch src {
		case SourceLLDP, SourceCDP, SourceDHCP:
			c = 0.95
		case SourceARP, SourceNBNS:
			c = 0.85
		case SourceMDNS:
			c = 0.80
			if o.Relayed() {
				// A reflected announcement is hearsay about a third party —
				// the same claim a resolver's answer makes — and grades
				// like one. See DecodeMDNS.
				c = 0.60
			}
		case SourceDNS:
			c = 0.60
		}
		if c > best {
			best = c
		}
	}
	if best == 0 {
		best = 0.60
	}
	return best
}

// sourcesOrSelf is Sources, falling back to the single Source when Finalize has
// not run. A caller grading a freshly-decoded observation should not have to
// know which of the two fields is populated.
func (o *HostObservation) sourcesOrSelf() []string {
	if len(o.Sources) > 0 {
		return o.Sources
	}
	if o.Source != "" {
		return []string{o.Source}
	}
	return nil
}
