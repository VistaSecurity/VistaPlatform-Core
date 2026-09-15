package hostobs

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// Source values. These are the wire values of HostObservation.Source and of
// every element of HostObservation.Sources; the wire contract
// (docsv4/internal/developer/architecture/discovery-host-observation.md)
// documents them as a closed set.
const (
	SourceARP  = "arp"
	SourceDHCP = "dhcp"
	SourceMDNS = "mdns"
	SourceNBNS = "nbns"
	SourceDNS  = "dns"
	SourceLLDP = "lldp"
	SourceCDP  = "cdp"
)

// Bounds. Every one of these caps something an attacker on the segment
// controls the size of. They are deliberately small: an inventory needs a
// host's names, not every name it has ever answered to.
const (
	// MaxAddresses is the number of distinct IP addresses kept per subject.
	MaxAddresses = 8
	// MaxHostnames is the number of distinct short names kept per subject.
	MaxHostnames = 8
	// MaxFQDNs is the number of distinct fully-qualified names kept per subject.
	MaxFQDNs = 8
	// MaxServices is the number of mDNS service types kept per subject.
	MaxServices = 16
	// MaxNameLen is the longest name kept, matching the DNS limit (RFC 1035).
	MaxNameLen = 253
	// MaxDescriptionLen bounds free-text device fields — the LLDP system
	// description and the CDP software version. Those carry a multi-line
	// banner (a full IOS version block runs to several kilobytes); we keep
	// enough to identify the platform and drop the rest.
	MaxDescriptionLen = 256
	// MaxIdentifierLen bounds structured-but-vendor-chosen identifiers: an
	// LLDP port ID, a CDP port ID, a DHCP vendor class.
	MaxIdentifierLen = 128
	// MaxCapabilities bounds the decoded LLDP/CDP capability name list.
	MaxCapabilities = 16
	// MaxDHCPParams bounds the DHCP parameter-request-list fingerprint.
	MaxDHCPParams = 64
)

// Why this package emits no `net.neighbors` fact.
//
// An LLDP or CDP advertisement proves the ADVERTISER exists, and that is the
// whole of what a passive capture measures. It does NOT establish an adjacency
// between the advertiser and the host the sensor runs on: a sensor is normally
// fed by a mirror or SPAN port, so the frame reached the capture interface by
// being copied there, not by arriving over the link the fact would describe.
// Recording "advertiser ←→ sensor host" from that would attach a fabricated
// edge to the sensor's asset, and mirror placement makes the misattribution the
// common case rather than the edge one.
//
// So the advertiser is emitted as its own [HostObservation] — chassis MAC,
// system name, management address, OUI vendor, and the model when the frame
// states one — with Source "lldp" or "cdp". `net.neighbors` stays what it
// already was: a fact device-interrogation writes after reading a device's OWN
// LLDP, CDP or ARP table, which really is a statement about that device's
// neighbours.

// HostObservation is one passive statement that a host exists, with whatever
// identity the frame carried. It is the payload of a `host_observation`
// discovery; see the wire contract for the consumer's obligations.
//
// Empty fields mean "not observed", never "observed as empty". Nothing here is
// written unconditionally, which is what lets [Coalesce] merge two
// observations without an empty value erasing a populated one — the same rule
// the discovery metadata envelope keeps (CLAUDE.md, "empty never wins").
type HostObservation struct {
	// ObservedAt is the capture timestamp of the frame the observation came
	// from, not the time it was decoded or sent.
	ObservedAt time.Time `json:"observed_at"`

	// MAC is the subject's hardware address, lowercase colon-separated. Empty
	// when the frame carried no usable one.
	MAC string `json:"mac,omitempty"`

	// MACLocallyAdministered records that MAC has the locally-administered bit
	// set — a randomised phone/laptop Wi-Fi address, a virtual NIC, or a
	// deliberately spoofed one. It is NOT a stable identifier: keying an asset
	// on it produces a new asset every time the device rotates its address.
	// Recorded explicitly rather than left to the consumer to work out,
	// because an explicit false is an answer and a missing field is not.
	MACLocallyAdministered bool `json:"mac_locally_administered,omitempty"`

	// Addresses are the IP addresses bound to the subject, in observation
	// order, bounded by MaxAddresses.
	Addresses []netip.Addr `json:"addresses,omitempty"`

	// Hostnames are short names (no dot) the subject answers to.
	Hostnames []string `json:"hostnames,omitempty"`

	// FQDNs are fully-qualified names (at least one dot) the subject answers
	// to, with the trailing root dot stripped.
	FQDNs []string `json:"fqdns,omitempty"`

	// Vendor is the OUI-registered manufacturer of MAC. Empty when the prefix
	// is not in the compiled table or MAC is locally administered.
	Vendor string `json:"vendor,omitempty"`

	// Model is the hardware model the subject STATED — the CDP platform TLV,
	// the LLDP-MED inventory model-name TLV. Empty when the frame named none;
	// it is never inferred from a banner, an OUI or a capability bitmask,
	// because a model guessed from a free-text description is a fabricated
	// measurement and this key joins the hardware end-of-support catalogue.
	Model string `json:"model,omitempty"`

	// Source is the decoder that produced this observation. After [Coalesce]
	// it is the source that first identified the subject; Sources lists them
	// all.
	Source string `json:"source"`

	// Sources is every decoder that contributed to a coalesced observation,
	// sorted. A single-decoder observation carries just its own source.
	Sources []string `json:"sources,omitempty"`

	// Services are mDNS service types the subject advertises ("_ipp._tcp").
	Services []string `json:"services,omitempty"`

	// Attributes are decoder-specific classification signals that are NOT
	// registered facts: the DHCP vendor class and parameter-request
	// fingerprint, the LLDP/CDP capability bits, the CDP platform string, the
	// ARP gratuitous flag. They are evidence for the classifier and for a
	// human reading the row, not statements the platform stores as facts.
	//
	// Values are restricted to JSON scalars, []string and []int by
	// construction — every writer is in this package.
	Attributes map[string]any `json:"attributes,omitempty"`

	// Facts are the REGISTERED fact keys this observation supports, derived
	// from the typed fields above by [HostObservation.Finalize]. Only keys the
	// `sensor` producer may write appear here (standards/fact-keys.yaml); the
	// consumer writes them to asset_facts as-is.
	Facts map[string]any `json:"facts,omitempty"`
}

// Finalize normalises, bounds and derives. Every decoder ends with it, and
// [Coalesce] re-runs it on the merged result, so the invariants hold in one
// place rather than seven.
func (o *HostObservation) Finalize() {
	o.MAC = NormalizeMAC(o.MAC)
	if o.MAC != "" {
		o.MACLocallyAdministered = macLocallyAdministered(o.MAC)
		if o.Vendor == "" {
			o.Vendor = VendorForMAC(o.MAC)
		}
	}

	o.Addresses = boundAddrs(o.Addresses, MaxAddresses)
	o.Hostnames = boundStrings(o.Hostnames, MaxHostnames)
	o.FQDNs = boundStrings(o.FQDNs, MaxFQDNs)
	o.Services = boundStrings(o.Services, MaxServices)
	o.Model = boundIdentifier(o.Model)
	if len(o.Sources) == 0 && o.Source != "" {
		o.Sources = []string{o.Source}
	} else {
		o.Sources = boundStrings(o.Sources, 8)
		sort.Strings(o.Sources)
	}
	if len(o.Attributes) == 0 {
		o.Attributes = nil
	}

	o.Facts = o.buildFacts()
}

// buildFacts derives the registered-key map. The keys here are exactly those
// standards/fact-keys.yaml lists the `sensor` producer for, and
// TestFactsAreRegisteredAndWritable asserts that — a key added here that the
// registry does not permit is rejected at the consumer's write, silently
// losing the fact, so the test is the guard.
func (o *HostObservation) buildFacts() map[string]any {
	f := make(map[string]any, 3)
	if o.Vendor != "" {
		f[facts.KeyHWVendor] = o.Vendor
	}
	if o.Model != "" {
		f[facts.KeyHWModel] = o.Model
	}
	if len(o.Services) > 0 {
		f[facts.KeyNetMdnsServices] = o.Services
	}
	if len(f) == 0 {
		return nil
	}
	return f
}

// Key is the identity this observation is coalesced on: MAC first, then the
// first address, then the first fully-qualified name. Returns "" when the
// observation identifies nothing, which is the caller's signal to drop it.
func (o *HostObservation) Key() string {
	if o.MAC != "" {
		return "mac:" + o.MAC
	}
	if len(o.Addresses) > 0 {
		return "ip:" + o.Addresses[0].String()
	}
	if len(o.FQDNs) > 0 {
		return "fqdn:" + o.FQDNs[0]
	}
	if len(o.Hostnames) > 0 {
		return "host:" + o.Hostnames[0]
	}
	return ""
}

// Identifies reports whether the observation carries any identity worth
// sending. A frame that parses cleanly but names nothing is dropped rather
// than stored as an asset with no identifiers.
func (o *HostObservation) Identifies() bool {
	return o.Key() != ""
}

// setAttr records a classification signal, creating the map on first use.
func (o *HostObservation) setAttr(k string, v any) {
	if o.Attributes == nil {
		o.Attributes = make(map[string]any, 4)
	}
	o.Attributes[k] = v
}

// addAddr appends an address if it is usable and not already present.
//
// The unspecified address is rejected: a DHCP DISCOVER carries ciaddr
// 0.0.0.0, and recording it as "an address this host has" would make every
// booting client on the segment share one.
func (o *HostObservation) addAddr(a netip.Addr) {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return
	}
	a = a.Unmap().WithZone("")
	for _, existing := range o.Addresses {
		if existing == a {
			return
		}
	}
	if len(o.Addresses) >= MaxAddresses {
		return
	}
	o.Addresses = append(o.Addresses, a)
}

// addName files a name under Hostnames or FQDNs by whether it is qualified,
// and derives the short name from a plain qualified host name.
//
// A name whose first label starts with an underscore is a DNS-SD service
// label ("_ipp._tcp.local"), not a host name, so no short name is derived
// from it — otherwise every printer on the segment would be named "_ipp".
func (o *HostObservation) addName(raw string) {
	name := normalizeName(raw)
	if name == "" {
		return
	}
	if !strings.Contains(name, ".") {
		o.addHostname(name)
		return
	}
	o.addFQDN(name)
	first, _, _ := strings.Cut(name, ".")
	if first != "" && !strings.HasPrefix(first, "_") {
		o.addHostname(first)
	}
}

func (o *HostObservation) addHostname(n string) {
	if n == "" || len(o.Hostnames) >= MaxHostnames {
		return
	}
	for _, existing := range o.Hostnames {
		if existing == n {
			return
		}
	}
	o.Hostnames = append(o.Hostnames, n)
}

func (o *HostObservation) addFQDN(n string) {
	if n == "" || len(o.FQDNs) >= MaxFQDNs {
		return
	}
	for _, existing := range o.FQDNs {
		if existing == n {
			return
		}
	}
	o.FQDNs = append(o.FQDNs, n)
}

func (o *HostObservation) addService(svc string) {
	if svc == "" || len(o.Services) >= MaxServices {
		return
	}
	for _, existing := range o.Services {
		if existing == svc {
			return
		}
	}
	o.Services = append(o.Services, svc)
}

// --- normalisation helpers -------------------------------------------------

// NormalizeMAC renders a hardware address as lowercase colon-separated hex, or
// "" when the input is not a usable 6-octet unicast address.
//
// Broadcast and multicast addresses are rejected: they are destinations, never
// the identity of a host, and an ARP frame whose sender hardware address is
// ff:ff:ff:ff:ff:ff is malformed or forged either way.
func NormalizeMAC(s string) string {
	if s == "" {
		return ""
	}
	var b [6]byte
	n := 0
	hi := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = int(c-'A') + 10
		case c == ':' || c == '-' || c == '.':
			continue
		default:
			return ""
		}
		if hi < 0 {
			hi = v
			continue
		}
		if n >= 6 {
			return ""
		}
		b[n] = byte(hi<<4 | v)
		n++
		hi = -1
	}
	if n != 6 || hi >= 0 {
		return ""
	}
	return MACFromBytes(b[:])
}

// MACFromBytes renders 6 octets as a lowercase colon-separated address, or ""
// for a wrong-length, all-zero, broadcast or multicast address.
func MACFromBytes(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	if b[0]&0x01 != 0 {
		// Multicast/broadcast bit — a destination, not an identity.
		return ""
	}
	allZero := true
	for _, c := range b {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}

// macLocallyAdministered reports the U/L bit of a normalised MAC.
func macLocallyAdministered(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	v, ok := hexByte(mac[0], mac[1])
	return ok && v&0x02 != 0
}

func hexByte(hi, lo byte) (byte, bool) {
	h, ok1 := hexVal(hi)
	l, ok2 := hexVal(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// normalizeName lowercases a DNS or NetBIOS name, strips the trailing root
// dot, enforces the length bound, and rejects anything with a byte outside the
// printable ASCII a host name may hold. Rejecting rather than escaping is
// deliberate: a name with a control byte in it is not a name we should be
// storing as an identifier, and escaping would invent one that never existed.
func normalizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > MaxNameLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f {
			return ""
		}
	}
	return strings.ToLower(s)
}

// boundText truncates a free-text device field and strips any PEM private-key
// block inside it.
//
// Truncation happens AFTER redaction, not before: cutting a PEM block in half
// first would leave a fragment with no END line, which TextPEM's regex cannot
// match, and the fragment would ship. The two orderings differ only on exactly
// the input that matters.
func boundText(s string) string {
	s = redact.TextPEM(s)
	s = strings.TrimSpace(s)
	if len(s) > MaxDescriptionLen {
		s = strings.TrimSpace(s[:MaxDescriptionLen])
	}
	return sanitizeText(s)
}

// boundIdentifier truncates a structured-but-vendor-chosen identifier.
func boundIdentifier(s string) string {
	s = redact.TextPEM(s)
	s = strings.TrimSpace(s)
	if len(s) > MaxIdentifierLen {
		s = strings.TrimSpace(s[:MaxIdentifierLen])
	}
	return sanitizeText(s)
}

// sanitizeText replaces control bytes with a space and collapses the result.
// Unlike a host name, a description IS free text — dropping it entirely
// because one byte is a tab would lose a useful platform string — so here we
// clean rather than reject.
func sanitizeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			c = ' '
		}
		if c == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

func boundStrings(in []string, max int) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, min(len(in), max))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func boundAddrs(in []netip.Addr, max int) []netip.Addr {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[netip.Addr]struct{}, len(in))
	out := make([]netip.Addr, 0, min(len(in), max))
	for _, a := range in {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap().WithZone("")
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
		if len(out) >= max {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
