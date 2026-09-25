package deviceinterrogation

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/redact"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// Ops facts and observed relationships (asset-inventory ADR-0004 D1,
// ADR-0003 D2).
//
// An interrogation already retrieves most of what a general asset inventory
// needs and throws it away at projection: UniFi's networkconf carries every
// VLAN and is filtered to VPNs, its device objects carry uplinks, port tables
// and LLDP neighbours; PAN-OS system info was fetched and discarded whole; SNMP
// asked four OIDs. These two lists are where that data now leaves a collector.
//
// The rules, in order of how easily they are lost:
//
//  1. A fact key must be REGISTERED (standards/fact-keys.yaml → shared/facts).
//     An unregistered key is rejected at emit time, because a key nobody
//     declared is a key no consumer can type, and asset_facts has no CHECK
//     constraint to catch it later.
//  2. A relationship type must be in the canonical ten (shared/relationships).
//  3. Both go through [Sanitize] like everything else a collector emits, so a
//     secret that reaches a fact value or an edge attribute is still masked by
//     the backstop. Collectors project onto allowlists first — that is the real
//     defence — but the backstop is what covers the vendor field nobody has
//     seen yet.
//
// This is collection only. Turning these observations into asset_facts and
// asset_relationships rows is the phase-1/2 ingest workstream; nothing here
// writes to a database or knows a tenant exists.

// Fact keys this package emits, aliased from the generated registry
// (standards/fact-keys.yaml → shared/facts). Collectors below use these names;
// the aliases are what makes a key a compile-time reference to the registry
// rather than a string literal nobody checks.
const (
	factOSName            = facts.KeyOSName
	factOSVersion         = facts.KeyOSVersion
	factHWVendor          = facts.KeyHWVendor
	factHWModel           = facts.KeyHWModel
	factHWSerial          = facts.KeyHWSerial
	factHWFirmwareVersion = facts.KeyHWFirmwareVersion
	factNetUptimeSeconds  = facts.KeyNetUptimeSeconds
	factNetInterfaces     = facts.KeyNetInterfaces
	factNetNeighbors      = facts.KeyNetNeighbors
	factNetVlans          = facts.KeyNetVlans
	factMgmtProtocol      = facts.KeyMgmtProtocol
	factMgmtPlaintext     = facts.KeyMgmtPlaintext

	// factNetRouteNextHopCount is the ONLY thing any collector may record about
	// a routing table (ADR-0004 D1: "routes summarised as next-hop count"). The
	// prefixes and the next-hop addresses are never stored.
	factNetRouteNextHopCount = facts.KeyNetRouteNextHopCount
)

// Relationship types this package emits, aliased from the canonical vocabulary
// (shared/relationships, ADR-0003 D2) for the same reason.
const (
	relTypeConnectsTo = string(relationships.ConnectsTo)
	relTypeMemberOf   = string(relationships.MemberOf)
	// relTypeDependsOn is measurable in exactly one place today: a load
	// balancer's own configuration, which STATES that a virtual server forwards
	// to a pool's members (ADR-0004 D1 (5)). A dependency inferred from the
	// pattern of observed flows is inferred, not measured, and enters as a
	// proposal instead.
	relTypeDependsOn = string(relationships.DependsOn)
)

// Confidence levels for a fact observation. They are not a probability — they
// are how directly the value was measured, which is what the reconciliation
// precedence needs when two collectors disagree.
const (
	// ConfidenceReported is a value the device stated about itself: a serial
	// from entPhysicalTable, an interface from `show interface all`.
	ConfidenceReported = 1.0
	// ConfidenceDerived is a value we computed from something the device
	// stated: a vendor resolved from a sysObjectID enterprise number, an asset
	// class implied by a device type. Right far more often than not, but a
	// mapping we maintain rather than an answer the device gave.
	ConfidenceDerived = 0.8
)

// Identifier kinds a collector may attach to a peer. These are the subset of
// the ten kinds of ADR-0002 D3 that a collector can observe — five of them
// about a NEIGHBOUR, which is all a device ever learns about one, plus
// agent_id, which a collector may state only about ITSELF.
//
// They are spelled here rather than imported from shared/identity on purpose:
// this package is vendored into the standalone agent binary and must stay free
// of the platform-runtime dependencies shared/identity carries. The spelling
// and the normalisation below are pinned to shared/identity by
// TestPeerIdentifierKindsMatchIdentityRegistry, so the two cannot drift.
const (
	IdentifierSerialNumber = "serial_number"
	IdentifierMACAddress   = "mac_address"
	IdentifierFQDN         = "fqdn"
	IdentifierHostname     = "hostname"
	IdentifierIPAddress    = "ip_address"
	// IdentifierAgentID is the reporting agent's own installation id, and it is
	// the ONE kind here that is never a claim about somebody else. An
	// interrogator must not attach it to a neighbour: it identifies the host
	// the agent is installed on, and stamping it on another device would give
	// two assets one identity. Host inventory in LOCAL mode is its only
	// producer (shared/hostinventory), where the subject IS the agent's host.
	IdentifierAgentID = "agent_id"
)

// FactObservation is one registered fact a collector measured about a subject.
//
// Value must satisfy facts.ValidateValue for Key: the registry owns the type,
// and a fact whose value does not match its declared type reads back as
// something no consumer can use. Array-valued facts are emitted as
// []map[string]any rather than typed structs so that [Sanitize] can walk
// inside them — the redactor has no reflection fallback, by design, so a typed
// struct would be structurally invisible to it.
type FactObservation struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
	// Confidence is how directly the value was measured, in (0, 1].
	Confidence float64 `json:"confidence"`
	// Subject names the asset the fact is about. The zero value means the
	// interrogated device itself.
	//
	// It exists because an interrogation is not always about one asset: a UniFi
	// controller reports the interfaces, uptime and serial of every device it
	// manages, and attributing a switch's port table to the controller would be
	// a worse answer than not collecting it.
	Subject PeerRef `json:"subject,omitzero"`
}

// PeerIdentifier is one identifier of a peer or subject: a kind from the
// ADR-0002 D3 vocabulary and a normalised value.
type PeerIdentifier struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// PeerRef is the other end of an observed relationship, or the subject of a
// fact — described by identifiers rather than by an id, because a collector
// cannot resolve an asset. The identification engine does that at ingest.
// PeerIdentityEvidence describes what the configured collector actually verified.
// Names, OUI guesses, configured targets and relayed advertisements never set it.
type PeerIdentityEvidence struct {
	ControllerInventory bool `json:"controller_inventory,omitempty"`
	ConnectedInterface  bool `json:"connected_interface,omitempty"`
}

type PeerRef struct {
	IdentityEvidence PeerIdentityEvidence `json:"identity_evidence,omitempty"`
	Identifiers      []PeerIdentifier     `json:"identifiers,omitempty"`
	DisplayName      string               `json:"display_name,omitempty"`
	// ClassHint is an asset-class key (shared/assetclass) proposing what the
	// peer is. A hint, never a decision: classification is a proposal that goes
	// through Approvals (ADR-0002 classifier seam).
	ClassHint string `json:"class_hint,omitempty"`

	// --- What the neighbour said about ITSELF -------------------------------
	//
	// Everything below is posture a discovery protocol advertises in the clear
	// and the interrogators were already parsing, and then dropping. Until it
	// was carried, the only evidence a peer's classification had was its MAC
	// prefix — so every device behind a vendor that makes more than one kind of
	// box (which is all of them) came back `unknown_host`, and a switch that
	// had literally announced "I am a switch" over LLDP was one of them.
	//
	// None of it is an identity and none of it is a secret: an LLDP/CDP frame
	// is broadcast to the segment, so anything here is already known to every
	// device on the wire. It is still projected onto these named fields rather
	// than carried as a map, for the reason every collector projects — a map
	// would carry whatever the vendor decided to put in the frame next.

	// Platform is the PRODUCT the neighbour advertised, and only that: CDP's
	// `Platform:` line ("cisco WS-C3750X-48P"), or the leading product segment
	// of an LLDP system description ("Cisco IOS Software"). It feeds
	// classify.ClassifyInput's Model, which is what the PID rules match on.
	//
	// The leading SEGMENT and not the whole description, which is the decision
	// this field exists to make explicit. An LLDP `System Description` is
	// free text an operator can put anything into, and one of them in this
	// repo's own fixtures contains an SNMP community string — so carrying the
	// description verbatim is collecting a secret, which
	// TestPanLLDPObservations_EmitsNeighboursAndEdges refuses and is right to.
	// [advertisedProduct] keeps the part before the first comma, bounded, which
	// is where every vendor puts the product and where none of them puts a
	// configured value.
	Platform string `json:"platform,omitempty"`

	// SoftwareVersion is the version the neighbour advertised — the version
	// TOKEN out of CDP's `Version :` block, never the block.
	//
	// Same rule as Platform and the same reason. The block is a multi-line
	// banner that on a real device carries the image path, the compile host,
	// the uptime and whatever the operator configured; [advertisedVersion]
	// lifts the one token after the word "Version" and discards the rest, so
	// what is stored is "15.2(4)E10" rather than somebody's banner.
	SoftwareVersion string `json:"software_version,omitempty"`

	// LLDPCapabilities and CDPCapabilities are the capability bits the
	// neighbour advertised, in the vocabulary shared/hostobs' decoders use — so
	// a rule fires the same whether the device was seen in a live capture or
	// read out of a switch's neighbour table.
	//
	// Two fields rather than one, because classify keeps the two vocabularies
	// apart on purpose: CDP's `switch` means the device switches, while
	// 802.1AB's `bridge` is the bridging FUNCTION that an access point and a
	// desk phone also perform. A rule written for one protocol firing on the
	// other's advertisement is exactly the fabricated fact the rule table
	// exists to avoid.
	LLDPCapabilities []string `json:"lldp_capabilities,omitempty"`
	CDPCapabilities  []string `json:"cdp_capabilities,omitempty"`
}

// maxAdvertisementLength bounds what a neighbour can put into a peer reference.
//
// 128 bytes. A product string is tens of characters and a version token fewer;
// anything longer is not one of those, and truncating is the cheap half of the
// defence. The real half is that neither field is free text at all — see
// [advertisedProduct] and [advertisedVersion].
const maxAdvertisementLength = 128

// advertisedProduct is the leading PRODUCT segment of an advertised
// description, bounded.
//
// The first line, then the part before the first comma. Every vendor's LLDP
// system description and CDP platform line leads with the product — "Cisco IOS
// Software, C3750E Software (...), Version 15.2(4)E10, RELEASE SOFTWARE" — and
// everything after that comma is a mixture of build metadata and whatever the
// device was configured with. This repo's own PAN-OS fixture carries an SNMP
// community string there, which is why this is a projection and not a copy.
func advertisedProduct(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	segment, _, _ := strings.Cut(strings.TrimSpace(strings.TrimSuffix(line, "\r")), ",")
	segment = strings.TrimSpace(segment)
	if len(segment) > maxAdvertisementLength {
		segment = strings.TrimSpace(segment[:maxAdvertisementLength])
	}
	// …and the segment is dropped whole when it NAMES a credential.
	//
	// Keeping the leading segment defends against the secret that this repo's
	// PAN-OS fixture happens to carry — "Cisco IOS Software, snmp community
	// s3cr3t" — only because that operator typed the product first. Position is
	// not a rule: "snmp community s3cr3t, Cisco IOS Software" is the same
	// description with the same secret, and the comma cut would have kept the
	// secret and thrown the product away. Nothing downstream could catch it
	// either — `Sanitize` is name-based, and the field is called `platform`.
	//
	// So the one VALUE-shaped rule that applies: if any word of the segment is
	// a name this repository has explicitly named as a credential, the segment
	// is not a product and none of it is kept. [redact.IsExplicitSecretName]
	// rather than [redact.IsSecretName] because the latter's "anything ending
	// in key" catch-all is a guess about VENDOR FIELD NAMES, and applying a
	// guess to free text would throw away real products.
	for _, word := range strings.Fields(segment) {
		if redact.IsExplicitSecretName(strings.Trim(word, `:=,;"'`)) {
			return ""
		}
	}
	return segment
}

// advertisedVersionRE lifts the version token out of a banner line.
//
// Anchored on the word "Version", which every vendor writes, and matching only
// the characters a version is made of. A banner with no such token yields
// nothing, which is the honest answer — it is never "the whole line".
var advertisedVersionRE = regexp.MustCompile(`(?i)\bversion[:\s]+([0-9][0-9A-Za-z.()_\-]*)`)

// advertisedVersion is the version TOKEN out of an advertised banner, or "".
func advertisedVersion(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	m := advertisedVersionRE.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	token := strings.TrimSpace(m[1])
	if len(token) > maxAdvertisementLength {
		return ""
	}
	return token
}

// IsZero reports whether the ref names nothing at all, which for a fact
// subject means "the interrogated device".
func (p PeerRef) IsZero() bool {
	return len(p.Identifiers) == 0 && p.DisplayName == "" && p.ClassHint == "" &&
		p.Platform == "" && p.SoftwareVersion == "" &&
		len(p.LLDPCapabilities) == 0 && len(p.CDPCapabilities) == 0
}

// Identifier returns the first value of the given kind, or "".
func (p PeerRef) Identifier(kind string) string {
	for _, id := range p.Identifiers {
		if id.Kind == kind {
			return id.Value
		}
	}
	return ""
}

// AddIdentifier normalises value for kind and appends it, reporting whether it
// was kept.
//
// A value that does not normalise is DROPPED, not stored: the all-zero MAC a
// UniFi port table returns for an empty port, the "unknown" an LLDP neighbour
// advertises as a system name, and the broadcast address are placeholders, and
// storing one as an identity is how two unrelated assets merge into one. A
// duplicate (kind, value) is dropped too — the same neighbour seen on two
// ports is one peer.
func (p *PeerRef) AddIdentifier(kind, value string) bool {
	norm, err := normalizeIdentifier(kind, value)
	if err != nil {
		return false
	}
	for _, existing := range p.Identifiers {
		if existing.Kind == kind && existing.Value == norm {
			return false
		}
	}
	p.Identifiers = append(p.Identifiers, PeerIdentifier{Kind: kind, Value: norm})
	return true
}

// lldpCapabilityNames normalises an advertised 802.1AB capability list onto the
// names shared/hostobs' LLDP decoder produces from the bitmask — which is the
// vocabulary shared/classify's `lldp_capabilities` rules are written in.
//
// One function for every vendor rendering, because there are three and they are
// all the same bitmask: IOS prints the single-letter legend codes ("B,R"),
// PAN-OS prints the words ("Bridge, Router"), and a controller's API returns a
// hyphenated array ("wlan-access-point"). A rule has to fire for all three or
// the same switch classifies differently depending on which box we asked.
//
// Anything outside the vocabulary is DROPPED rather than passed through
// lower-cased: an unmapped token reaches the engine as a capability name
// nothing can ever match, which reads as evidence and is not.
func lldpCapabilityNames(capabilities string) []string {
	var out []string
	seen := map[string]bool{}
	for _, field := range strings.FieldsFunc(capabilities, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '/'
	}) {
		name, ok := lldpCapabilitySpellings[strings.ToLower(strings.TrimSpace(field))]
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// lldpCapabilitySpellings maps every rendering we have seen onto one name.
//
// The letters are IOS's own legend, verbatim: B - Bridge, C - DOCSIS Cable
// Device, O - Other, P - Repeater, R - Router, S - Station, T - Telephone,
// W - WLAN Access Point. The words and hyphenated forms are PAN-OS's and the
// controller APIs'.
var lldpCapabilitySpellings = map[string]string{
	"b": "bridge", "bridge": "bridge",
	"c": "docsis_cable_device", "docsis": "docsis_cable_device",
	"docsis_cable_device": "docsis_cable_device", "docsis-cable-device": "docsis_cable_device",
	"o": "other", "other": "other",
	"p": "repeater", "repeater": "repeater",
	"r": "router", "router": "router",
	"s": "station_only", "station": "station_only",
	"station_only": "station_only", "station-only": "station_only",
	"t": "telephone", "telephone": "telephone", "phone": "telephone",
	"w": "wlan_access_point", "wlan": "wlan_access_point",
	"wlan_access_point": "wlan_access_point", "wlan-access-point": "wlan_access_point",
	"access_point": "wlan_access_point", "access-point": "wlan_access_point",
	"c_vlan_component": "c_vlan_component", "c-vlan-component": "c_vlan_component",
	"s_vlan_component": "s_vlan_component", "s-vlan-component": "s_vlan_component",
	"two_port_mac_relay": "two_port_mac_relay", "two-port-mac-relay": "two_port_mac_relay",
}

// RelationshipDirection says which way an observed edge runs, relative to the
// observation's subject.
type RelationshipDirection string

const (
	// SubjectToPeer — the canonical direction runs from the subject (the
	// interrogated device, or the Subject of the observation) to the peer.
	SubjectToPeer RelationshipDirection = "subject_to_peer"
	// PeerToSubject — the canonical direction runs from the peer to the
	// subject. Emitted rather than flipping the type, because the reverse of a
	// type is a label and never a second type (ADR-0003 D2).
	PeerToSubject RelationshipDirection = "peer_to_subject"
)

// Valid reports whether d is one of the two directions.
func (d RelationshipDirection) Valid() bool {
	return d == SubjectToPeer || d == PeerToSubject
}

// RelationshipObservation is one edge a collector observed: a canonical type, a
// direction, the two ends, and the type-specific detail.
type RelationshipObservation struct {
	// Type is one of the canonical ten (shared/relationships).
	Type      string                `json:"type"`
	Direction RelationshipDirection `json:"direction"`
	// Subject is the end the collector was standing on. The zero value means
	// the interrogated device itself.
	Subject PeerRef `json:"subject,omitzero"`
	Peer    PeerRef `json:"peer"`
	// Attributes carries the type-specific detail ADR-0003 D2 names: the local
	// and remote port names of an LLDP neighbour, a VLAN id, the transport of a
	// connection. It is walked by [Sanitize] like any other collected map.
	Attributes map[string]any `json:"attributes,omitempty"`
}

// AddFact validates a fact observation and appends it to the result.
//
// Validation is the point: the fact key must be registered, the value must
// match its registered type, and device-interrogation must be a declared
// producer of that key. A collector emitting a key it is not registered for
// means two subsystems disagree about who owns a fact, which is how one key
// ends up with two meanings.
//
// The producer is facts.ProducerDeviceInterrogation, including when this
// package runs inside the standalone agent: the producer names the CAPABILITY
// that measured the fact, not the binary it happened to run in. Both runtimes
// share this code precisely so they cannot describe the same measurement two
// ways.
//
// A DIFFERENT capability that builds an InterrogateResult uses
// [InterrogateResult.AddFactFrom] with its own producer. Host inventory
// (shared/hostinventory) is the first: it measures os.kernel, hw.uuid,
// svc.listening_sockets, sw.package_count, agent.id and agent.mode, and the
// registry lists `device-agent` — not `device-interrogation` — as the producer
// of every one of them. Routing those through here would fail validation, and
// widening the keys' producer lists to make it pass would be the "one key, two
// meanings" bug the validation exists to prevent.
func (r *InterrogateResult) AddFact(f FactObservation) error {
	return r.AddFactFrom(facts.ProducerDeviceInterrogation, f)
}

// AddFactFrom validates a fact observation measured by a named producer and
// appends it to the result.
//
// producer must be one of the registry's declared producers
// (standards/fact-keys.yaml) and must be listed for the key. Everything else —
// key registration, value type, confidence range — is checked exactly as
// [InterrogateResult.AddFact] checks it, because those rules are properties of
// the fact rather than of who measured it.
func (r *InterrogateResult) AddFactFrom(producer string, f FactObservation) error {
	if r == nil {
		return fmt.Errorf("deviceinterrogation: AddFact on a nil result")
	}
	if !facts.MayWrite(producer, f.Key) {
		if _, known := facts.Get(f.Key); !known {
			return fmt.Errorf("deviceinterrogation: fact key %q is not registered in standards/fact-keys.yaml", f.Key)
		}
		return fmt.Errorf("deviceinterrogation: fact key %q does not list %s as a producer", f.Key, producer)
	}
	if err := facts.ValidateValue(f.Key, f.Value); err != nil {
		return err
	}
	// A confidence of zero is not "unknown", it is a fact nothing believes.
	// Making it an error forces a collector to say how directly it measured
	// the value rather than inheriting a default it never thought about.
	if f.Confidence <= 0 || f.Confidence > 1 {
		return fmt.Errorf("deviceinterrogation: fact %s: confidence %v is not in (0, 1]", f.Key, f.Confidence)
	}
	r.Facts = append(r.Facts, f)
	return nil
}

// AddRelationship validates an observed edge and appends it to the result.
func (r *InterrogateResult) AddRelationship(rel RelationshipObservation) error {
	if r == nil {
		return fmt.Errorf("deviceinterrogation: AddRelationship on a nil result")
	}
	t := relationships.Type(rel.Type)
	if !t.Valid() {
		return fmt.Errorf("deviceinterrogation: %q is not one of the canonical relationship types %v", rel.Type, relationships.Strings())
	}
	if !t.Measurable() {
		return fmt.Errorf("deviceinterrogation: relationship type %q is declared or derived, never measured by a collector", rel.Type)
	}
	if !rel.Direction.Valid() {
		return fmt.Errorf("deviceinterrogation: relationship %s: direction %q is not %s or %s", rel.Type, rel.Direction, SubjectToPeer, PeerToSubject)
	}
	// An edge whose far end carries no identifier cannot be resolved to an
	// asset by any intake path, so it would be written and never matched. A
	// display name alone is not an identity.
	if len(rel.Peer.Identifiers) == 0 {
		return fmt.Errorf("deviceinterrogation: relationship %s: peer carries no identifier", rel.Type)
	}
	r.Relationships = append(r.Relationships, rel)
	return nil
}

// addFact appends a fact, warning rather than failing the interrogation when
// the collector and the registry disagree.
//
// Every in-tree caller passes a constant key and a value it built itself, so a
// failure here is a programming error, and the projection tests catch it before
// it ships. At runtime, losing one fact must not lose the interrogation that
// carried it — but it must not be silent either, which is why this warns on the
// same channel the package's other non-fatal failures use.
func (r *InterrogateResult) addFact(key string, value any, confidence float64) {
	r.addSubjectFact(PeerRef{}, key, value, confidence)
}

// addSubjectFact is addFact for a fact about something other than the
// interrogated device — a switch a controller manages, for instance.
func (r *InterrogateResult) addSubjectFact(subject PeerRef, key string, value any, confidence float64) {
	if err := r.AddFact(FactObservation{Key: key, Value: value, Confidence: confidence, Subject: subject}); err != nil {
		r.warnAs(WarningError, "fact "+key, "An observed "+key+" value was not recorded", err.Error())
	}
}

// addRelationship appends an edge, warning rather than failing on an invalid
// one. Same reasoning as addFact.
func (r *InterrogateResult) addRelationship(rel RelationshipObservation) {
	if err := r.AddRelationship(rel); err != nil {
		r.warnAs(WarningError, "relationship "+rel.Type, "An observed "+rel.Type+" relationship was not recorded", err.Error())
	}
}

// normalizeIdentifier canonicalises an identifier value for its kind, mirroring
// shared/identity's rules so a collector and the identification engine produce
// the same string for the same thing.
//
// It is a mirror rather than a call because shared/identity pulls in the
// platform AI seam and the config loader, neither of which belongs in a
// cross-compiled agent binary.
// TestNormalizeIdentifierMatchesIdentityPackage pins every rule below against
// identity.Normalize, including the values both must REJECT.
func normalizeIdentifier(kind, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("deviceinterrogation: %s: value is empty", kind)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("deviceinterrogation: %s: value contains a control character", kind)
		}
	}

	switch kind {
	case IdentifierMACAddress:
		return canonicalMAC(v)
	case IdentifierFQDN:
		return canonicalDNSName(v, true)
	case IdentifierHostname:
		return canonicalDNSName(v, false)
	case IdentifierIPAddress:
		return canonicalIP(v)
	case IdentifierSerialNumber, IdentifierAgentID:
		// Opaque: a serial's case and punctuation are the vendor's, and
		// folding them loses the join key to a CMDB. An agent id is a uuid we
		// issued and is carried verbatim for the same reason — identity.
		// Normalize treats both the same way, which is what
		// TestNormalizeIdentifierMatchesIdentityPackage pins.
		return v, nil
	default:
		return "", fmt.Errorf("deviceinterrogation: unknown identifier kind %q", kind)
	}
}

// canonicalMAC accepts aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff and
// aabbccddeeff, and emits the first form. The all-zero and broadcast addresses
// are rejected: both are placeholders a device returns for "no neighbour", not
// identities.
func canonicalMAC(v string) (string, error) {
	var hex strings.Builder
	hex.Grow(12)
	for _, r := range strings.ToLower(v) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r == ':', r == '-', r == '.', r == ' ':
			// separator
		default:
			return "", fmt.Errorf("deviceinterrogation: mac_address: %q is not a MAC address", v)
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return "", fmt.Errorf("deviceinterrogation: mac_address: %q has %d hex digits, want 12", v, len(h))
	}
	if h == "000000000000" || h == "ffffffffffff" {
		return "", fmt.Errorf("deviceinterrogation: mac_address: %q is a placeholder, not an identity", v)
	}
	var out strings.Builder
	out.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String(), nil
}

// canonicalDNSName lowercases, strips the root label, and rejects anything that
// is not a DNS name. requireDot distinguishes an FQDN from a short hostname.
func canonicalDNSName(v string, requireDot bool) (string, error) {
	s := strings.TrimSuffix(strings.ToLower(v), ".")
	if s == "" || len(s) > 253 {
		return "", fmt.Errorf("deviceinterrogation: %q is not a usable DNS name", v)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return "", fmt.Errorf("deviceinterrogation: %q contains %q, which is not valid in a DNS name", v, string(r))
		}
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return "", fmt.Errorf("deviceinterrogation: %q has an empty label", v)
	}
	if requireDot && !strings.Contains(s, ".") {
		return "", fmt.Errorf("deviceinterrogation: fqdn: %q is a single label", v)
	}
	return s, nil
}

// canonicalHostnameOrEmpty returns name canonicalised as a short DNS hostname,
// or "" when it is not one.
//
// Several collectors (UniFi managed devices and VPN networks, Fortinet IPSec
// tunnels, PAN-OS SSL-decrypt profiles and security rules, F5 virtual
// servers, an SNMP agent's sysName) read a human-chosen display name or
// config-object label straight off the vendor API and used to assign it
// directly to CryptoAsset.Hostname. A name like "U6+ Living Room" or
// "Back Porch #1" is a fine display string but is not a DNS name, and
// assigning it to Hostname sends it downstream to the identity layer, which
// rejects it as an invalid hostname identifier — silently losing the
// identifier and, run after run, flooding the log with the same reject.
//
// The caller keeps the raw value in Metadata for display and calls this
// guard before ever writing to Hostname, so an invalid name never leaves the
// collector in the first place.
func canonicalHostnameOrEmpty(name string) string {
	canon, err := canonicalDNSName(name, false)
	if err != nil {
		return ""
	}
	return canon
}

// canonicalIP parses with net/netip, unmaps IPv4-in-IPv6 and drops the zone: a
// %eth0 on one host is not the same interface as on another.
func canonicalIP(v string) (string, error) {
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return "", fmt.Errorf("deviceinterrogation: ip_address: %q is not an IP address: %w", v, err)
	}
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsUnspecified() {
		return "", fmt.Errorf("deviceinterrogation: ip_address: %q is a placeholder, not an identity", v)
	}
	return addr.String(), nil
}

// cidrFromAddressAndMask combines an address and a DOTTED netmask — the form
// PAN-OS reports management addressing in and FortiOS reports every interface
// in — into one CIDR string, or "" when the address is not an address.
//
// An unreadable mask yields the bare address rather than a guessed prefix
// length: /32 would claim the interface serves one host and /24 would invent a
// segment, and both are statements the device did not make.
func cidrFromAddressAndMask(address, netmask string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	mask, err := netip.ParseAddr(strings.TrimSpace(netmask))
	if err != nil || !mask.Is4() || !addr.Is4() {
		return addr.String()
	}
	bits := 0
	for _, octet := range mask.As4() {
		for b := 7; b >= 0; b-- {
			if octet&(1<<b) == 0 {
				break
			}
			bits++
		}
	}
	return netip.PrefixFrom(addr, bits).String()
}

// addHostIdentifiers offers a name to a peer as an FQDN and a hostname, unless
// the name is an address or a MAC wearing a name's clothing.
//
// The guard is load-bearing. Digits and dots are legal in a DNS name, so
// "198.51.100.20" normalises as one — and an F5 pool member is very often named
// after its own address, which would give one backend three identifiers, one of
// them a hostname it does not have. Two unrelated assets then merge the moment
// something really is called that.
//
// The address and MAC forms are still offered by the caller under their own
// kinds; this only refuses to ALSO call them names.
func addHostIdentifiers(peer *PeerRef, name string) {
	if peer == nil || strings.TrimSpace(name) == "" {
		return
	}
	if _, err := canonicalIP(name); err == nil {
		return
	}
	if _, err := canonicalMAC(name); err == nil {
		return
	}
	peer.AddIdentifier(IdentifierFQDN, name)
	peer.AddIdentifier(IdentifierHostname, name)
}

// peerRef builds a peer from a display name and a class hint, with no
// identifiers yet. Callers add identifiers with AddIdentifier, which is what
// normalises and drops the placeholders.
func peerRef(displayName, classHint string) PeerRef {
	return PeerRef{DisplayName: strings.TrimSpace(displayName), ClassHint: classHint}
}
