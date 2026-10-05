package identity

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
	"github.com/vistasecurity/vistaplatform/shared/identity/derive"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
)

// Intake is the one place that turns what a collector saw into an
// [Observation].
//
// Before it, about ten adapters across inventory-service and
// device-interrogation-service each decided an observation's scope, its
// [Observation.DynamicScopes] and its admission flags for themselves, and the
// same device with the same kind of evidence got opposite outcomes depending on
// which path carried it. An adapter now produces a [Sighting] — what it saw,
// with no scope, no dynamic flag and no admission flags — and Intake decides
// the rest, the same way for every path:
//
//   - every address and every name is scoped SEPARATELY, against ONE segment
//     snapshot loaded once per call ([Repository.SegmentSnapshot]):
//     an address by [SegmentSnapshot.ScopeForAddress]; a name by the segment
//     of the address it was seen at, else the domain rule
//     ([SegmentSnapshot.ScopeForName]), else the tenant default;
//   - DynamicScopes comes from the segments' STORED effective posture only
//     (operator > measured > inferred, decided once at write time by
//     shared/identity/postgres/segment_posture.go). A Sighting has no field a
//     collector could use to overlay its own run's DHCP opinion;
//   - Direct / Relayed / Authoritative come from the sighting's [Channel]
//     through one table ([ChannelAdmission]);
//   - identifier hygiene is applied once, by the shared packages
//     (derive, attrlist, hostnamequality, hostobs, [GenericNames]);
//   - every address an operator declared, or the host reported about itself,
//     is marked [Identifier.Pinned] for owner decision 1.
//
// Intake does not resolve anything and writes nothing: its output is handed
// to [Engine.Resolve] exactly as an adapter's hand-built Observation is today,
// which is what lets an adapter run both side by side and log [Diff] before it
// switches.
//
// Safe for concurrent use.
type Intake struct {
	repo    Repository
	generic *GenericNames
}

// IntakeOption configures [NewIntake].
type IntakeOption func(*Intake)

// WithIntakeGenericNames shares a [GenericNames] the caller already holds — and
// with it the caller's cardinality cache — instead of building one over the
// repository. Nil applies the static dictionary alone.
func WithIntakeGenericNames(g *GenericNames) IntakeOption {
	return func(in *Intake) { in.generic = g }
}

// NewIntake builds an Intake over a repository. The repository supplies the
// segment snapshot and the tenant hostname counts the generic-name rule reads;
// Intake never writes to it.
func NewIntake(repo Repository, opts ...IntakeOption) (*Intake, error) {
	if repo == nil {
		return nil, errors.New("identity: NewIntake needs a repository")
	}
	in := &Intake{repo: repo, generic: NewGenericNames(repo)}
	for _, o := range opts {
		o(in)
	}
	return in, nil
}

// ErrInvalidSighting is returned by [Intake.Build] for a sighting that cannot be
// turned into an observation at all: no tenant, an invalid source, an unknown
// channel, or an identifier kind no collector may claim. It is a bug in the
// adapter, never a property of the network.
var ErrInvalidSighting = errors.New("identity: invalid sighting")

// Channel is HOW a collector came to know what a [Sighting] says: what stood
// between the device and the platform when the evidence was taken. It is the
// one input the admission flags are derived from ([ChannelAdmission]).
type Channel string

// The channels. sketched six (L2 frame, L3 probe, authenticated session,
// controller inventory, API, person); three more are needed to reproduce what
// the adapters already distinguish — a name heard first-hand that binds no
// interface, the same heard through a reflector, and L3 traffic that completed
// no handshake.
const (
	// ChannelL2Frame — a layer-2 frame that binds an interface: ARP, DHCP,
	// LLDP, CDP, or a switch/AP port reporting the client on its own interface
	// (deviceinterrogation's ConnectedInterface).
	ChannelL2Frame Channel = "l2_frame"
	// ChannelAdvertisement — a name or service advertisement heard first-hand
	// (mDNS, NetBIOS, a DNS answer), or a device reporting a neighbour it did
	// not verify. It names a device; it does not bind one.
	ChannelAdvertisement Channel = "advertisement"
	// ChannelRelayed — an advertisement repeated by something other than its
	// subject: an mDNS reflector on another VLAN (`mdns_relayed`). Recorded,
	// never direct.
	ChannelRelayed Channel = "relayed"
	// ChannelL3Probe — an L3 exchange that COMPLETED with the address: a TLS
	// cipher negotiated or an SSH host key read, whether the platform probed
	// or a sensor watched it happen. Something at that address answered.
	ChannelL3Probe Channel = "l3_probe"
	// ChannelL3Traffic — the address was seen at L3 with no completed
	// exchange: a flow, a connection attempt, a probe nothing answered.
	ChannelL3Traffic Channel = "l3_traffic"
	// ChannelAuthenticatedSession — the platform was ON the host: its agent
	// or sensor reporting about the machine it runs on, or an authenticated
	// session (SSH, device API) reading the device's own configuration — host
	// inventory, Add device's probe that read a serial.
	ChannelAuthenticatedSession Channel = "authenticated_session"
	// ChannelControllerInventory — a controller listing a device it manages
	// (UniFi's adopted devices).
	ChannelControllerInventory Channel = "controller_inventory"
	// ChannelAPI — a cloud provider's or a system of record's API listing the
	// resource: cloud collectors, CMDB and NetBox connections. The adapter
	// must have verified the collector's trust anchor before it picks this
	// channel (for example inventory-service's cloudCollectorAuthoritative);
	// the channel states what was verified, it does not verify.
	ChannelAPI Channel = "api"
	// ChannelPerson — a person typed it: manual create, the Devices form
	// without a probe, a spreadsheet import.
	ChannelPerson Channel = "person"
)

// AllChannels returns every channel, in table order.
func AllChannels() []Channel {
	return []Channel{
		ChannelL2Frame, ChannelAdvertisement, ChannelRelayed, ChannelL3Probe, ChannelL3Traffic,
		ChannelAuthenticatedSession, ChannelControllerInventory, ChannelAPI, ChannelPerson,
	}
}

// ChannelAdmission is THE table from channel to admission flags. It is the only
// place an [AdmissionEvidence]'s Direct, Relayed and Authoritative are decided
// for a sighting:
//
//	channel                 Direct  Relayed  Authoritative
//	l2_frame                  ✓
//	advertisement
//	relayed                           ✓
//	l3_probe                  ✓
//	l3_traffic
//	authenticated_session     ✓                  ✓
//	controller_inventory                         ✓
//	api                                          ✓
//	person
//
// Where the adapters agreed, the table is what they did: ARP/DHCP/LLDP/CDP
// direct and mDNS not (host-observation ingest); a completed TLS/SSH exchange
// direct (discovery findings); host inventory and Add device's serial-reading
// probe direct and authoritative; cloud collectors, CMDB and NetBox
// authoritative; a person neither. Where they disagreed, see the design note
// (docsv4/internal/developer/design/asset-inventory/identity-intake.md,
// "Where the adapters disagreed").
//
// OperatorConfirmed is never set here: a confirmation is a decision on an
// observation already held, not something a collector sees.
//
// ok is false for a channel not in the table, including the empty one —
// "the collector did not say" is not a channel, and defaulting it to anything
// would hand some path admission it never earned.
func ChannelAdmission(c Channel) (AdmissionEvidence, bool) {
	switch c {
	case ChannelL2Frame, ChannelL3Probe:
		return AdmissionEvidence{Direct: true}, true
	case ChannelRelayed:
		return AdmissionEvidence{Relayed: true}, true
	case ChannelAuthenticatedSession:
		return AdmissionEvidence{Direct: true, Authoritative: true}, true
	case ChannelControllerInventory, ChannelAPI:
		return AdmissionEvidence{Authoritative: true}, true
	case ChannelAdvertisement, ChannelL3Traffic, ChannelPerson:
		return AdmissionEvidence{}, true
	}
	return AdmissionEvidence{}, false
}

// keepsLocalMACs reports whether a locally administered MAC on this channel is
// a configured, stable address rather than a randomised one: the host's own
// configuration (a VM's 52:54:00 NIC read by its agent), a cloud API (an ENI's
// 02:/0a: MAC), or a person typing one. Everywhere else — a frame on the wire,
// a controller's client list — it is the phone's rotating Wi-Fi address.
func keepsLocalMACs(c Channel) bool {
	return c == ChannelAuthenticatedSession || c == ChannelAPI || c == ChannelPerson
}

// Sighting is what a collector saw, normalised to one shape and nothing more:
// the input of [Intake.Build].
//
// It deliberately has no scope, no dynamic flag and no admission flags. Those
// are decisions, and making them in the adapter is the divergence
// exists to end; an adapter that needs a field to say one of them has found a
// rule that belongs in Intake.
type Sighting struct {
	// TenantID scopes everything. A sighting with no tenant is rejected.
	TenantID string `json:"tenant_id"`

	// Source is the provenance of the sighting as a whole, exactly as
	// [Observation.Source]: kind, a `producer:detail` ref and the measurement
	// mode. It must be valid.
	Source Source `json:"source"`

	// Channel is how the evidence was taken; it alone decides the admission
	// flags ([ChannelAdmission]). Required.
	Channel Channel `json:"channel"`

	// ObservedAt is when the thing was seen. Zero lets the engine stamp its
	// own clock, as it does for an Observation.
	ObservedAt time.Time `json:"observed_at"`

	// ReceiptID is the producer's delivery id, so a retry is recognised as the
	// same sighting ([ObservationReceiptKey]). CollectorVersion is the
	// collector build that produced it. Both are carried into
	// [AdmissionEvidence] unchanged.
	ReceiptID        string `json:"receipt_id,omitempty"`
	CollectorVersion string `json:"collector_version,omitempty"`

	// ClassHint and ClassProvenance are the collector's (or the rule table's)
	// opinion of what this is, carried to [Observation.ClassHint] and
	// [Observation.ClassProvenance] unchanged. ClassHint is also the scope of a
	// `name` identifier: a name identifies within a class.
	ClassHint       string          `json:"class_hint,omitempty"`
	ClassProvenance ClassProvenance `json:"class_provenance,omitzero"`

	// DisplayName is the label the collector would show for the thing. Empty
	// lets Intake choose the best name it carries ([hostnamequality.Best]),
	// else its first address, else its first MAC.
	DisplayName string `json:"display_name,omitempty"`

	// Confidence is the collector's confidence in the sighting as a whole,
	// 0..1 — what an approval rule's min_confidence reads. Zero is NOT STATED.
	Confidence float64 `json:"confidence,omitempty"`

	// Ownership and NetworkType are the classifier's view of where the
	// sighting was made ([Network.Ownership], [Network.Type]). Intake fills
	// in Network.SegmentID itself.
	Ownership   string `json:"ownership,omitempty"`
	NetworkType string `json:"network_type,omitempty"`

	// CloudNetworkRef is the cloud network (VPC / VNet) the sighting was made
	// inside, as the provider's resource id; empty for every LAN sighting.
	// See [Repository.ScopeForAddress] for why only a path that ENUMERATED a
	// cloud network may set it.
	CloudNetworkRef string `json:"cloud_network_ref,omitempty"`

	// Identifiers are the raw identifiers, in the collector's order, each
	// with its own address context and provenance. Order matters in one place:
	// the first address that resolves to a real segment is the sighting's
	// [Network.SegmentID].
	Identifiers []SightedIdentifier `json:"identifiers,omitempty"`

	// Endpoints are the faces the collector saw the thing expose, exactly as
	// [Observation.Endpoints]; Intake only sanitises them
	// ([EndpointObservation.Sanitized]).
	Endpoints []EndpointObservation `json:"endpoints,omitempty"`

	// Attributes are class attributes the collector observed, carried to
	// [Observation.Attributes] unchanged (the engine reads only an allowlist).
	Attributes map[string]any `json:"attributes,omitempty"`

	// TLSCertFingerprints are the SHA-256 fingerprints of the leaf
	// certificates the device presented, carried to
	// [Observation.TLSCertFingerprints] unchanged: evidence for the drift
	// classifier, never an identifier.
	TLSCertFingerprints []string `json:"tls_cert_fingerprints,omitempty"`

	// BridgePriorScope asks Intake to carry, beside every address it scopes to
	// a real segment, the SAME address at [ScopeTenantDefault] — but only when
	// that tenant-default copy already has an owner.
	//
	// It is the bridge across a network being registered: the sighting made
	// before the segment existed stored `ip_address@tenant`; the one after it
	// scopes the address to the new segment, and without the old key nothing
	// would match the asset the first sighting created. Carrying the old key
	// lets the engine match that asset and attach the segment-scoped key to
	// it, instead of minting a duplicate. When nobody owns the tenant-default
	// copy nothing is added, so a sighting of a never-seen address is
	// unchanged. (Formerly inventory-service's addPriorDefaultScopeIdentifier,
	// restricted there to a host's own connection table; ADR-0003
	// Consequences.)
	//
	// It is a lookup, not a scope decision: the address is still scoped by
	// [SegmentSnapshot.ScopeForAddress], and the copy names a key that
	// already exists or is not added at all.
	BridgePriorScope bool `json:"bridge_prior_scope,omitempty"`
}

// SightedIdentifier is one raw identifier as a collector saw it: no scope, no
// dynamic flag. Intake scopes it.
type SightedIdentifier struct {
	// Kind is the identifier kind the collector filed it under. A name is
	// re-filed by Intake: a dotted name that is not `.local` is an fqdn, any
	// other name a hostname — whichever of the two the collector chose.
	// `declaration_id` is refused: it is issued only by an operator's
	// confirmation, never seen.
	Kind Kind `json:"kind"`
	// Value is as the collector reported it; Intake normalises it.
	Value string `json:"value"`

	// Address is the address this identifier was seen AT, for a hostname or
	// fqdn: the address that announced the name, or that the name answered
	// from. It is how a name gets its own address context rather than the
	// sighting's first address. Empty means "no address of its own", and the
	// name is scoped with the sighting's first resolved address instead.
	// Ignored on an ip_address (the value is the address) and on every
	// other kind.
	Address string `json:"address,omitempty"`

	// Profile is the sync profile a `cmdb_sys_id` was read from, which is
	// that kind's scope. Rejected on any other kind.
	Profile string `json:"profile,omitempty"`

	// Confidence is 0..1; zero means 1.0 (an identifier the collector read
	// is measured, not graded). A derived MAC Intake adds carries 0.9.
	Confidence float64 `json:"confidence,omitempty"`

	// Provenance is this identifier's own provenance where it differs from
	// the sighting's. The zero value means "as the sighting".
	Provenance IdentifierProvenance `json:"provenance,omitzero"`

	// KeyAlgorithm is the key type of an `ssh_host_key_fingerprint` as the
	// collector reported it (carried to [Identifier.KeyAlgorithm], which the
	// drift classifier reads: only a same-algorithm change is a rotation).
	// Ignored on every other kind.
	KeyAlgorithm string `json:"key_algorithm,omitempty"`

	// Assignment is how the host said it holds this address, when it said:
	// [AssignmentStatic] for an interface it reports as statically
	// configured, [AssignmentDynamic] for a DHCP lease. Empty is "nobody
	// said", which is every address somebody else saw in use. Carried to
	// [Identifier.Assignment] on an ip_address and refused on any other kind.
	// A dynamic assignment is never pinned, whatever the provenance says: the
	// host itself called it a lease.
	Assignment AddressAssignment `json:"assignment,omitempty"`
}

// IdentifierProvenance is how one identifier, rather than the sighting, came
// to be known.
type IdentifierProvenance struct {
	// Kind overrides the sighting's [Source.Kind] for this identifier:
	//
	//   - SourceInferred — the collector DERIVED it (Ref names the evidence).
	//     It reaches [Identifier.Source], where the engine applies the
	//     inferred-identifier rules (never creates, votes after a native
	//     value, not direct evidence).
	//   - SourceDeclared — an operator declared this value on the asset
	//     (a manual edit carried through a measured re-observation, say). On
	//     an ip_address it sets [Identifier.Pinned]. It does not strengthen
	//     [Identifier.Source]: the engine never lets a caller raise an
	//     identifier's provenance above its observation's.
	//   - SourceMeasured / SourceImported — on a DECLARED sighting, a value
	//     the collector read rather than the person typed (the MAC Add
	//     device's probe read): it reaches [Identifier.Source] with that
	//     lower kind, so it is stored as measured. On a measured sighting the
	//     same as the zero value.
	//
	// Empty means the sighting's kind.
	Kind SourceKind `json:"kind,omitempty"`
	// Ref names the evidence for an inferred or lowered identifier
	// ("derived:eui64:<addr>"). Empty falls back to the sighting's ref.
	Ref string `json:"ref,omitempty"`
	// SelfReported says the HOST reported this address about itself — its
	// agent or an authenticated session reading its own interface
	// configuration — rather than someone else seeing it in use. On an
	// ip_address it sets [Identifier.Pinned] (owner decision 1).
	SelfReported bool `json:"self_reported,omitempty"`
	// Claimed says the device read this address off its OWN interface
	// configuration as an address it serves a network on — a gateway's
	// address on each network it routes — and asks the engine to
	// settle who else holds it ([Identifier.Claimed], claimed.go). It implies
	// SelfReported. Valid only on an ip_address of a measured sighting over
	// [ChannelAuthenticatedSession], and never with a dynamic assignment:
	// anything else is refused as [ErrInvalidSighting], because a claim
	// nobody can make first-hand is a rule an adapter has misapplied.
	Claimed bool `json:"claimed,omitempty"`
}

// ClaimsAddresses reports whether any identifier of the sighting is a claimed
// address ([IdentifierProvenance.Claimed]).
//
// Such a sighting describes the networks a device serves, not where the
// device stands, so it never PLACES the device: the internal sightings route
// does not project its segment onto the asset's location the way it does
// for an ordinary first-hand sighting. The device's home segment is the
// segment of the address it was reached at, which the collector's service
// sets on its own.
func (s Sighting) ClaimsAddresses() bool {
	for _, raw := range s.Identifiers {
		if raw.Provenance.Claimed {
			return true
		}
	}
	return false
}

// Withheld is a value a sighting carried that Intake refused as an
// IDENTIFIER and did not lose: it is reported here so the adapter can log it,
// and, where it has an attribute home, write it ([IntakeResult.AttributeEvidence]).
type Withheld struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	// Reason is one of the Withheld* constants.
	Reason string `json:"reason"`
}

// Withheld reasons.
const (
	// WithheldSyntheticName — a UUID-form, IP-encoded or `none` name
	// (hostnamequality.IsIdentityName); kept as attrlist.KeySyntheticNames.
	WithheldSyntheticName = "synthetic_name"
	// WithheldTemporaryIPv6 — an RFC 8981-shaped rotating address
	// (derive.RoleTemporary); kept as attrlist.KeyIPv6Temporary.
	WithheldTemporaryIPv6 = "temporary_ipv6"
	// WithheldUnscopedLinkLocal — a link-local address in a sighting with no
	// real segment to scope it to; kept as attrlist.KeyLinkLocal.
	WithheldUnscopedLinkLocal = "unscoped_link_local"
	// WithheldLocallyAdministeredMAC — the U/L bit is set on a channel where
	// that means a randomised, rotating address (see keepsLocalMACs).
	WithheldLocallyAdministeredMAC = "locally_administered_mac"
	// WithheldVirtualRouterMAC — a VRRP/CARP/HSRP/GLBP virtual router MAC
	// (hostobs.VirtualMACProtocol): it belongs to the floating address's group
	// and moves to the standby at failover.
	WithheldVirtualRouterMAC = "virtual_router_mac"
)

// IntakeResult is everything [Intake.Assess] decided about a sighting.
type IntakeResult struct {
	// Observation is what to hand the engine.
	Observation Observation
	// Rejected are identifiers that did not normalise (an IP in a name slot,
	// a MAC with eleven digits), with the reason. Nothing is dropped quietly.
	Rejected []RejectedIdentifier
	// Withheld are values refused as identifiers by hygiene, with the reason.
	Withheld []Withheld
	// AttributeEvidence is the subset of Withheld that has an attribute home,
	// keyed by attrlist key (KeySyntheticNames, KeyIPv6Temporary,
	// KeyLinkLocal), in sighting order — what the adapter writes with
	// attrlist.Record once the observation has resolved to an asset.
	AttributeEvidence map[string][]string
	// Snapshot is the segment snapshot the sighting was scoped against, so a
	// caller that needs a further answer from it (the asset's segment
	// enrichment) asks the same topology rather than reading it again.
	Snapshot SegmentSnapshot
}

// derivedMACConfidence is the confidence a MAC Intake derives is recorded
// with — the value both adapters used ( Phase 2). Not voting-relevant.
const derivedMACConfidence = 0.9

// Build turns a sighting into the observation the engine resolves. It is
// [Intake.Assess] without the side results.
func (in *Intake) Build(ctx context.Context, s Sighting) (Observation, error) {
	res, err := in.Assess(ctx, s)
	if err != nil {
		return Observation{}, err
	}
	return res.Observation, nil
}

// Assess applies every intake rule to a sighting, loading the tenant's segment
// snapshot exactly once.
//
// Errors:
//
//   - [ErrInvalidSighting] — the adapter built something no rule can read;
//   - the snapshot read's own error — the adapter decides whether to degrade
//     (today's adapters scope to the tenant default and log) or fail;
//   - [ErrNoUsableIdentifier] — nothing survived normalisation and hygiene.
//     The result is still returned in full, so the adapter can record what was
//     withheld and why.
func (in *Intake) Assess(ctx context.Context, s Sighting) (IntakeResult, error) {
	if strings.TrimSpace(s.TenantID) == "" {
		return IntakeResult{}, fmt.Errorf("%w: no tenant", ErrInvalidSighting)
	}
	if !s.Source.Valid() {
		return IntakeResult{}, fmt.Errorf("%w: source %+v is not a valid provenance", ErrInvalidSighting, s.Source)
	}
	admission, ok := ChannelAdmission(s.Channel)
	if !ok {
		return IntakeResult{}, fmt.Errorf("%w: channel %q is not one of the intake channels", ErrInvalidSighting, s.Channel)
	}
	for _, raw := range s.Identifiers {
		if raw.Kind == KindDeclarationID {
			return IntakeResult{}, fmt.Errorf("%w: declaration identifiers are issued only by an operator's confirmation", ErrInvalidSighting)
		}
		if k := raw.Provenance.Kind; k != "" && !k.Valid() {
			return IntakeResult{}, fmt.Errorf("%w: identifier provenance kind %q", ErrInvalidSighting, k)
		}
		if !raw.Assignment.Valid() {
			return IntakeResult{}, fmt.Errorf("%w: address assignment %q", ErrInvalidSighting, raw.Assignment)
		}
		if raw.Assignment != "" && raw.Kind != KindIPAddress {
			return IntakeResult{}, fmt.Errorf("%w: an address assignment describes only an ip_address, not a %s", ErrInvalidSighting, raw.Kind)
		}
		if raw.Provenance.Claimed {
			switch {
			case raw.Kind != KindIPAddress:
				return IntakeResult{}, fmt.Errorf("%w: only an ip_address can be claimed, not a %s", ErrInvalidSighting, raw.Kind)
			case raw.Assignment == AssignmentDynamic:
				return IntakeResult{}, fmt.Errorf("%w: a claimed address cannot be a DHCP lease", ErrInvalidSighting)
			case !claimsFirstHand(s.Source, admission):
				return IntakeResult{}, fmt.Errorf("%w: an address can be claimed only by a measured, first-hand sighting (channel %q, source %q)",
					ErrInvalidSighting, s.Channel, s.Source.Kind)
			}
		}
	}

	snap, err := in.repo.SegmentSnapshot(ctx, s.TenantID)
	if err != nil {
		return IntakeResult{}, fmt.Errorf("identity: intake: segment snapshot for tenant %s: %w", s.TenantID, err)
	}

	admission.ReceiptID = s.ReceiptID
	admission.CollectorVersion = s.CollectorVersion
	b := &intakeBuild{
		in: in, s: s, snap: snap,
		res: IntakeResult{Snapshot: snap},
		obs: Observation{
			TenantID:            s.TenantID,
			Admission:           admission,
			ClassHint:           s.ClassHint,
			ClassProvenance:     s.ClassProvenance,
			Source:              s.Source,
			ObservedAt:          s.ObservedAt,
			Confidence:          s.Confidence,
			Network:             Network{Ownership: s.Ownership, Type: s.NetworkType},
			Attributes:          maps.Clone(s.Attributes),
			TLSCertFingerprints: append([]string(nil), s.TLSCertFingerprints...),
		},
		seen: map[string]int{},
	}
	b.run(ctx)
	if b.err != nil {
		return IntakeResult{}, b.err
	}
	res := b.res
	res.Observation = b.obs
	if len(res.Observation.Identifiers) == 0 {
		return res, fmt.Errorf("%w: every identifier the sighting carried was rejected or withheld", ErrNoUsableIdentifier)
	}
	return res, nil
}

// intakeBuild is one Assess call's working state.
type intakeBuild struct {
	in   *Intake
	s    Sighting
	snap SegmentSnapshot
	obs  Observation
	res  IntakeResult
	// seen maps an identifier key to its index in obs.Identifiers, so a value
	// reported twice is one identifier (with the stronger markings of both).
	seen map[string]int
	// primary is the first REAL segment an address in the sighting resolved
	// to, empty when none did.
	primary string
	// firstAddr and firstMAC are display-name fallbacks.
	firstAddr, firstMAC string
	// err is a store read that failed mid-build (the prior-scope bridge's
	// ownership lookup). Assess returns it instead of a partial observation.
	err error
}

// sightedAddr is one parsed ip_address of the sighting with its scope.
type sightedAddr struct {
	raw   SightedIdentifier
	addr  netip.Addr
	scope string
}

func (b *intakeBuild) run(ctx context.Context) {
	s := b.s

	// Pass 1: every address scoped on its own, so the sighting's primary
	// segment is known before any name or link-local address needs it.
	var addrs []sightedAddr
	for _, raw := range s.Identifiers {
		if raw.Kind != KindIPAddress {
			continue
		}
		v, err := Normalize(KindIPAddress, raw.Value)
		if err != nil {
			b.reject(raw, err)
			continue
		}
		addr := netip.MustParseAddr(v)
		scope, _ := b.snap.ScopeForAddress(addr, s.CloudNetworkRef)
		addrs = append(addrs, sightedAddr{raw: raw, addr: addr, scope: scope})
		if b.primary == "" && scope != ScopeTenantDefault {
			b.primary = scope
		}
	}

	statedMAC := false
	for _, raw := range s.Identifiers {
		if raw.Kind == KindMACAddress && strings.TrimSpace(raw.Value) != "" {
			// Counted even when hygiene withholds it below: a MAC the
			// sighting stated is better evidence than one Intake could derive,
			// and a derived one that differed from it would be noise.
			statedMAC = true
		}
	}

	// Pass 2: addresses — hygiene, then the identifier.
	for _, a := range addrs {
		if mac, ok := derive.MACFromEUI64(a.addr); ok && !statedMAC {
			b.addDerivedMAC(mac, derive.RefEUI64(a.addr))
		}
		switch attrlist.AddressAttribute(a.addr, b.primary != "") {
		case attrlist.KeyIPv6Temporary:
			b.withhold(a.raw.Kind, a.addr.String(), WithheldTemporaryIPv6, attrlist.KeyIPv6Temporary)
			continue
		case attrlist.KeyLinkLocal:
			b.withhold(a.raw.Kind, a.addr.WithZone("").String(), WithheldUnscopedLinkLocal, attrlist.KeyLinkLocal)
			continue
		}
		scope := a.scope
		if a.addr.Is6() && a.addr.IsLinkLocalUnicast() {
			// Unique only on its own link, which no segment ever contains: it
			// identifies within the segment the sighting was made in.
			scope = b.primary
		}
		if b.firstAddr == "" {
			b.firstAddr = a.addr.String()
		}
		id := Identifier{
			Kind: KindIPAddress, Value: a.addr.String(), Scope: scope,
			Assignment: a.raw.Assignment,
			// The host calling the address a lease outranks everything else:
			// a declared or self-reported lease is still a lease.
			Pinned: a.raw.Assignment != AssignmentDynamic &&
				(b.kindOf(a.raw) == SourceDeclared || a.raw.Provenance.SelfReported || a.raw.Provenance.Claimed || a.raw.Assignment == AssignmentStatic),
			// Validated in Assess: an ip_address, not a lease, first-hand.
			Claimed: a.raw.Provenance.Claimed,
		}
		b.add(a.raw, id)
		if s.BridgePriorScope && scope != ScopeTenantDefault && scope != "" {
			b.bridgePriorScope(ctx, a.raw, id)
		}
	}
	if b.err != nil {
		return
	}

	// Pass 3: everything else, in the sighting's order.
	var names, synthetic []string
	for _, raw := range s.Identifiers {
		switch raw.Kind {
		case KindIPAddress:
			continue
		case KindHostname, KindFQDN:
			if n, ok := b.addName(ctx, raw, &synthetic); ok {
				names = append(names, n)
			}
		case KindMACAddress:
			b.addMAC(raw)
		case KindSerialNumber:
			b.add(raw, Identifier{Kind: KindSerialNumber, Value: raw.Value})
			if !statedMAC {
				if mac, ok := derive.MACFromSerialRegistered(raw.Value); ok {
					b.addDerivedMAC(mac, derive.RefSerial(raw.Value))
				}
			}
		case KindName:
			// A name identifies within a class (ADR-0002 D3 erratum). With no
			// class hint it falls to the tenant default, as Normalized does.
			b.add(raw, Identifier{Kind: KindName, Value: raw.Value, Scope: s.ClassHint})
		case KindCMDBSysID:
			b.add(raw, Identifier{Kind: KindCMDBSysID, Value: raw.Value, Scope: raw.Profile})
		case KindSSHHostKeyFingerprint:
			b.add(raw, Identifier{Kind: raw.Kind, Value: raw.Value, KeyAlgorithm: raw.KeyAlgorithm})
		default:
			// agent_id, sensor_id, cloud_resource_id, and any kind Normalize
			// does not know (rejected there).
			b.add(raw, Identifier{Kind: raw.Kind, Value: raw.Value})
		}
	}

	// The sighting's own segment: its first real address segment, else the
	// first real scope a name found, else the tenant default — never empty.
	b.obs.Network.SegmentID = b.primary
	if b.obs.Network.SegmentID == "" {
		for _, id := range b.obs.Identifiers {
			if (id.Kind == KindHostname || id.Kind == KindIPAddress) && id.Scope != ScopeTenantDefault {
				b.obs.Network.SegmentID = id.Scope
				break
			}
		}
	}
	if b.obs.Network.SegmentID == "" {
		// An fqdn identifies without a scope, but a `domain` segment still
		// PLACES the sighting it names. Domain patterns are dotted
		// (`corp.example.com`), so the names they match are almost always
		// fqdns: without this, a sighting carrying only `db.corp.example.com`
		// landed in the tenant default and the domain segment placed nothing,
		// where both services' observationScope placed it by name.
		for _, id := range b.obs.Identifiers {
			if id.Kind != KindFQDN {
				continue
			}
			if scope, ok := b.snap.ScopeForName(id.Value); ok {
				b.obs.Network.SegmentID = scope
				break
			}
		}
	}
	if b.obs.Network.SegmentID == "" {
		b.obs.Network.SegmentID = ScopeTenantDefault
	}

	// DynamicScopes: every scope this observation names, by its STORED
	// effective posture and nothing else.
	for _, scope := range b.scopesNamed() {
		if b.snap.IsDynamic(scope) {
			if b.obs.DynamicScopes == nil {
				b.obs.DynamicScopes = map[string]bool{}
			}
			b.obs.DynamicScopes[scope] = true
		}
	}

	if len(s.Endpoints) > 0 {
		b.obs.Endpoints = make([]EndpointObservation, 0, len(s.Endpoints))
		for _, ep := range s.Endpoints {
			b.obs.Endpoints = append(b.obs.Endpoints, ep.Sanitized())
		}
	}

	// Names are context, not identity. A synthetic name is still the best
	// LABEL when it is the only one.
	labels := append(append([]string{}, names...), synthetic...)
	if h := hostnamequality.BestHostname(labels...); h != "" {
		b.obs.Hostname = strings.ToLower(h)
	}
	switch {
	case strings.TrimSpace(s.DisplayName) != "":
		b.obs.DisplayName = strings.TrimSpace(s.DisplayName)
	case hostnamequality.Best(labels...) != "":
		b.obs.DisplayName = strings.ToLower(hostnamequality.Best(labels...))
	case b.firstAddr != "":
		b.obs.DisplayName = b.firstAddr
	default:
		b.obs.DisplayName = b.firstMAC
	}
}

// addName files, scopes and grades one hostname or fqdn. It returns the
// normalised name when it became an identifier; a synthetic name is appended to
// *synthetic instead.
func (b *intakeBuild) addName(ctx context.Context, raw SightedIdentifier, synthetic *[]string) (string, bool) {
	v := strings.TrimSpace(raw.Value)
	measured := b.kindOf(raw) == SourceMeasured || b.kindOf(raw) == SourceInferred
	if v != "" && measured && !looksLikeAddress(v) && !hostnamequality.IsIdentityName(v) {
		// Not identity ( D1): a UUID-form, IP-encoded or `none` name.
		// Judged only for what a collector SAW — a name a person or a system
		// of record supplied is a statement about which device this is.
		*synthetic = append(*synthetic, v)
		b.withhold(raw.Kind, v, WithheldSyntheticName, attrlist.KeySyntheticNames)
		return "", false
	}

	// One filing rule for every path: a dotted name is an fqdn — globally
	// unique, no scope — EXCEPT `.local`, which is link-scoped (RFC 6762 §3)
	// and stays a scoped hostname. Filing `.local` as an fqdn let a gateway
	// that reflected a laptop's announcement absorb the laptop by name.
	kind := KindHostname
	if strings.Contains(strings.TrimSuffix(v, "."), ".") && !hostnamequality.IsMDNSLocalName(v) {
		kind = KindFQDN
	}
	id := Identifier{Kind: kind, Value: v}
	if kind == KindHostname {
		id.Scope = b.nameScope(raw)
	}
	if kind == KindHostname && measured {
		// B2: a name many unrelated devices carry is recorded but cannot
		// decide. Never for a declared name, and never an fqdn (Mark checks).
		id = b.in.generic.Mark(ctx, b.s.TenantID, id)
	}
	n, ok := b.add(raw, id)
	return n.Value, ok
}

// nameScope is THE name-scope rule:
//
//  1. the segment of the address the name was seen at, when that is a real
//     segment;
//  2. with no address of its own, the sighting's first real address segment;
//  3. otherwise the domain rule ([SegmentSnapshot.ScopeForName]);
//  4. otherwise the tenant default.
//
// An address in a declared subnet is a stronger statement than a name matching
// a domain pattern, which is why 1 and 2 come first — the order
// shared/network.MatchSegment has always used. Rule 3 now applies whenever no
// address placed the name; before Intake a host whose address was in no CIDR
// segment never reached its domain segment in either service ( item 8).
func (b *intakeBuild) nameScope(raw SightedIdentifier) string {
	if ctxAddr := strings.TrimSpace(raw.Address); ctxAddr != "" {
		if addr, err := netip.ParseAddr(ctxAddr); err == nil {
			if scope, _ := b.snap.ScopeForAddress(addr, b.s.CloudNetworkRef); scope != ScopeTenantDefault {
				return scope
			}
		}
	} else if b.primary != "" {
		return b.primary
	}
	if scope, ok := b.snap.ScopeForName(raw.Value); ok {
		return scope
	}
	return ScopeTenantDefault
}

// bridgePriorScope adds the tenant-default copy of a segment-scoped address
// when that copy already has an owner ([Sighting.BridgePriorScope]).
func (b *intakeBuild) bridgePriorScope(ctx context.Context, raw SightedIdentifier, id Identifier) {
	if b.err != nil {
		return
	}
	owners, err := b.in.repo.FindByIdentifier(ctx, b.s.TenantID, KindIPAddress, id.Value, ScopeTenantDefault)
	if err != nil {
		b.err = fmt.Errorf("identity: intake: looking up the prior tenant-default owner of %s: %w", id.Value, err)
		return
	}
	if len(owners) == 0 {
		return
	}
	prior := id
	prior.Scope = ScopeTenantDefault
	b.add(raw, prior)
}

// addMAC applies the MAC hygiene and records the MAC when it survives.
func (b *intakeBuild) addMAC(raw SightedIdentifier) {
	v, err := Normalize(KindMACAddress, raw.Value)
	if err != nil {
		b.reject(raw, err)
		return
	}
	if b.kindOf(raw) != SourceDeclared && b.s.Channel != ChannelPerson {
		if _, virtual := hostobs.VirtualMACProtocol(v); virtual {
			b.withhold(KindMACAddress, v, WithheldVirtualRouterMAC, "")
			return
		}
		if !keepsLocalMACs(b.s.Channel) && hostobs.MACLocallyAdministered(v) {
			b.withhold(KindMACAddress, v, WithheldLocallyAdministeredMAC, "")
			return
		}
	}
	if b.firstMAC == "" {
		b.firstMAC = v
	}
	b.add(raw, Identifier{Kind: KindMACAddress, Value: v})
}

// addDerivedMAC appends a MAC worked out from other evidence, as an inferred
// identifier the engine keeps the provenance of.
func (b *intakeBuild) addDerivedMAC(mac, ref string) {
	b.add(SightedIdentifier{Kind: KindMACAddress, Confidence: derivedMACConfidence,
		Provenance: IdentifierProvenance{Kind: SourceInferred, Ref: ref}},
		Identifier{Kind: KindMACAddress, Value: mac})
}

// add normalises id (scope included), applies raw's confidence and
// provenance, and appends it — or merges it into the identical identifier
// already present. It reports the identifier as stored and whether it was
// kept.
func (b *intakeBuild) add(raw SightedIdentifier, id Identifier) (Identifier, bool) {
	if raw.Profile != "" && raw.Kind != KindCMDBSysID {
		b.reject(raw, fmt.Errorf("identity: %s: a sync profile scopes only cmdb_sys_id", raw.Kind))
		return Identifier{}, false
	}
	id.Confidence = raw.Confidence
	if id.Confidence <= 0 {
		id.Confidence = 1
	}
	if id.Generic && id.Confidence > GenericConfidence {
		id.Confidence = GenericConfidence
	}
	if k := b.kindOf(raw); k == SourceInferred {
		ref := raw.Provenance.Ref
		if ref == "" {
			ref = b.s.Source.Ref
		}
		id.Source = Source{Kind: SourceInferred, Ref: ref}
	} else if SourceRank(k) < SourceRank(b.s.Source.Kind) {
		// An identifier the collector MEASURED inside a sighting a person
		// declared (the probe's MAC on an Add device form): stored measured,
		// so the person is not credited with typing it. The engine honours a
		// lower provenance, never a higher one.
		ref := raw.Provenance.Ref
		if ref == "" {
			ref = b.s.Source.Ref
		}
		id.Source = Source{Kind: k, Ref: ref, Mode: b.s.Source.Mode}
	}
	n, err := id.Normalized()
	if err != nil {
		b.reject(raw, err)
		return Identifier{}, false
	}
	if i, dup := b.seen[n.Key()]; dup {
		have := &b.obs.Identifiers[i]
		have.Pinned = have.Pinned || n.Pinned
		have.Claimed = have.Claimed || n.Claimed
		if have.Assignment == "" {
			have.Assignment = n.Assignment
		}
		// A native observation of a value Intake also derived is the stronger
		// claim: the derived provenance gives way.
		if have.Inferred() && !n.Inferred() {
			have.Source, have.Confidence = n.Source, n.Confidence
		} else if b.rankOf(n.Source) > b.rankOf(have.Source) {
			// Typed by the person AND read by the probe: the stronger claim.
			have.Source = n.Source
		}
		return *have, true
	}
	b.seen[n.Key()] = len(b.obs.Identifiers)
	b.obs.Identifiers = append(b.obs.Identifiers, n)
	return n, true
}

// rankOf is the provenance rank of an identifier's own source, where empty
// means the sighting's.
func (b *intakeBuild) rankOf(src Source) int {
	if src.Kind == "" {
		return SourceRank(b.s.Source.Kind)
	}
	return SourceRank(src.Kind)
}

// kindOf is the effective source kind of one identifier.
func (b *intakeBuild) kindOf(raw SightedIdentifier) SourceKind {
	if raw.Provenance.Kind != "" {
		return raw.Provenance.Kind
	}
	return b.s.Source.Kind
}

func (b *intakeBuild) reject(raw SightedIdentifier, err error) {
	b.res.Rejected = append(b.res.Rejected, RejectedIdentifier{
		Identifier: Identifier{Kind: raw.Kind, Value: raw.Value}, Err: err,
	})
}

func (b *intakeBuild) withhold(kind Kind, value, reason, attrKey string) {
	b.res.Withheld = append(b.res.Withheld, Withheld{Kind: kind, Value: value, Reason: reason})
	if attrKey == "" {
		return
	}
	if b.res.AttributeEvidence == nil {
		b.res.AttributeEvidence = map[string][]string{}
	}
	b.res.AttributeEvidence[attrKey] = append(b.res.AttributeEvidence[attrKey], value)
}

// scopesNamed is every segment scope the observation refers to — its own and
// each scoped identifier's — once each.
func (b *intakeBuild) scopesNamed() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(b.obs.Network.SegmentID)
	for _, id := range b.obs.Identifiers {
		if id.Kind == KindHostname || id.Kind == KindIPAddress {
			add(id.Scope)
		}
	}
	return out
}

// looksLikeAddress reports whether a name slot holds an address; that is a
// normalisation reject ("an IP is never a name"), not a synthetic name.
func looksLikeAddress(v string) bool {
	_, err := netip.ParseAddr(strings.TrimSuffix(v, "."))
	return err == nil
}
