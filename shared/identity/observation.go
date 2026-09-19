package identity

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Ownership values for [Network.Ownership]: whether the address the
// observation was seen at is inside the tenant's own space.
//
// The vocabulary has to bridge two spellings. ADR-0002 D1 says class
// `external` "when the address is outside the tenant's owned space", while the
// live classifier (shared/approval.Classification) emits "internal",
// "third_party" and "unknown". Rather than pick one and silently mis-class
// everything the other produces, [Network.IsExternal] accepts both spellings
// of outside.
const (
	// OwnershipInternal — the address is in a known tenant network segment.
	OwnershipInternal = "internal"
	// OwnershipExternal — the address is outside the tenant's owned space.
	OwnershipExternal = "external"
	// OwnershipThirdParty is the live classifier's spelling of
	// [OwnershipExternal] and is treated as identical.
	OwnershipThirdParty = "third_party"
	// OwnershipUnknown — a private address in no registered segment. It is
	// INSIDE for classification purposes: an unregistered internal subnet is
	// still the tenant's, and calling it external would put the tenant's own
	// hosts in the third-party bucket.
	OwnershipUnknown = "unknown"
)

// Network is where the observation was seen, as the `observation` query target
// exposes it to approval rules (QUERY_LANGUAGE §4.1 and §8):
//
//	network.ownership  →  Ownership
//	network.type       →  Type
//	network.segment_id →  SegmentID, and exists(network.segment_id) is SegmentID != ""
type Network struct {
	// Ownership is one of the Ownership* constants.
	Ownership string `json:"ownership,omitempty"`
	// Type is the classifier's network type: "private" or "public".
	Type string `json:"type,omitempty"`
	// SegmentID is the tenant network segment the address falls in, empty when
	// it falls in none. It is also the natural [Identifier.Scope] for hostname
	// and ip_address identifiers.
	SegmentID string `json:"segment_id,omitempty"`
}

// IsExternal reports whether the observation was seen outside the tenant's
// owned space, and therefore whether an asset created from it is class
// `external` rather than `unknown_host` (ADR-0002 D1).
func (n Network) IsExternal() bool {
	switch n.Ownership {
	case OwnershipExternal, OwnershipThirdParty:
		return true
	default:
		return false
	}
}

// EndpointObservation is one (address|fqdn, port, transport) an asset was seen
// exposing. Endpoints have DEPENDENT identity: they are never matched on their
// own, only upserted under an asset the identifiers resolved
// (ADR-0002 D3). Source and SeenAt are provenance filled in by the engine.
type EndpointObservation struct {
	// Address is the IP, empty when only a name is known. At least one of
	// Address and FQDN must be set.
	Address string `json:"address,omitempty"`
	FQDN    string `json:"fqdn,omitempty"`
	// Port is 0 for an at-rest or declared endpoint; DATA_MODEL §2 stores that
	// as NULL and the old "AT-REST" sentinel is retired.
	Port int `json:"port,omitempty"`
	// Transport is "tcp", "udp" or "none".
	Transport string `json:"transport,omitempty"`
	// Protocol is the protocol_type enum value, empty when unidentified.
	Protocol string `json:"protocol,omitempty"`

	// ServiceName is what is listening, where the source knows. A host's own
	// view of its sockets names the PROCESS holding each one, which is the
	// strongest form of this claim available anywhere in the product — stronger
	// than a banner, which is whatever a service chose to say about itself.
	ServiceName string `json:"service_name,omitempty"`
	// ServiceConfidence and ServiceIdentificationMethod are how the name was
	// arrived at, in the vocabulary asset_endpoints already stores ("reported"
	// / "inferred", and a method string). Empty leaves the column's default,
	// which is `none` — an endpoint with a name and no method would be a claim
	// with no argument behind it.
	ServiceConfidence           string `json:"service_confidence,omitempty"`
	ServiceIdentificationMethod string `json:"service_identification_method,omitempty"`

	// BoundLocal says whether the socket is reachable only from the host
	// itself. THREE-VALUED, which is why it is a pointer: nil means nobody
	// established it (every endpoint a network scan found — a scan cannot know,
	// it only sees what answers), and an explicit false is a measurement that
	// the service IS exposed to the network. Collapsing nil into false would
	// have every scanned endpoint assert exposure nobody measured.
	BoundLocal *bool `json:"bound_local,omitempty"`

	Source Source    `json:"source,omitzero"`
	SeenAt time.Time `json:"seen_at,omitzero"`
}

// Key is the dependent-identity tuple of an endpoint within its asset:
// address-or-fqdn, port, transport. It matches the unique index of
// DATA_MODEL §2 and is what [Repository.UpsertEndpoints] upserts on.
//
// Note that when Address is set, FQDN plays no part in this key at all — the
// same rule [EndpointObservation.Sanitized] enforces at the field level. An
// endpoint identified by an address is one thing regardless of what name (if
// any) travels alongside it.
func (e EndpointObservation) Key() string {
	addr := e.Address
	if addr == "" {
		addr = e.FQDN
	}
	return EndpointKey(addr, e.Port, e.Transport)
}

// Sanitized returns a copy of the endpoint observation with an FQDN that is
// actually an IP literal folded away: "an IP is never a name" is already the
// rule [normalizeDNSName] enforces for the identifier kinds ("use ip_address"),
// and an endpoint needs the same rule plus one more — an endpoint identified
// by an address is identified by (address, port, transport); FQDN is an
// ATTRIBUTE of that endpoint, not part of what identifies it.
//
// A scan target that happens to be an IP literal ("192.0.2.230") used to be
// written into FQDN unchanged by every builder that assumed "the target
// string" was a name, because it has dots and passes a naive hostname check.
// That produced a second asset_endpoints row for a listener already recorded
// with fqdn NULL from a passive observation — same address, same port, same
// transport, "duplicate" only because one row's name field held an address
// spelled as text.
//
// The fix: if FQDN parses as an IP address, it is dropped. If the endpoint had
// no address of its own, the literal is promoted to Address instead — the
// observation still describes a real socket, just not a named one.
func (e EndpointObservation) Sanitized() EndpointObservation {
	fqdn := strings.TrimSpace(e.FQDN)
	if fqdn == "" {
		return e
	}
	addr, err := netip.ParseAddr(fqdn)
	if err != nil {
		// Not an IP literal — an ordinary name, left alone.
		return e
	}
	out := e
	out.FQDN = ""
	if strings.TrimSpace(out.Address) == "" {
		out.Address = addr.Unmap().WithZone("").String()
	}
	return out
}

// Observation is one sighting handed to the engine by an intake path.
//
// It is deliberately a value with no behaviour beyond normalisation: the
// builders that construct one per intake path are workstream 1.2, and they
// live with the path that knows what it saw, not here.
//
// # The fields approval rules read
//
// QUERY_LANGUAGE §4.1 makes `observation` a query target, so the same
// predicate language that filters assets filters an in-flight discovery. The
// mapping from today's approval-rule JSON conditions (§8) is:
//
//	source:sensor                          →  Source.Producer()
//	network.ownership:internal             →  Network.Ownership
//	network.type:corporate                 →  Network.Type
//	confidence >= 0.8                      →  Confidence
//	exists(network.segment_id)             →  Network.SegmentID != ""
//	network.segment_id=<uuid>              →  Network.SegmentID
//
// `require_network_space_match` has no equivalent and is dropped (§8).
type Observation struct {
	// TenantID scopes everything. An observation with no tenant is rejected.
	TenantID string `json:"tenant_id"`

	Admission AdmissionEvidence `json:"admission,omitzero"`

	// ClassHint is the class the intake path believes this is, empty when it
	// has no opinion. It selects the identifier precedence and becomes the
	// created asset's class; when empty the engine falls back to `external` or
	// `unknown_host` (ADR-0002 D1) rather than guessing a better one.
	ClassHint string `json:"class_hint,omitempty"`

	// ClassProvenance is where ClassHint came from, when that is not the
	// observation's own source.
	//
	// The zero value means "the same place everything else in this observation
	// came from", which is what every intake meant before workstream 2.10b and
	// is still right for a hint the collector itself formed. A hint the RULE
	// ENGINE produced is different: the observation was measured, the
	// MAC-to-class mapping was not, and the rule that argued it has an id a
	// reviewer can follow. See [ClassSourceKind].
	ClassProvenance ClassProvenance `json:"class_provenance,omitzero"`

	Identifiers []Identifier          `json:"identifiers,omitempty"`
	Endpoints   []EndpointObservation `json:"endpoints,omitempty"`

	Source     Source    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`

	Network Network `json:"network,omitzero"`

	// Confidence is the intake path's confidence in the observation as a
	// whole, 0..1. It is what the approval rule's `min_confidence` reads.
	Confidence float64 `json:"confidence"`

	// DisplayName and Hostname are convenience context for a created asset.
	// They are not identity: the authoritative list is Identifiers.
	DisplayName string `json:"display_name,omitempty"`
	Hostname    string `json:"hostname,omitempty"`

	// Attributes are the class-specific attributes the intake path observed
	// (vendor, model, operating_system …), exactly as they would be written to
	// `assets.attributes`.
	//
	// The engine does not WRITE them — reconciling an attribute against what an
	// asset already carries is ADR-0002 D4's job and belongs to the intake
	// path — and reads only [SummaryAttributeKeys] from them, to hand the
	// matcher seam something to compare. A pair of records agreeing on a serial
	// is identity; a pair disagreeing about the vendor is evidence of two
	// things, and there was previously no way for a matcher to know it.
	Attributes map[string]any `json:"attributes,omitempty"`

	// DynamicScopes names the scopes in this observation that hand addresses
	// out dynamically, so an ip_address inside one does not decide a match
	// (ADR-0002 D3) — today's DHCP lease is tomorrow's other host.
	//
	// It is on the OBSERVATION and not only on [Config] because whether a
	// segment is dynamic is a per-tenant, per-segment fact the builder learns
	// at the moment it resolves the address
	// ([Repository.ScopeForAddress] returns it alongside the scope), while an
	// engine is built once and shared. The two are unioned; neither overrides
	// the other, because both are saying the same thing and a scope named by
	// either is dynamic.
	DynamicScopes map[string]bool `json:"dynamic_scopes,omitempty"`
}

// ClassProvenance is how an observation's class hint was decided.
//
// Empty Kind means "as the observation was": the engine then records the class
// with the observation's own source kind and producer, which is what happened
// before this type existed.
type ClassProvenance struct {
	// Kind is the class column's own vocabulary, which has one value more than
	// [SourceKind] — see [ClassSourceKind].
	Kind ClassSourceKind `json:"kind,omitempty"`

	// Ref is what `assets.class_source_ref` records: the classification_rules
	// row id for a rule-derived class.
	Ref string `json:"ref,omitempty"`

	// Confidence is what the DECIDER asserts about the class, which is not the
	// same number as the observation's confidence in itself. A sensor can be
	// certain it saw a MAC (Observation.Confidence 1) while the OUI rule that
	// turns that MAC into `printer` asserts 0.85.
	//
	// Zero means NOT STATED and the engine falls back to the observation's own
	// confidence, exactly as it did before — the same "0 is not assessed"
	// distinction the risk score and the PQC buckets keep.
	Confidence float64 `json:"confidence,omitempty"`
}

// IsZero reports whether the provenance says nothing, so `omitzero` works and a
// caller can ask the question without comparing three fields.
func (c ClassProvenance) IsZero() bool {
	return c.Kind == "" && c.Ref == "" && c.Confidence == 0
}

// RejectedIdentifier is an identifier that could not be normalised, kept with
// the reason. Nothing is dropped quietly: a caller that chooses leniency with
// [Observation.Sanitize] gets the rejects back and can log or surface them.
type RejectedIdentifier struct {
	Identifier Identifier
	Err        error
}

// Sanitize returns a copy of the observation with every identifier normalised,
// and the ones that could not be normalised removed and returned separately.
//
// [Engine.Resolve] is strict: it errors on an identifier that does not
// normalise, because at that point a malformed identifier is a bug in the
// caller and a silent skip is how bad data gets into an inventory. An intake
// path that must not fail a whole batch for one bad MAC calls Sanitize first —
// which makes the leniency a visible decision at the call site, with the
// rejects in hand, rather than a default nobody can see.
func (o Observation) Sanitize() (Observation, []RejectedIdentifier) {
	out := o
	out.Identifiers = make([]Identifier, 0, len(o.Identifiers))
	var rejected []RejectedIdentifier
	for _, id := range o.Identifiers {
		n, err := id.Normalized()
		if err != nil {
			rejected = append(rejected, RejectedIdentifier{Identifier: id, Err: err})
			continue
		}
		out.Identifiers = append(out.Identifiers, n)
	}
	if len(o.Endpoints) > 0 {
		// Endpoints never error (there is nothing to reject — an IP-literal
		// FQDN is not malformed, it is just misfiled, and [Sanitized] refiles
		// it), so this is a plain map rather than the identifier loop's
		// reject-and-continue.
		out.Endpoints = make([]EndpointObservation, 0, len(o.Endpoints))
		for _, ep := range o.Endpoints {
			out.Endpoints = append(out.Endpoints, ep.Sanitized())
		}
	}
	return out, rejected
}

// EndpointKey builds the dependent-identity key of an endpoint within its
// asset. Exported so the phase-1 upsert and this package agree on one spelling
// of the tuple — two spellings of a dedupe key is the failure ADR-0002 D3
// exists to end.
func EndpointKey(addressOrFQDN string, port int, transport string) string {
	t := strings.ToLower(strings.TrimSpace(transport))
	if t == "" {
		t = "none"
	}
	return strings.ToLower(strings.TrimSpace(addressOrFQDN)) + "|" + strconv.Itoa(port) + "|" + t
}

// ApplicationKey builds the natural key of an application under its host:
// (product, instance) from ADR-0002 D3's dependent-identity rule. Pass the
// result to [Engine.ResolveDependent] as its key argument.
func ApplicationKey(product, instance string) string {
	return strings.ToLower(strings.TrimSpace(product)) + "|" + strings.ToLower(strings.TrimSpace(instance))
}

// ServiceKey builds the natural key of a service: its name, unique per tenant.
func ServiceKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
