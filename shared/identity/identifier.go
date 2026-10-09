package identity

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// Kind is an identifier kind: one of the nine of ADR-0002 D3. It is a defined
// type rather than a bare string so a wrong constant is a compile error, and
// so [Kind.Valid] has somewhere to live. The class registry stores the same
// vocabulary as plain strings (assetclass.IdentifierKinds); [KindsFromStrings]
// converts, and TestKindRegistryAgreesWithAssetClass pins the two together.
type Kind string

// The nine identifier kinds, in the default precedence order of ADR-0002 D3 —
// most durable first. A class may reorder or drop kinds; it may not invent
// one.
const (
	// KindDeclarationID is issued by the server for an explicit operator
	// confirmation. It never makes an observed alias authoritative.
	KindDeclarationID Kind = "declaration_id"
	// KindAgentID is a host agent's own installation id: the strongest
	// identifier we have, because we issued it.
	KindAgentID Kind = "agent_id"
	// KindSensorID identifies a sensor installation, independently of a device agent.
	KindSensorID Kind = "sensor_id"
	// KindCloudResourceID is an ARN, Azure resource id or GCP self-link.
	KindCloudResourceID Kind = "cloud_resource_id"
	// KindSerialNumber is the hardware serial.
	KindSerialNumber Kind = "serial_number"
	// KindCMDBSysID is the sys_id of the CI in an external CMDB, scoped to the
	// sync profile it came from.
	KindCMDBSysID Kind = "cmdb_sys_id"
	// KindSSHHostKeyFingerprint is the fingerprint of the host key an SSH
	// endpoint presented.
	KindSSHHostKeyFingerprint Kind = "ssh_host_key_fingerprint"
	// KindMACAddress is a layer-2 address, canonicalised to aa:bb:cc:dd:ee:ff.
	KindMACAddress Kind = "mac_address"
	// KindFQDN is a fully qualified domain name: at least two labels, no
	// trailing dot, lowercase.
	KindFQDN Kind = "fqdn"
	// KindHostname is a short name. It identifies only WITHIN a scope (a
	// segment or site) — see [Kind.RequiresScope].
	KindHostname Kind = "hostname"
	// KindIPAddress is an IP address. It identifies only within a scope, and
	// never within one flagged dynamic — see [Config.DynamicScopes].
	KindIPAddress Kind = "ip_address"

	// KindName is a DECLARED name, scoped by class key. It is the tenth kind
	// and it is not in the default precedence: it exists for the classes that
	// have no independent identity of their own and are identified by what
	// somebody called them — the `service` branch (ADR-0002 D3 erratum:
	// "services identify by (tenant, class, name), realised as the `name`
	// identifier kind").
	//
	// It is deliberately absent from [DefaultPrecedenceList] so a class that
	// does not list it can never match on one. A server that happens to carry a
	// declared name is still a server, identified by its serial.
	KindName Kind = "name"
)

// ScopeTenantDefault is the scope a scoped identifier carries when no narrower
// scope applies: the tenant-wide default space.
//
// ADR-0002 D3 erratum: "hostname and ip_address are scoped to the matching
// segment, else to the tenant-wide default scope; ip_address never votes in a
// dynamic segment." The original rule — no segment means no scope, and an
// unscoped weak identifier does not vote — had a consequence nobody followed
// through: a tenant with NO segments configured, which is every fresh tenant,
// produced an identifier that could never decide anything, so every
// re-observation of one host created another asset, each after the first with
// no identifiers at all. Measured before the fix: one host ingested three times
// became three assets.
//
// A sentinel rather than a nullable column because the uniqueness key is
// `(tenant_id, kind, value, coalesce(scope, ”))` — a literal scope value works
// unchanged, and `tenant` cannot collide with a segment id, which is a uuid.
//
// When a tenant later creates segments, an asset identified under the default
// scope KEEPS its identifiers; a re-observation inside a new segment adds the
// segment-scoped identifier alongside, and the engine matches through the
// stronger kinds first. A tenant reorganising its segments may therefore see
// merge proposals, which is correct: it has just told us two things it used to
// call one might be two.
const ScopeTenantDefault = "tenant"

// DefaultPrecedence is the order of ADR-0002 D3, used when an observation
// carries no class hint or the hint's class is not in the registry. It is
// returned as a fresh slice by [DefaultPrecedenceList]; the variable itself is
// not exported to keep it from being reordered in place by a caller.
var defaultPrecedence = []Kind{
	KindAgentID,
	KindSensorID,
	KindCloudResourceID,
	KindSerialNumber,
	KindCMDBSysID,
	KindSSHHostKeyFingerprint,
	KindMACAddress,
	KindFQDN,
	KindHostname,
	KindIPAddress,
}

// allKinds is the whole vocabulary: the nine of the default precedence plus
// `name`, which is valid but never votes unless a class lists it. Validity and
// precedence are different questions, and conflating them is what would let a
// `name` identifier decide a server's identity.
var allKinds = append([]Kind{KindDeclarationID}, append(append([]Kind{}, defaultPrecedence...), KindName)...)

// DefaultPrecedenceList returns a copy of the default precedence order.
//
// It is the NINE of ADR-0002 D3; `name` is not among them. Use [AllKinds] for
// the whole vocabulary (validation, display ordering).
func DefaultPrecedenceList() []Kind {
	out := make([]Kind, len(defaultPrecedence))
	copy(out, defaultPrecedence)
	return out
}

// AllKinds returns a copy of every identifier kind, default-precedence order
// first and `name` last.
func AllKinds() []Kind {
	out := make([]Kind, len(allKinds))
	copy(out, allKinds)
	return out
}

// Valid reports whether k is one of the ten kinds.
func (k Kind) Valid() bool {
	for _, known := range allKinds {
		if k == known {
			return true
		}
	}
	return false
}

// Singleton reports whether an asset may hold at most ONE value of this kind
// (within one scope). Collector installations and durable resource IDs are singletons:
//
//	agent_id           one device-agent installation per host
//	sensor_id          one sensor installation per host
//	cloud_resource_id  one ARN / resource id names one provider resource
//	serial_number      one chassis, one serial
//	cmdb_sys_id        one CI per sync profile (the profile IS the scope)
//
// The other six are legitimately multi-valued: a machine has several MACs,
// several addresses, several names, and several SSH endpoints with different
// host keys. Nothing about holding two of those says the asset is two things.
//
// # Why the distinction is load-bearing
//
// [Engine.Resolve] walks the class precedence and "the first kind that matches
// exactly one asset decides". A singleton value the engine has NEVER SEEN owns
// nothing, so it cannot decide — being high in the precedence list buys nothing
// when the value is new — and a LOWER-precedence kind decides instead. The
// observation's identifiers are then attached to whatever that decided, and the
// asset quietly acquires a second `cloud_resource_id`.
//
// That is an auto-merge of two resources, which ADR-0002 D5 forbids, arriving
// through the door marked "matched". It was reproduced against a real Postgres:
// two EC2 instances, different instance ids, different ARNs, the same private
// address (two VPCs with the same CIDR, or one address reused after a
// termination) became ONE asset carrying two `cloud_resource_id` identifiers,
// with no merge proposal — the second instance inheriting the first's approval
// state, tags and findings.
//
// So a singleton disagreement is treated as what it is: evidence that these are
// two different things, which outranks whatever weaker identifier they happen
// to share. See [Engine.Resolve]'s singleton guard.
//
// The comparison is per (kind, SCOPE), not per kind. `cmdb_sys_id` is scoped to
// the sync profile it came from, so one asset legitimately carries one sys_id
// per profile; two sys_ids in the SAME profile is the contradiction.
func (k Kind) Singleton() bool {
	switch k {
	case KindAgentID, KindSensorID, KindCloudResourceID, KindSerialNumber, KindCMDBSysID:
		return true
	default:
		return false
	}
}

// RequiresScope reports whether this kind identifies only within a scope.
//
// A hostname identifies "within a segment or site" and an IP "within a
// segment" (ADR-0002 D3): "printer-2" or 10.0.0.5 are answers to a question
// only once you say where you were standing. A `name` identifies within a
// class: two services may share a name only if they are different kinds of
// thing, and the class is what says so.
//
// There is always an answer. When no narrower scope applies the scope is
// [ScopeTenantDefault] — [Identifier.Normalized] fills it in — so an identifier
// of these kinds is never left unable to decide anything. The earlier rule
// (no scope, no vote) produced an identifier that could not match and an asset
// that could not be recognised again; see [ScopeTenantDefault].
func (k Kind) RequiresScope() bool {
	return k == KindHostname || k == KindIPAddress || k == KindName || k == KindDeclarationID
}

// DefaultScopeFor returns the scope a value of this kind carries when the
// caller has nothing narrower: the tenant-wide default for the scoped kinds,
// and no scope at all for the six globally unique ones.
func (k Kind) DefaultScopeFor() string {
	if k.RequiresScope() {
		return ScopeTenantDefault
	}
	return ""
}

// AcceptsScope reports whether a scope means anything for this kind:
// the segment for hostname and ip_address, the class key for name, the sync
// profile for cmdb_sys_id (DATA_MODEL §2). The other six kinds are globally
// unique by construction and a scope on one is meaningless.
//
// It is not cosmetic. The uniqueness invariant is a unique index over tenant,
// kind, value and the coalesced scope, so a scope nobody asked for
// SPLITS the key: one serial number arriving once bare and once carrying the
// segment the collector happened to know becomes two rows, two owners, two
// assets — with no conflict, no proposal, and nothing in the history to say
// what happened. That is the "six intake paths, four dedupe keys" failure this
// package exists to end, reappearing one field to the right, so a scope on a
// global kind is rejected rather than trimmed away silently.
func (k Kind) AcceptsScope() bool {
	return k.RequiresScope() || k == KindCMDBSysID
}

// KindsFromStrings converts a precedence list from the class registry (plain
// strings) into kinds, dropping any value that is not one of the ten. A
// dropped value means the two registries have diverged, which
// TestKindRegistryAgreesWithAssetClass exists to prevent; dropping rather than
// erroring keeps a future registry addition from breaking identification
// everywhere at once.
func KindsFromStrings(in []string) []Kind {
	out := make([]Kind, 0, len(in))
	for _, s := range in {
		k := Kind(s)
		if k.Valid() {
			out = append(out, k)
		}
	}
	return out
}

// Identifier is one identifier observed for a thing.
//
// Kind, Value, Scope and Confidence are the identity of the row; Source and
// SeenAt are the provenance `asset_identifiers` also stores (DATA_MODEL §2)
// and are filled in by the engine from the observation, so a caller building
// an Observation does not set them.
//
// With ONE exception: a caller may mark an identifier it DERIVED rather than
// observed — a MAC recovered from an EUI-64 IPv6 address or read out of a
// MAC-shaped serial (shared/identity/derive, D3) — by setting
// Source.Kind to [SourceInferred] and Source.Ref to the evidence
// ("derived:eui64:<addr>", "derived:serial:<serial>"). The engine keeps that
// provenance instead of overwriting it with the observation's, so it reaches
// `asset_identifiers.source_kind/source_ref` and the asset page can say what
// the value was derived from. Any other per-identifier Source is ignored: a
// caller can only WEAKEN an identifier's provenance, never strengthen it. See
// [Identifier.Inferred] for the rules an inferred identifier votes under.
type Identifier struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	// Scope is the segment id for hostname and ip_address, and the sync
	// profile id for cmdb_sys_id. Empty for the global kinds.
	Scope string `json:"scope,omitempty"`
	// Confidence is 0..1, and 1.0 for a measured identifier.
	Confidence float64 `json:"confidence"`
	// Generic marks a hostname that many unrelated devices carry — a default
	// or role name (`iphone`, `printer`) or one the tenant already sees on
	// three or more assets ( B2). It is per-observation CONTEXT decided at
	// ingest ([GenericNames.Mark]); it is not part of the identity of the row
	// ([Identifier.Key] ignores it) and it is not stored: the name is still
	// recorded, as true, and the flag exists so the engine needs no lookup.
	Generic bool `json:"generic,omitempty"`

	// Pinned marks an `ip_address` that is not merely where the device was
	// seen: an operator DECLARED it on the asset, or the host REPORTED it about
	// itself (its agent, or an authenticated session reading its own interface
	// configuration). Owner decision 1 on: such an address still matches
	// its owner inside a DHCP segment, because a pinned address is not a lease.
	//
	// Like Generic it is per-observation context, not identity: [Identifier.Key]
	// ignores it. [Intake] sets it; the repositories turn it into the stored
	// `address_assignment = 'static'` ([Identifier.StoredAssignment]) unless
	// [Identifier.Assignment] says otherwise, and the engine's vote exemption
	// reads the OWNER's stored assignment, never this flag on the sighting
	// (pinned.go). It is meaningful only on `ip_address`.
	Pinned bool `json:"pinned,omitempty"`

	// Claimed marks an `ip_address` the device itself reported as an address
	// configured on its own interface, over a first-hand session the platform
	// opened: the canonical case is a gateway's address on each network it
	// routes. A claimed address is always [Identifier.Pinned], and it
	// does one more thing: it settles who else holds the address
	// (claimed.go). It re-homes from a provisional asset, or from one that
	// holds nothing but addresses, and it votes even in a dynamic scope
	// against any other holder, so that holder becomes a merge proposal
	// rather than silently keeping it.
	//
	// Per-observation context like Pinned: not part of [Identifier.Key], not
	// stored. [Intake] sets it, and only on a measured sighting whose channel
	// is direct and authoritative (an authenticated session).
	Claimed bool `json:"claimed,omitempty"`

	// Assignment is the explicit form of the same fact, for the one answer
	// Pinned cannot carry: a host reporting an address as a DHCP lease
	// ([AssignmentDynamic]). Empty defers to Pinned (and to a declared source):
	// see [Identifier.StoredAssignment]. Meaningful for `ip_address` only;
	// [Identifier.Normalized] clears it on every other kind. Provenance, not
	// identity: [Identifier.Key] ignores it.
	Assignment AddressAssignment `json:"address_assignment,omitempty"`

	// DeviceConfirmedAt is when an `ip_address` was last shown to be held by
	// the DEVICE its owner describes: a direct measurement decided by an
	// observed device-binding kind (a MAC, a host key, a serial, an agent)
	// that attached or re-attached the address to that owner (leasefresh.go,
	// ADR-0002 D3 erratum "the lease-fresh address"). A sighting that
	// touched the row by name does not advance it.
	//
	// Like Assignment it travels both ways: the engine sets it on the
	// addresses it attaches under a device-decided match, the stores keep
	// the newest value (`asset_identifiers.device_confirmed_at`, never moved
	// backwards) and LoadSummaries reports it on the owner's copy. Meaningful
	// for `ip_address` only; zero means nothing has confirmed a device there.
	DeviceConfirmedAt time.Time `json:"device_confirmed_at,omitzero"`

	// KeyAlgorithm is the key type of an `ssh_host_key_fingerprint` — the
	// family [NormalizeSSHKeyAlgorithm] returns (`ed25519`, `rsa`,
	// `ecdsa-p256`, …) — and empty for every other kind, or when the observer
	// did not say.
	//
	// It is a sibling of the value, not part of it. A host offers one key per
	// algorithm and a probe sees whichever one negotiation picked, so two
	// fingerprints on one host are normally two keys, not a rotation; the drift
	// classifier tells the cases apart by algorithm ( Decision 4). The
	// fingerprint alone is still the identity — a SHA-256 over the key blob,
	// which includes the type — so [Identifier.Key] ignores this, and rows
	// stored before it existed keep matching. Stores persist it
	// (`asset_identifiers.key_algorithm`) and fill it in on the next sighting
	// that carries it.
	KeyAlgorithm string `json:"key_algorithm,omitempty"`

	// Source and SeenAt are provenance, set by the engine.
	Source Source    `json:"source,omitzero"`
	SeenAt time.Time `json:"seen_at,omitzero"`
}

// AddressAssignment is how an `ip_address` came to be held by its asset — the
// `asset_identifiers.address_assignment` column. Empty is "nobody said", and it
// is the overwhelmingly common answer: a sensor that sees an address on the
// wire cannot tell a lease from a pin.
type AddressAssignment string

const (
	// AssignmentStatic is a pinned address: an operator declared it on the
	// asset, or the host's own agent reported the interface as statically
	// configured. It decides a match for its owner even inside a segment
	// flagged dynamic, because the segment's DHCP flag is a statement about
	// the range and this is a statement about this one address.
	AssignmentStatic AddressAssignment = "static"
	// AssignmentDynamic is an address the host's own agent reported as a
	// DHCP lease. Recorded, never a reason to vote.
	AssignmentDynamic AddressAssignment = "dynamic"
)

// Valid reports whether a is one of the two stored values or empty.
func (a AddressAssignment) Valid() bool {
	return a == "" || a == AssignmentStatic || a == AssignmentDynamic
}

// StoredAssignment is the assignment a repository records for this identifier:
// empty for every kind but `ip_address`; the identifier's own [Assignment]
// when it has one; otherwise [AssignmentStatic] for an `ip_address` marked
// [Identifier.Pinned] or a person DECLARED (an operator typing an address onto
// an asset is pinning it — decision 1); otherwise empty.
//
// It lives here, and both repositories call it, so "a declaration pins its
// address" is one rule rather than one per intake path: the manual identifier
// edit, the Devices form and a declared observation through the engine all
// reach the store through [Repository.AttachIdentifiers] or
// [Repository.CreateAsset].
func (i Identifier) StoredAssignment() AddressAssignment {
	if i.Kind != KindIPAddress {
		return ""
	}
	if i.Assignment != "" {
		// An explicit answer — the host said "dhcp" — wins over Pinned, which
		// Intake also sets on every self-reported address.
		return i.Assignment
	}
	if i.Pinned || i.Source.Kind == SourceDeclared {
		return AssignmentStatic
	}
	return ""
}

// SourceRank orders source kinds for the identifier upsert's provenance rule:
// declared (a person said so) over measured and imported (a collector or a
// system of record said so) over inferred (we worked it out). A stored
// identifier's source_kind moves only UP this ladder, and its source_ref moves
// with its source_kind — a weaker sighting refreshes last-seen without
// rewriting who vouched for the value. An empty kind ranks as measured, the
// column's default.
func SourceRank(k SourceKind) int {
	switch k {
	case SourceDeclared:
		return 3
	case SourceInferred:
		return 1
	default:
		return 2
	}
}

// UpsertIdentifier folds a re-sighting `next` into the stored copy `prev` of
// the same identifier, under the provenance rules the SQL upsert in
// shared/identity/postgres applies (the identitytest contract holds the two
// to the same answers):
//
//   - source kind moves only up [SourceRank]; the ref travels with the kind
//     (an equal-rank re-sighting of the same kind refreshes a non-empty ref,
//     a weaker or sideways one keeps the stored ref);
//   - the address assignment is replaced only by a non-empty value from a
//     source at least as strong as the stored one, so `static` is never
//     downgraded to unknown and a measured "dhcp" never unpins a declaration;
//   - last-seen never moves backwards;
//   - an SSH host key's algorithm, once known, is kept when a re-sighting
//     does not say it.
//
// Everything else (confidence, generic) is next's. It is exported for the
// in-memory repository, which is the executable statement of the rule.
func UpsertIdentifier(prev, next Identifier) Identifier {
	out := next
	if prev.SeenAt.After(next.SeenAt) {
		out.SeenAt = prev.SeenAt
	}
	prevKind, nextKind := storedSourceKind(prev.Source.Kind), storedSourceKind(next.Source.Kind)
	prevRank, nextRank := SourceRank(prevKind), SourceRank(nextKind)
	switch {
	case nextRank > prevRank:
		out.Source = next.Source
		out.Source.Kind = nextKind
	case nextKind == prevKind:
		out.Source = prev.Source
		out.Source.Kind = prevKind
		if strings.TrimSpace(next.Source.Ref) != "" {
			out.Source.Ref = next.Source.Ref
		}
	default:
		out.Source = prev.Source
		out.Source.Kind = prevKind
	}
	if out.KeyAlgorithm == "" {
		// A sighting that does not say an SSH host key's algorithm does not
		// forget one an earlier sighting said ( Decision 4), as the SQL
		// upsert's coalesce does.
		out.KeyAlgorithm = prev.KeyAlgorithm
	}
	prevAssign, nextAssign := prev.StoredAssignment(), next.StoredAssignment()
	out.Assignment = prevAssign
	if nextAssign != "" && nextRank >= prevRank {
		out.Assignment = nextAssign
	}
	// A device confirmation never moves backwards (leasefresh.go), as the SQL
	// upsert's GREATEST does: a late-arriving sighting cannot make an address
	// look less recently confirmed than it is, and a sighting that confirmed
	// nothing (zero) does not erase one that did.
	if prev.DeviceConfirmedAt.After(next.DeviceConfirmedAt) {
		out.DeviceConfirmedAt = prev.DeviceConfirmedAt
	}
	return out
}

// storedSourceKind is the column's default made explicit: an identifier
// written with no source kind is stored `measured`.
func storedSourceKind(k SourceKind) SourceKind {
	if k == "" {
		return SourceMeasured
	}
	return k
}

// NormalizeSSHKeyAlgorithm maps an SSH host key type or signature algorithm
// name to the KEY family it names, or "" when it names none.
//
// The observers report different names for one key: a probe reports the
// negotiated SIGNATURE algorithm (`rsa-sha2-512`), a banner grab the key type
// (`ssh-rsa`), an agent its own spelling. All three are one RSA key. ECDSA
// keeps its curve, because a host may hold a P-256 and a P-384 key at once; a
// host certificate is the key it certifies.
func NormalizeSSHKeyAlgorithm(raw string) string {
	a := strings.ToLower(strings.TrimSpace(raw))
	a = strings.TrimSuffix(a, "-cert-v01@openssh.com")
	switch a {
	case "":
		return ""
	case "ssh-rsa", "rsa", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa-sha256@ssh.com", "rsa-sha2-256@ssh.com", "rsa-sha2-512@ssh.com":
		return "rsa"
	case "ssh-ed25519", "ed25519":
		return "ed25519"
	case "ssh-ed448", "ed448":
		return "ed448"
	case "ssh-dss", "dsa", "dss":
		return "dsa"
	case "ecdsa-sha2-nistp256", "ecdsa-p256", "ecdsa256", "nistp256":
		return "ecdsa-p256"
	case "ecdsa-sha2-nistp384", "ecdsa-p384", "ecdsa384", "nistp384":
		return "ecdsa-p384"
	case "ecdsa-sha2-nistp521", "ecdsa-p521", "ecdsa521", "nistp521":
		return "ecdsa-p521"
	case "sk-ssh-ed25519@openssh.com":
		return "sk-ed25519"
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		return "sk-ecdsa-p256"
	case "ecdsa":
		// A bare "ecdsa" does not say which curve, and the curve is what
		// tells two ECDSA keys apart. Unknown, not a guess.
		return ""
	default:
		// A name we do not recognise is kept verbatim rather than dropped:
		// two sightings spelling it the same way still compare.
		return a
	}
}

// Inferred reports whether the identifier was derived from other evidence
// rather than observed (see the exception on [Identifier]).
//
// An inferred identifier is recorded and may vote, under three guards
// ( Phase 2):
//
//  1. it never CREATES: an asset whose every identifier would be inferred is
//     not written ([ErrNoUsableIdentifier]);
//  2. within its kind it votes AFTER the native identifiers, so when a native
//     one has decided, an inferred one may only corroborate or conflict;
//  3. the singleton, prior-decision and dynamic-scope rules apply unchanged.
//
// It is also not DIRECT evidence of anything: it does not count toward
// admission ([AssessAdmission]) and a match it decided does not move a DHCP
// lease (lease.go). It still counts as naming a device where that is the safe
// reading — the address-only link rule and 1c's provisional refusal.
func (i Identifier) Inferred() bool { return i.Source.Kind == SourceInferred }

// Key is the tuple the uniqueness invariant is defined over, within a tenant:
// kind, value and scope. Two identifiers with the same Key are the same
// identifier however they were observed.
func (i Identifier) Key() string {
	return string(i.Kind) + "|" + i.Value + "|" + i.Scope
}

// Normalized returns a copy of the identifier with its value normalised, or an
// error naming the kind and the value that failed.
//
// It also rejects a scope on a kind that has none ([Kind.AcceptsScope]): the
// scope is part of the uniqueness key, so a spurious one silently produces a
// second asset for one identifier value.
//
// A scoped kind that arrives with NO scope is given [ScopeTenantDefault] here,
// which is the one funnel every identifier passes through on its way into the
// engine ([Engine.Resolve] and [Observation.Sanitize] both call it). Doing it
// here rather than in each of the seven observation builders is what makes it
// impossible for a builder to produce an identifier that cannot decide
// anything — the defect that made one host, ingested three times in a tenant
// with no segments, into three assets.
func (i Identifier) Normalized() (Identifier, error) {
	v, err := Normalize(i.Kind, i.Value)
	if err != nil {
		return i, err
	}
	scope := strings.TrimSpace(i.Scope)
	if scope != "" && !i.Kind.AcceptsScope() {
		return i, fmt.Errorf("identity: %s: scope %q is meaningless for this kind and would split the uniqueness key; only hostname, ip_address, name and cmdb_sys_id are scoped", i.Kind, scope)
	}
	if scope == "" {
		scope = i.Kind.DefaultScopeFor()
	}
	if !i.Assignment.Valid() {
		return i, fmt.Errorf("identity: %s: address assignment %q is not one of static, dynamic or empty", i.Kind, i.Assignment)
	}
	out := i
	out.Value = v
	out.Scope = scope
	if out.Kind != KindIPAddress {
		// How an address is assigned is a fact about an address. On any other
		// kind it means nothing, and storing it would invite a reader to think
		// it did.
		out.Assignment = ""
	}
	if i.Kind == KindSSHHostKeyFingerprint {
		out.KeyAlgorithm = NormalizeSSHKeyAlgorithm(i.KeyAlgorithm)
	} else {
		out.KeyAlgorithm = ""
	}
	return out, nil
}

// Normalize canonicalises an identifier value for its kind, so that two
// observers who spell the same fact differently produce the same row.
//
// Per kind:
//
//   - agent_id, cloud_resource_id, cmdb_sys_id, serial_number,
//     ssh_host_key_fingerprint — trimmed, case PRESERVED. These are opaque
//     tokens issued by something else. Case-folding them would be a guess, and
//     the guess is asymmetric: two spellings of one agent produce a duplicate
//     asset, which a merge proposal fixes, while two distinct base64
//     fingerprints folded together produce a wrong merge, which nothing
//     catches. An ARN's resource portion is case-sensitive by specification.
//   - mac_address — 12 hex digits in any of the four common spellings
//     (colon, hyphen, Cisco dotted-quad, bare), emitted as aa:bb:cc:dd:ee:ff.
//     All-zero and broadcast are rejected: they are placeholders, not
//     identities.
//   - fqdn — lowercased, one trailing dot stripped, at least two labels
//     required. A single-label name is a hostname, and hostnames identify only
//     within a scope: accepting one here would let a caller evade that rule by
//     choosing the other kind.
//   - hostname — lowercased, trailing dot stripped.
//   - ip_address — parsed with net/netip, IPv4-in-IPv6 unmapped, zone dropped
//     (a %eth0 on one host is not the same interface as on another), emitted
//     canonically. The unspecified address is rejected.
//   - name — trimmed, internal whitespace collapsed to one space, lowercased.
//     A declared name is typed by a person, so "Payments  API", "payments api"
//     and " Payments API " are one service and must produce one row. It is
//     folded where the opaque kinds are not, because the opposite risk applies:
//     nobody issued this token, so two spellings are a duplicate a human has to
//     reconcile rather than two distinct things a fold would wrongly merge.
//
// Every kind rejects an empty or whitespace-only value: the absence of an
// identifier is not an identifier whose value is "".
func Normalize(kind Kind, value string) (string, error) {
	if !kind.Valid() {
		return "", fmt.Errorf("identity: unknown identifier kind %q", string(kind))
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("identity: %s: value is empty", kind)
	}
	if strings.ContainsFunc(v, isControl) {
		return "", fmt.Errorf("identity: %s: value contains a control character", kind)
	}

	switch kind {
	case KindMACAddress:
		return normalizeMAC(v)
	case KindFQDN:
		return normalizeDNSName(v, true)
	case KindHostname:
		return normalizeDNSName(v, false)
	case KindIPAddress:
		return normalizeIP(v)
	case KindName:
		return normalizeName(v)
	case KindDeclarationID, KindAgentID, KindSensorID, KindCloudResourceID, KindSerialNumber, KindCMDBSysID, KindSSHHostKeyFingerprint:
		// Opaque: trimmed only. See the doc comment for why case survives.
		return v, nil
	default:
		// Unreachable: kind.Valid() above covers all ten. Present so an
		// eleventh kind added to the constants without a rule here fails loudly
		// at the first call rather than being stored unnormalised.
		return "", fmt.Errorf("identity: %s: no normalisation rule", kind)
	}
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// normalizeMAC accepts aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff
// and aabbccddeeff, and emits the first form.
func normalizeMAC(v string) (string, error) {
	lower := strings.ToLower(v)
	var hex strings.Builder
	hex.Grow(12)
	for _, r := range lower {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r == ':', r == '-', r == '.', r == ' ':
			// separator
		default:
			return "", fmt.Errorf("identity: mac_address: %q contains %q, which is not hex or a separator", v, string(r))
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return "", fmt.Errorf("identity: mac_address: %q has %d hex digits, want 12", v, len(h))
	}
	switch h {
	case "000000000000":
		return "", fmt.Errorf("identity: mac_address: %q is the all-zero address, which is a placeholder and not an identity", v)
	case "ffffffffffff":
		return "", fmt.Errorf("identity: mac_address: %q is the broadcast address, which is not an identity", v)
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

// dnsAllowed is the character set both DNS kinds accept: letters, digits,
// hyphen, dot and underscore (service labels such as _ldap._tcp are real).
// Anything else — a wildcard, a slash, a colon, a non-ASCII rune — is rejected
// rather than silently kept: an IDN must arrive as punycode, and "*.a.com" is
// a certificate subject, not an asset.
func dnsAllowed(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '.', r == '_':
		return true
	default:
		return false
	}
}

func normalizeDNSName(v string, requireDot bool) (string, error) {
	kind := KindHostname
	if requireDot {
		kind = KindFQDN
	}
	s := strings.ToLower(v)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("identity: %s: %q is only a trailing dot", kind, v)
	}
	if len(s) > 253 {
		return "", fmt.Errorf("identity: %s: %q is %d characters, over the 253 limit", kind, v, len(s))
	}
	for _, r := range s {
		if !dnsAllowed(r) {
			return "", fmt.Errorf("identity: %s: %q contains %q, which is not valid in a DNS name", kind, v, string(r))
		}
	}
	// An IP literal is not a name.
	//
	// `dnsAllowed` accepts digits and dots, so "192.0.2.10" passed every check
	// above and — having two labels — was accepted as an FQDN. Every builder
	// that puts "the host" into a DNS kind therefore produced a SECOND
	// identifier row for an address that was already an ip_address: two rows,
	// two owners possible, one host. And because the two kinds sit at different
	// points in the precedence list, an fqdn spelled as an address could decide
	// a match that the identical ip_address was forbidden to decide inside a
	// dynamic segment — the DHCP rule, evaded by choosing the other kind.
	//
	// Rejected here, in the one funnel every identifier passes through, rather
	// than in each of the seven observation builders: a builder that forgets is
	// exactly how this arrived.
	if _, err := netip.ParseAddr(s); err == nil {
		return "", fmt.Errorf("identity: %s: %q is an IP address, not a name; use ip_address", kind, v)
	}
	// Exactly ONE trailing dot is the root label and was stripped above.
	// Anything still starting or ending with a dot, or containing two in a
	// row, has an empty label. (A second trailing dot is how the fuzzer found
	// this: "0000.." trimmed to "0000.", which then contained a dot and so
	// passed the FQDN two-label test while not being normalised — the second
	// pass rejected what the first had accepted.)
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return "", fmt.Errorf("identity: %s: %q has an empty label", kind, v)
	}
	if requireDot && !strings.Contains(s, ".") {
		return "", fmt.Errorf("identity: fqdn: %q is a single label; a short name is a hostname, and a hostname identifies only within a scope", v)
	}
	return s, nil
}

// normalizeName folds a declared name: trim, collapse internal whitespace to a
// single space, lowercase. strings.Fields splits on every Unicode space class,
// so a tab or a non-breaking space between two words folds the same way a plain
// one does.
func normalizeName(v string) (string, error) {
	folded := strings.Join(strings.Fields(v), " ")
	if folded == "" {
		return "", fmt.Errorf("identity: name: %q is only whitespace", v)
	}
	if len(folded) > 253 {
		return "", fmt.Errorf("identity: name: %q is %d characters, over the 253 limit", v, len(folded))
	}
	return strings.ToLower(folded), nil
}

func normalizeIP(v string) (string, error) {
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return "", fmt.Errorf("identity: ip_address: %q is not an IP address: %w", v, err)
	}
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return "", fmt.Errorf("identity: ip_address: %q is not a valid address", v)
	}
	if addr.IsUnspecified() {
		return "", fmt.Errorf("identity: ip_address: %q is the unspecified address, which is a placeholder and not an identity", v)
	}
	return addr.String(), nil
}

// classPrecedence returns the identifier precedence for a class key from the
// generated registry, converted to kinds. The second result is false for a key
// the registry does not carry — an unknown key, or a tenant leaf subclass,
// which is a runtime row and not in the generated hierarchy.
//
// A class with an EMPTY precedence returns an empty slice and true: that class
// has no independent identity at all. Empty and absent are not the same answer.
// No FIXED class is empty any more — the three `service` classes, which used to
// be, now carry `[name]` (ADR-0002 D3 erratum) — but a tenant leaf subclass or
// a future class may be, and an empty list must not silently fall back to the
// default order and give a thing an IP-address identity the registry denied it.
func classPrecedence(classKey string) ([]Kind, bool) {
	c, ok := assetclass.Get(classKey)
	if !ok {
		return nil, false
	}
	return KindsFromStrings(c.IdentifierPrecedence), true
}
