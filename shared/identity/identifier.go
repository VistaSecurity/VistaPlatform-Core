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
type Identifier struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	// Scope is the segment id for hostname and ip_address, and the sync
	// profile id for cmdb_sys_id. Empty for the global kinds.
	Scope string `json:"scope,omitempty"`
	// Confidence is 0..1, and 1.0 for a measured identifier.
	Confidence float64 `json:"confidence"`

	// Source and SeenAt are provenance, set by the engine.
	Source Source    `json:"source,omitzero"`
	SeenAt time.Time `json:"seen_at,omitzero"`
}

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
	out := i
	out.Value = v
	out.Scope = scope
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
