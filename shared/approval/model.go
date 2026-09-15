// Package approval evaluates a tenant's segment auto-approval rules.
//
// Auto-approval has exactly one gate: the discovered asset is on a user-defined
// network segment with auto-approve enabled. The rules in
// discovery_auto_approval_rules are generated from those segments by
// inventory-service's ManageAutoApprovalRules; this package only reads and
// evaluates them.
//
// It lives in shared/ because every ingestion path — the discovery pipeline,
// manual asset create, CMDB pull — must reach the same decision. Two
// implementations of an authorization rule is the failure this placement exists
// to prevent.
//
// # A rule is a query, not a JSON object
//
// The rule was a jsonb `conditions` object with seven recognised keys and a
// hand-written interpreter beside it (QUERY_LANGUAGE.md §8). It is now a query
// string over the `observation` target, parsed and validated by the same
// package that validates a scope, a saved view and the inventory URL.
//
// Three things follow, and they are the reason for the change:
//
//   - A typo is a 422 at write time. The old interpreter read the keys it knew
//     and ignored the rest, so `network_ownershp: internal` was a rule with one
//     fewer condition — quietly wider than what was written.
//   - The editor's autocomplete and the moment the rule fires read one
//     vocabulary. A second interpreter is how they come to disagree.
//   - Absence stays absence. A predicate over something the observation does
//     not carry is UNKNOWN and does not match (§5.2), where the old evaluator's
//     `if v, ok := conditions[k]; ok` skipped the condition entirely, which is
//     the same shape as auto-approving on a question nobody answered.
package approval

import (
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// Rule represents a row of discovery_auto_approval_rules: a tenant-owned rule
// for auto-approving discoveries.
type Rule struct {
	ID          uuid.UUID `db:"id"`
	TenantID    uuid.UUID `db:"tenant_id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	// Query is the predicate, over the `observation` target. An EMPTY query
	// matches every observation — a rule that auto-approves everything, which
	// is deliberately expressible and deliberately something a person has to
	// write.
	Query     string    `db:"query"`
	IsActive  bool      `db:"is_active"`
	CreatedBy uuid.UUID `db:"created_by"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	// compiled is the validated AST, cached so a batch of a thousand
	// discoveries parses each rule once rather than a thousand times.
	compiled ast.Node
	// compileErr is the failure from compiling Query, remembered so a broken
	// rule is reported once and then skipped, not re-parsed per discovery.
	compileErr error
	compiledOK bool
}

// Classification represents the network space/segment classification result.
//
// Ownership has three values:
//   - "internal"    — IP belongs to a known tenant network segment
//   - "third_party" — IP is a public internet address outside any registered segment
//   - "unknown"     — IP is RFC 1918 private but not in any registered segment
//     (may be an unregistered internal subnet)
//
// Only "third_party" discoveries are routed to the external connections path.
// "unknown" private addresses still go through the managed asset pipeline.
type Classification struct {
	Ownership   string     // "internal", "third_party", "unknown"
	Type        string     // "private", "public"
	SpaceID     *uuid.UUID // legacy
	SpaceName   *string    // legacy
	SegmentID   *uuid.UUID
	SegmentName *string
}

// Discovery is the projection of a discovered thing that rule evaluation reads
// — the `observation` target of QUERY_LANGUAGE §4.1, as a Go struct.
//
// Deliberately narrow. Callers hold richer records (sensor_discoveries rows,
// asset create inputs) and project onto this, rather than this package taking a
// dependency on any one caller's model. Every field is optional: a field the
// caller did not fill is ABSENT, and a predicate over it is Unknown rather than
// false — which is what stops a rule from firing on a question nobody answered.
type Discovery struct {
	TenantID uuid.UUID
	// Confidence is a POINTER so "confidence 0" and "confidence unmeasured"
	// stay different answers. A rule saying `confidence >= 0.8` must not fire
	// on a discovery nobody scored — and nil is the only spelling of that which
	// a caller cannot forget, where a parallel `ConfidenceSet bool` defaults to
	// the wrong value every time somebody adds a field above it.
	Confidence *float64
	// Metadata is the JSONB envelope as stored. It is read for one thing: to
	// tell a cloud discovery from a sensor one, which is the `source` field.
	Metadata []byte

	// Kind says what the observation IS — `crypto` or `host_observation` — as
	// distinct from Metadata's `source`, which says who produced it. The two are
	// independent: a sensor produces both.
	//
	// EMPTY MEANS NOT STATED, and a predicate over it is then Unknown (§5.2)
	// rather than false. The declared and imported intake paths leave it empty
	// deliberately: a spreadsheet row is neither a cryptographic measurement nor
	// a passive host observation, and defaulting it to either would make a rule
	// fire on a question nobody answered — the exact failure the jsonb
	// interpreter's `if v, ok := conditions[k]; ok` used to produce.
	Kind string

	// Hostname and Address are what was observed, when anything was.
	Hostname string
	Address  string
	// ClassPath is the class the intake path proposed, as a dotted PATH
	// (`hardware.computer.server`), so `class:hardware` is a subtree test on it
	// (§5.3). Empty means the path had no opinion — not `unknown_host`.
	ClassPath string
	// FirstSeen is when the observation was made.
	FirstSeen time.Time
}

// WithConfidence returns d with its confidence set. It exists so a caller that
// HAS a confidence does not have to take the address of a loop variable.
func (d Discovery) WithConfidence(c float64) Discovery {
	d.Confidence = &c
	return d
}

// WithKind returns d with its kind set. Callers that know what an observation
// IS state it; callers that do not leave it empty, which is absent rather than
// a default.
func (d Discovery) WithKind(k string) Discovery {
	d.Kind = k
	return d
}

// observationSource adapts a Discovery and its Classification to the
// evaluator's Source interface.
//
// The switch is on the ACCESSOR COLUMN the catalogue assigned, not on the
// field's surface name: `network.ownership` resolves to the column
// `network_ownership`, and matching on the column is what keeps this in step
// with registrycatalog's observationFields without re-stating the spelling.
type observationSource struct {
	d      Discovery
	c      *Classification
	source string
}

func (s observationSource) Field(ref ast.FieldRef) (any, bool) {
	switch ref.Accessor.Column {
	case "source":
		return s.source, s.source != ""
	case "kind":
		return s.d.Kind, s.d.Kind != ""
	case "confidence":
		if s.d.Confidence == nil {
			return nil, false
		}
		return *s.d.Confidence, true
	case "class_key", "class_path":
		return s.d.ClassPath, s.d.ClassPath != ""
	case "hostname":
		return s.d.Hostname, s.d.Hostname != ""
	case "address":
		if s.d.Address == "" {
			return nil, false
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(s.d.Address))
		if err != nil {
			return nil, false
		}
		if addr.IsUnspecified() {
			// 0.0.0.0 is not an address. It is the `dest_ip NOT NULL` column
			// compromise two producers make for a thing that HAS no address —
			// a host observation of a device that only ever ARP-probed, a cloud
			// resource with no network face — and the wire contract says in so
			// many words that a consumer must read it as "none observed" and
			// never as an address. Parsing it into one would make
			// `address in 10.0.0.0/8` answer *false* for a host we never
			// measured an address for, which is a different claim from "we do
			// not know", and the wrong one to auto-approve on.
			return nil, false
		}
		return addr, true
	case "network_ownership":
		if s.c == nil || s.c.Ownership == "" {
			return nil, false
		}
		return s.c.Ownership, true
	case "network_type":
		if s.c == nil || s.c.Type == "" {
			return nil, false
		}
		return s.c.Type, true
	case "network_segment_id":
		if s.c == nil || s.c.SegmentID == nil {
			return nil, false
		}
		return s.c.SegmentID.String(), true
	case "first_seen_at":
		if s.d.FirstSeen.IsZero() {
			return nil, false
		}
		return s.d.FirstSeen, true
	}
	// A field the catalogue publishes but this projection does not carry is
	// ABSENT, not false. `attr.*`, `fact.*` and `tag.*` on an observation are
	// exactly that: the thing has not been resolved to an asset yet, so it has
	// no attributes, facts or tags. Unknown is the honest answer.
	return nil, false
}

// FreeText is the §5.4 corpus for an observation: the hostname and the address.
// There is no display name yet (the asset does not exist) and no identifier
// rows (they are being resolved), so those two are the whole set — and stating
// it narrowly is what stops a free-text rule from silently widening later.
func (s observationSource) FreeText() []string {
	var out []string
	if s.d.Hostname != "" {
		out = append(out, s.d.Hostname)
	}
	if s.d.Address != "" {
		out = append(out, s.d.Address)
	}
	return out
}
