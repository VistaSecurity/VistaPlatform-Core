package identity

import (
	"reflect"
	"time"
)

// AttributeGroup is one of the three groups ADR-0002 D4 reconciles on its own
// precedence table. Which group an attribute is in is a property of the
// attribute, not of the write, so the caller names it.
type AttributeGroup string

const (
	// GroupIdentity is identity and observed facts: addresses, OS, firmware,
	// serial, model, endpoints. "Reality beats records."
	GroupIdentity AttributeGroup = "identity"
	// GroupContext is context: owner, business unit, environment, support
	// group, site, tags. "People beat probes for who owns what."
	GroupContext AttributeGroup = "context"
	// GroupClass is the asset's class. "A human's correction sticks."
	GroupClass AttributeGroup = "class"
)

// Valid reports whether g is one of the three groups.
func (g AttributeGroup) Valid() bool {
	switch g {
	case GroupIdentity, GroupContext, GroupClass:
		return true
	default:
		return false
	}
}

// HighConfidence is the threshold at which a measured CLASS counts as
// "measured with high confidence" in ADR-0002 D4's class table.
//
// The ADR says "high confidence" without a number, and a rule with no number
// cannot be implemented or tested. 0.8 is chosen to match the one threshold
// the product already exposes for the same judgement — the auto-approval
// rule's `min_confidence: 0.8` — so an operator meets one number, not two. A
// measured class BELOW it still outranks inferred; it just no longer outranks
// an imported class, which is the distinction the table is drawing.
const HighConfidence = 0.8

// ValueWithSource is one candidate value for an attribute, with the provenance
// that decides whether it may overwrite another.
type ValueWithSource struct {
	// Value is the value itself. A nil Value, an empty string, a zero number,
	// an empty slice or an empty map are all "empty" — but a bool false is
	// NOT. See [Reconcile].
	Value any `json:"value"`
	// Source is where it came from. Mode splits measured into active and
	// passive (ADR-0002 D4's two measured rows).
	Source Source `json:"source"`
	// Confidence is 0..1, read only by the class group's "measured with high
	// confidence" tier.
	Confidence float64 `json:"confidence,omitempty"`
	// At is when the value was observed or declared. It is not consulted by
	// the precedence rules and is carried for the history row.
	At time.Time `json:"at,omitzero"`
}

// Reconcile decides which of two values for the same attribute wins, per
// ADR-0002 D4, and returns the winner.
//
// Three tables, one per group, highest first:
//
//	identity   declared > measured-active > measured-passive > imported > inferred
//	context    declared > imported > measured > inferred
//	class      declared > measured (confidence >= HighConfidence) > imported >
//	           measured (below it) > inferred
//
// plus two rules that override the tables:
//
//   - **Empty never wins.** An incoming empty value never replaces a populated
//     one, whatever its source. This is the discovery-envelope rule, and the
//     exception in it is load-bearing: a bool `false` is an ANSWER, not an
//     absence. Demoting an explicit false is the jq `//` mistake that silently
//     inverts a security flag.
//   - **Inferred never overwrites measured or declared** (ADR-0008 D4.2), at
//     any confidence. It may fill a gap — an empty existing value — and it may
//     propose a correction a human accepts, which is the approval path, not
//     this function.
//
// A tie in rank goes to the incoming value: two observations of equal
// authority, and the later one is the current state of the world.
//
// # The gap in the ADR, and how it is closed
//
// D4's identity table does not list `declared` at all — it ranks only the
// automatic sources. Ranking declared at the TOP of that table is the reading
// taken here, for the reason the ADR gives for the other two tables: a human's
// correction sticks. The alternative — declared below measured — makes the
// edit field in the UI a control that reports success and does nothing,
// because the next scan silently reverts it, which is the exact failure shape
// this codebase keeps paying for.
func Reconcile(group AttributeGroup, existing, incoming ValueWithSource) ValueWithSource {
	incomingEmpty := IsEmptyValue(incoming.Value)
	existingEmpty := IsEmptyValue(existing.Value)

	// Empty never wins.
	if incomingEmpty {
		return existing
	}
	// Nothing to defend: an incoming value fills a gap regardless of source.
	// This is the one way an inferred value lands without approval, and
	// ADR-0008 D4.2 explicitly permits it ("It may fill a gap").
	if existingEmpty {
		return incoming
	}
	// The floor: inferred never overwrites measured or declared.
	//
	// In the three known groups this is redundant with the tables below, which
	// already rank inferred last. It is not redundant when the GROUP is not
	// one of the three — a typo, or a fourth group added later without a table
	// — because every source then ranks equal and the tie would hand the write
	// to the incoming value. ADR-0008 D4.2 is not conditional on the caller
	// spelling the group correctly, so it is enforced before the tables are
	// consulted. TestReconcileInferredFloorHoldsUnderAnUnknownGroup is the
	// case that makes this line load-bearing.
	if incoming.Source.Kind == SourceInferred &&
		(existing.Source.Kind == SourceMeasured || existing.Source.Kind == SourceDeclared) {
		return existing
	}

	if rank(group, incoming) >= rank(group, existing) {
		return incoming
	}
	return existing
}

// rank scores a value's source within a group. Higher wins. The numbers are
// ordinal and carry no meaning beyond their order.
func rank(group AttributeGroup, v ValueWithSource) int {
	switch group {
	case GroupContext:
		switch v.Source.Kind {
		case SourceDeclared:
			return 4
		case SourceImported:
			return 3
		case SourceMeasured:
			return 2
		case SourceInferred:
			return 1
		}
	case GroupClass:
		switch v.Source.Kind {
		case SourceDeclared:
			return 5
		case SourceMeasured:
			if v.Confidence >= HighConfidence {
				return 4
			}
			// A measured class the collector was not sure of. It still beats a
			// model's guess; it no longer beats a system of record.
			return 2
		case SourceImported:
			return 3
		case SourceInferred:
			return 1
		}
	case GroupIdentity:
		switch v.Source.Kind {
		case SourceDeclared:
			return 5
		case SourceMeasured:
			if v.Source.Mode == ModeActive {
				return 4
			}
			// Passive, and also unspecified: a caller that did not say how it
			// measured has not earned the active tier.
			return 3
		case SourceImported:
			return 2
		case SourceInferred:
			return 1
		}
	}
	// An unknown group or an unknown source kind ranks below everything. A
	// value whose provenance we cannot read must not win by default.
	return 0
}

// IsEmptyValue reports whether v is "empty" for the purposes of "empty never
// wins": nil, an empty string, a zero number, an empty slice, array or map, or
// a nil pointer or interface.
//
// A bool false is NOT empty, and neither is a zero time.Time treated specially
// — an explicit false is an answer (`cert_has_sct`, `mtls_detected`), and
// demoting it is how a security flag silently inverts.
func IsEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	switch t := v.(type) {
	case bool:
		return false
	case string:
		return t == ""
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return rv.Len() == 0
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() == 0
	case reflect.Pointer, reflect.Interface:
		return rv.IsNil()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.Bool:
		return false
	default:
		return false
	}
}
