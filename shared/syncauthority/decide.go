package syncauthority

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Action is what a field decision asks the sync to do.
type Action string

const (
	// ActionNone: the two sides agree.
	ActionNone Action = "none"
	// ActionPush: write our value to the peer.
	ActionPush Action = "push"
	// ActionPull: write the peer's value here.
	ActionPull Action = "pull"
	// ActionMerge: write the union to whichever side lacks it.
	ActionMerge Action = "merge"
	// ActionConflict: a person decides (Discovery → Approvals).
	ActionConflict Action = "conflict"
)

// Side is one side's value of a field and its change history since the last
// sync of the connection.
type Side struct {
	// Value in canonical form (see Canonical): nil, bool, float64, string or a
	// []any for a set.
	Value any
	// Changed is true when this side changed the field since the last sync.
	// Meaningful only when Input.Baseline is true.
	Changed bool
	// ChangedAt is when this side last changed the field (zero = unknown).
	ChangedAt time.Time
}

// Input is everything one field decision reads.
type Input struct {
	Authority Authority
	Ours      Side
	Theirs    Side
	// Baseline is true when the connection has synced this object before, so
	// the Changed flags compare against an agreed value. On the first sync
	// they are ignored.
	Baseline bool
	// ObservedAt is our collectors' last observation of the object; zero when
	// nothing of ours ever measured it (an object only a person or the peer
	// declared). Read for `observed` fields only.
	ObservedAt time.Time
	// StaleWindow is how long an observation stays authoritative.
	StaleWindow time.Duration
	// Now is the clock.
	Now time.Time
	// Window overrides NewestWindow (zero = NewestWindow); tests only.
	Window time.Duration
}

// Decision is the outcome for one field.
type Decision struct {
	Action Action
	// Value is what the action writes: ours for a push, theirs for a pull, the
	// union for a merge; nil for none and conflict.
	Value any
	// Reason is one sentence for the plan and the run record.
	Reason string
}

// Decide applies the SYNC_MODEL §4 rules to one field.
//
//	equal                                   → none
//	observed, observation inside the window → push ours
//	observed, observation stale             → conflict (a stale measurement and
//	                                          a different peer value: a person
//	                                          decides; nothing is overwritten)
//	observed, empty here and untouched      → pull theirs (an empty field is
//	                                          not a measurement)
//	observed, never observed by us          → the three-way rule below
//	peer                                    → pull theirs
//	declared_here, changed on BOTH sides    → conflict
//	declared_here, ours empty and untouched → pull theirs (nothing typed here
//	                                          to defend; a first sync fills in)
//	declared_here                           → push ours
//	merge                                   → union, both ways
//	newest                                  → the side that changed wins; both
//	                                          changed: the newer wins unless
//	                                          the two are within the window
//	                                          (or either time is unknown) →
//	                                          conflict
//
// Unknown authorities are conflicts: a field nobody can be shown to own is
// never written silently.
func Decide(in Input) Decision {
	if Equal(in.Ours.Value, in.Theirs.Value) {
		return Decision{Action: ActionNone, Reason: "both sides agree"}
	}
	switch in.Authority {
	case Observed:
		// An empty value here is not a measurement: an object we observe can
		// still have a field our collectors never filled (a switch whose
		// platform no probe identified). Pushing the empty would blank the
		// peer, so the peer's value is taken, as for declared_here.
		if IsEmpty(in.Ours.Value) && (!in.Baseline || !in.Ours.Changed) {
			return Decision{Action: ActionPull, Value: in.Theirs.Value, Reason: "observed here but never measured; taking the peer's value"}
		}
		if in.ObservedAt.IsZero() {
			return threeWay(in, "never observed here; ")
		}
		if in.Now.Sub(in.ObservedAt) <= in.StaleWindow {
			return Decision{Action: ActionPush, Value: in.Ours.Value, Reason: "observed here within the stale window"}
		}
		return Decision{Action: ActionConflict, Reason: fmt.Sprintf(
			"our observation is stale (last seen %s) and the peer disagrees", in.ObservedAt.UTC().Format(time.RFC3339))}
	case Peer:
		return Decision{Action: ActionPull, Value: in.Theirs.Value, Reason: "the peer is authoritative"}
	case DeclaredHere:
		if in.Baseline && in.Ours.Changed && in.Theirs.Changed {
			return Decision{Action: ActionConflict, Reason: "declared here, and changed on both sides since the last sync"}
		}
		if IsEmpty(in.Ours.Value) && (!in.Baseline || !in.Ours.Changed) {
			return Decision{Action: ActionPull, Value: in.Theirs.Value, Reason: "declared here but never set here; taking the peer's value"}
		}
		return Decision{Action: ActionPush, Value: in.Ours.Value, Reason: "declared here"}
	case Merge:
		return Decision{Action: ActionMerge, Value: union(in.Ours.Value, in.Theirs.Value), Reason: "merged: union of both sides"}
	case Newest:
		return threeWay(in, "")
	default:
		return Decision{Action: ActionConflict, Reason: fmt.Sprintf("unknown authority %q", in.Authority)}
	}
}

// threeWay is the `newest` rule: the side that changed since the last sync
// wins; when both (or, before any baseline, neither is known) changed, the
// newer change wins unless the two are inside the window.
func threeWay(in Input, prefix string) Decision {
	window := in.Window
	if window == 0 {
		window = NewestWindow
	}
	if in.Baseline {
		switch {
		case in.Ours.Changed && !in.Theirs.Changed:
			return Decision{Action: ActionPush, Value: in.Ours.Value, Reason: prefix + "changed here only"}
		case in.Theirs.Changed && !in.Ours.Changed:
			return Decision{Action: ActionPull, Value: in.Theirs.Value, Reason: prefix + "changed in the peer only"}
		}
	}
	if in.Ours.ChangedAt.IsZero() || in.Theirs.ChangedAt.IsZero() {
		return Decision{Action: ActionConflict, Reason: prefix + "both sides differ and their change times are not both known"}
	}
	dt := in.Ours.ChangedAt.Sub(in.Theirs.ChangedAt)
	if dt <= window && dt >= -window {
		return Decision{Action: ActionConflict, Reason: fmt.Sprintf("%schanged on both sides within %s of each other", prefix, window)}
	}
	if dt > 0 {
		return Decision{Action: ActionPush, Value: in.Ours.Value, Reason: prefix + "changed more recently here"}
	}
	return Decision{Action: ActionPull, Value: in.Theirs.Value, Reason: prefix + "changed more recently in the peer"}
}

// Canonical turns a decoded JSON value (or a Go scalar) into the form Equal
// compares: "" and empty sets become nil, numbers become float64, sets are
// sorted. It is how "no description" (NULL here, "" in NetBox) agrees with
// itself.
func Canonical(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return t
	case *string:
		if t == nil {
			return nil
		}
		return Canonical(*t)
	case bool:
		return t
	case int:
		return float64(t)
	case int32:
		return float64(t)
	case int64:
		return float64(t)
	case float32:
		return float64(t)
	case float64:
		return t
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return t.String()
		}
		return f
	case []any:
		if len(t) == 0 {
			return nil
		}
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, Canonical(e))
		}
		sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
		return out
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return Canonical(out)
	case map[string]any:
		if len(t) == 0 {
			return nil
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = Canonical(e)
		}
		return out
	default:
		return t
	}
}

// Equal compares two values in canonical form.
func Equal(a, b any) bool {
	return key(Canonical(a)) == key(Canonical(b))
}

// IsEmpty reports whether v is absent in canonical form.
func IsEmpty(v any) bool { return Canonical(v) == nil }

// Fingerprint is a stable string for a value, for "ignore until changed":
// a resolved conflict is suppressed while both sides keep these fingerprints.
func Fingerprint(v any) string { return key(Canonical(v)) }

func key(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

// union is the merge of two set values (a scalar counts as a one-element set).
func union(a, b any) any {
	seen := map[string]bool{}
	var out []any
	for _, v := range []any{a, b} {
		c := Canonical(v)
		var items []any
		switch t := c.(type) {
		case nil:
		case []any:
			items = t
		default:
			items = []any{t}
		}
		for _, e := range items {
			if k := key(e); !seen[k] {
				seen[k] = true
				out = append(out, e)
			}
		}
	}
	return Canonical(out)
}
