package agentconfig

import (
	"fmt"
	"sort"
)

// Origin says where an effective value came from. It exists so the console can
// tell an operator "this is your fleet default" rather than showing a number
// with no provenance — and so "revert to fleet default" knows whether there is
// anything to revert.
type Origin string

const (
	// OriginBuiltIn is the device's own default: nobody has set this.
	OriginBuiltIn Origin = "built_in"
	// OriginFleet is the tenant-wide default.
	OriginFleet Origin = "fleet"
	// OriginDevice is an override set on this one device.
	OriginDevice Origin = "device"
)

// Resolved is one effective setting and where it came from.
type Resolved struct {
	Key    Key
	Value  Value
	Origin Origin
	Field  Field
}

// Resolve computes the effective settings for one device.
//
// Precedence, weakest first: the field's built-in default, the tenant's fleet
// default, then the device's own override. A key absent from a layer inherits;
// a key PRESENT with an explicit value wins even when that value equals the one
// it replaces, because "the operator set this here" is a fact about the device
// that survives a later change to the fleet default.
//
// Keys that do not apply to this runtime are dropped rather than rejected: a
// fleet default is one document covering both runtimes, so it will routinely
// carry sensor keys that an agent must ignore.
func Resolve(rt Runtime, fleet, device Values) []Resolved {
	fields := FieldsFor(rt)
	out := make([]Resolved, 0, len(fields))
	for _, f := range fields {
		r := Resolved{Key: f.Key, Value: f.Default, Origin: OriginBuiltIn, Field: f}
		if v, ok := fleet[f.Key]; ok && !v.IsZero() {
			r.Value, r.Origin = v, OriginFleet
		}
		if v, ok := device[f.Key]; ok && !v.IsZero() {
			r.Value, r.Origin = v, OriginDevice
		}
		out = append(out, r)
	}
	return out
}

// Effective is Resolve reduced to the values alone — what the device is told to
// be.
func Effective(rt Runtime, fleet, device Values) Values {
	out := make(Values)
	for _, r := range Resolve(rt, fleet, device) {
		out[r.Key] = r.Value
	}
	return out
}

// Validate checks a set of proposed values against the registry, returning one
// error per bad key rather than the first.
//
// An operator changing six settings should be told about all six problems at
// once; returning early makes fixing a form a round trip per field.
func Validate(rt Runtime, vals Values) error {
	var problems []string
	for _, k := range vals.Keys() {
		v := vals[k]
		f, known := Registry[k]
		if !known {
			problems = append(problems, fmt.Sprintf("%s: unknown setting", k))
			continue
		}
		if !AppliesTo(k, rt) {
			problems = append(problems, fmt.Sprintf("%s: not a %s setting", k, rt))
			continue
		}
		if v.IsZero() {
			// Explicitly clearing a key is how an override is removed. It is
			// not an error, and it must not be turned into one: the caller
			// strips empties before storing.
			continue
		}
		switch f.Kind {
		case KindBool:
			if v.B == nil {
				problems = append(problems, fmt.Sprintf("%s: expected true or false, got %q", k, v.String()))
			}
		case KindInt:
			if v.I == nil {
				problems = append(problems, fmt.Sprintf("%s: expected a whole number, got %q", k, v.String()))
				continue
			}
			if *v.I > f.Max {
				problems = append(problems, fmt.Sprintf("%s: %d is above the maximum of %d", k, *v.I, f.Max))
				continue
			}
			// Below the floor is RAISED, not rejected — see Field.Floor. Below
			// the minimum with no floor is an error.
			if f.Floor == 0 && *v.I < f.Min {
				problems = append(problems, fmt.Sprintf("%s: %d is below the minimum of %d", k, *v.I, f.Min))
			}
		case KindEnum:
			if v.S == nil {
				problems = append(problems, fmt.Sprintf("%s: expected one of %v", k, f.Allowed))
				continue
			}
			if !contains(f.Allowed, *v.S) {
				problems = append(problems, fmt.Sprintf("%s: %q is not one of %v", k, *v.S, f.Allowed))
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return &ValidationError{Problems: problems}
}

// ValidationError carries every problem found, not the first.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return e.Problems[0]
	}
	return fmt.Sprintf("%d invalid settings: %v", len(e.Problems), e.Problems)
}

// Normalize applies the registry's floors, returning the values as they will
// actually be enforced plus a note for each value it moved.
//
// Raising happens HERE, before storage, rather than on the device: the agent
// raises a sub-hour host-inventory interval itself and logs that it did, which
// is invisible to the operator who typed it. Storing the raised value means the
// console shows what is really running.
func Normalize(rt Runtime, vals Values) (Values, []string) {
	out := vals.Clone()
	var notes []string
	for _, k := range out.Keys() {
		f, ok := Registry[k]
		if !ok || !AppliesTo(k, rt) || f.Kind != KindInt {
			continue
		}
		v := out[k]
		if v.I == nil || f.Floor == 0 || *v.I >= f.Floor {
			continue
		}
		notes = append(notes, fmt.Sprintf("%s: raised %d to the minimum of %d", k, *v.I, f.Floor))
		out[k] = Int(f.Floor)
	}
	return out, notes
}

// NeedsConfirmation returns the fields in a change that carry a confirmation
// requirement and are being turned ON.
//
// Turning such a setting OFF needs no confirmation: the confirmation exists to
// make somebody acknowledge what begins to be collected, and stopping
// collection needs no such acknowledgement.
func NeedsConfirmation(rt Runtime, current, proposed Values) []Field {
	var out []Field
	for _, k := range proposed.Keys() {
		f, ok := Registry[k]
		if !ok || f.Confirm == "" || !AppliesTo(k, rt) {
			continue
		}
		v := proposed[k]
		if v.B == nil || !*v.B {
			continue
		}
		if cur, ok := current[k]; ok && cur.B != nil && *cur.B {
			// Already on: re-saving a form must not re-prompt.
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
