package agentconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// Revision is the content hash of a set of effective values: the identity of
// "what this device has been asked to be".
//
// Content-addressed rather than a counter, for the reason in the package doc: a
// counter would have to be bumped on every device inheriting a changed fleet
// default, and a device missed by that sweep reads as converged forever. A hash
// needs no sweep — the values changed, so the revision differs, so the device
// disagrees on its next check-in.
//
// The runtime is part of the hash. The same values mean different things to a
// sensor and an agent, and two devices of different kinds should not be able to
// share a revision string by coincidence.
func Revision(rt Runtime, vals Values) string {
	h := sha256.New()
	// sha256's Write never returns an error, so these writes cannot fail; the
	// errors are dropped explicitly rather than left unchecked.
	_, _ = fmt.Fprintf(h, "v1\n%s\n", rt)
	keys := vals.Keys()
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		v := vals[k]
		if v.IsZero() {
			// An unset key is not a value. Hashing it as an empty string would
			// make "absent" and "set to empty" the same revision.
			continue
		}
		// The type letter is in the hash so that true and "true", or 1 and
		// "1", are different revisions. They arrive from JSON, where that
		// distinction is one careless client away.
		var kind byte = 's'
		switch {
		case v.B != nil:
			kind = 'b'
		case v.I != nil:
			kind = 'i'
		}
		_, _ = fmt.Fprintf(h, "%s\x00%c\x00%s\x1e", k, kind, v.String())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// State is how far a device has got towards its desired revision.
type State string

const (
	// StateNeverReported means the device has not told us what it is running.
	// Distinct from Pending: a device that has never checked in is not "about
	// to converge", and showing it as pending would be a promise nobody made.
	StateNeverReported State = "never_reported"
	// StateNotReporting means the device HAS checked in but named no revision:
	// a build older than desired state, which will never converge no matter how
	// long anyone waits.
	//
	// Separate from StateNeverReported because the two need different actions —
	// one device is unreachable, the other needs upgrading — and separate from
	// StatePending because pending implies it is on its way. Collapsing any two
	// of the three is the three-valued flattening this codebase keeps having to
	// undo.
	StateNotReporting State = "not_reporting"
	// StatePending means the device is running something other than the
	// desired revision.
	StatePending State = "pending"
	// StateApplied means the device reported the desired revision.
	StateApplied State = "applied"
	// StateFailed means the device reported that it could not apply it.
	StateFailed State = "failed"
	// StateAwaitingRestart means the device applied what it could and is
	// waiting for a restart to adopt the rest.
	StateAwaitingRestart State = "awaiting_restart"
)

// Report is what a device says about itself on check-in.
type Report struct {
	// Revision is the desired revision the device believes it is running.
	// Empty means the device does not speak desired state at all — an older
	// build — which is StateNeverReported, never StateApplied.
	Revision string
	// At is when the device said so.
	At time.Time
	// Failures maps a key to the device's own reason for not applying it.
	Failures map[Key]string
	// PendingRestart lists keys the device has accepted but cannot adopt until
	// it restarts.
	PendingRestart []Key
}

// Status is the answer the console renders.
type Status struct {
	State State
	// Desired is the revision the platform wants.
	Desired string
	// Reported is what the device last said it was running, if anything.
	Reported string
	// At is when the device last reported.
	At time.Time
	// Failures and PendingRestart are carried through from the report so the
	// console can name the specific setting rather than saying "something
	// failed".
	Failures       map[Key]string
	PendingRestart []Key
}

// Reconcile compares desired values against what a device reported.
//
// Order matters and is deliberate: a device that reported failures is Failed
// even if its revision matches, because "I am running revision X but three of
// its settings did not take" is a failure, not a success. Reporting the match
// first is how a console ends up showing green over a broken device.
func Reconcile(rt Runtime, desired Values, rep Report) Status {
	want := Revision(rt, desired)
	st := Status{
		Desired:        want,
		Reported:       rep.Revision,
		At:             rep.At,
		Failures:       rep.Failures,
		PendingRestart: rep.PendingRestart,
	}
	switch {
	case rep.Revision == "" && rep.At.IsZero():
		st.State = StateNeverReported
	case rep.Revision == "":
		st.State = StateNotReporting
	case len(rep.Failures) > 0:
		st.State = StateFailed
	case rep.Revision != want:
		st.State = StatePending
	case len(rep.PendingRestart) > 0:
		st.State = StateAwaitingRestart
	default:
		st.State = StateApplied
	}
	return st
}

// Diff returns the keys whose effective value changes between two sets, in key
// order. It is what an audit entry records and what the console shows before an
// operator saves.
func Diff(before, after Values) []Change {
	seen := make(map[Key]struct{}, len(before)+len(after))
	for k := range before {
		seen[k] = struct{}{}
	}
	for k := range after {
		seen[k] = struct{}{}
	}
	keys := make([]Key, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	var out []Change
	for _, k := range keys {
		b, a := before[k], after[k]
		if b.Equal(a) {
			continue
		}
		out = append(out, Change{Key: k, From: b, To: a})
	}
	return out
}

// Change is one setting moving from one value to another.
type Change struct {
	Key  Key
	From Value
	To   Value
}

func (c Change) String() string {
	from, to := c.From.String(), c.To.String()
	if c.From.IsZero() {
		from = "unset"
	}
	if c.To.IsZero() {
		to = "unset"
	}
	return fmt.Sprintf("%s: %s → %s", c.Key, from, to)
}

// RestartRequired reports whether any changed key can only be adopted on
// restart, so the console can say so at save time rather than leaving an
// operator watching a row that will not go green.
func RestartRequired(changes []Change) []Key {
	var out []Key
	for _, c := range changes {
		if f, ok := Registry[c.Key]; ok && f.Apply == ApplyOnRestart {
			out = append(out, c.Key)
		}
	}
	return out
}
