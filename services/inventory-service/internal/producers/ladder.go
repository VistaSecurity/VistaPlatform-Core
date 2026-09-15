package producers

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// The end-of-life ladders, in days.
//
// # Why the numbers are here and the severities are not
//
// The registry owns what a rung MEANS — its severity and its 0-100 score — and
// the writer refuses any pair that is not one of its rungs verbatim. What the
// registry cannot own is where the boundaries fall, because `threshold` is free
// text in the producer's own units ("within 90 days of end of life"), and
// parsing an integer back out of an English sentence would make a typo in the
// YAML a silent change of behaviour.
//
// So: the producer declares the days, the registry declares the meaning, and
// [TestEOLLadderMatchesRegistry] asserts the two still describe the same ladder
// — rung count, severities, scores and threshold wording. Edit either and that
// test fails, which is the point: a ladder is a decision, and a decision that
// changes should be looked at rather than absorbed.
const (
	// osWarnDays / softwareWarnDays: how far ahead of the end-of-life date the
	// first rung starts reporting.
	osWarnDays       = 90
	softwareWarnDays = 90
	// hardwareWarnDays is longer because replacing hardware takes longer than
	// upgrading a package: a purchase order, a maintenance window, a rack visit.
	hardwareWarnDays = 180

	// longPastDays is where the worst rung begins, for all three kinds — a year
	// past the date the vendor stopped shipping fixes.
	longPastDays = 365
)

// Rung indices, worst-last, matching the registry's `rungs` order.
const (
	rungApproaching = 0 // inside the warning window, not yet past
	rungPast        = 1 // past the date, within longPastDays
	rungLongPast    = 2 // past by more than longPastDays
)

// eolLadder is one kind's day boundaries.
type eolLadder struct {
	kind     string
	warnDays int
}

var eolLadders = map[string]eolLadder{
	findings.KindOSEndOfLife:          {kind: findings.KindOSEndOfLife, warnDays: osWarnDays},
	findings.KindSoftwareEndOfLife:    {kind: findings.KindSoftwareEndOfLife, warnDays: softwareWarnDays},
	findings.KindHardwareEndOfSupport: {kind: findings.KindHardwareEndOfSupport, warnDays: hardwareWarnDays},
}

// rungFor picks the rung for a kind given how many days remain until the
// end-of-life date (negative means the date has passed).
//
// Returns ok=false when the date is further ahead than the warning window: that
// is a supported product, and a finding about it would be noise that trains
// people to ignore the ones that matter.
//
// Note the direction of the comparisons. `daysRemaining >= 0` is the boundary
// between "approaching" and "past", and the day the date falls IS still
// supported — a product goes out of support at the end of its end-of-life date,
// not at the start of it.
func rungFor(kind string, daysRemaining int) (findings.Rung, bool, error) {
	l, ok := eolLadders[kind]
	if !ok {
		return findings.Rung{}, false, fmt.Errorf("producers: %q has no end-of-life ladder", kind)
	}

	idx := -1
	switch {
	case daysRemaining >= 0 && daysRemaining <= l.warnDays:
		idx = rungApproaching
	case daysRemaining < 0 && -daysRemaining <= longPastDays:
		idx = rungPast
	case daysRemaining < 0:
		idx = rungLongPast
	}
	if idx < 0 {
		return findings.Rung{}, false, nil
	}

	r, err := producer.Rung(findings.ProducerEOL, kind, idx)
	if err != nil {
		return findings.Rung{}, false, err
	}
	return r, true, nil
}

// eolDetail is the `{detail}` the registry's title_template substitutes: a
// short phrase a person reads as a date relationship, not a signed integer.
func eolDetail(daysRemaining int) string {
	switch {
	case daysRemaining > 1:
		return fmt.Sprintf("in %d days", daysRemaining)
	case daysRemaining == 1:
		return "tomorrow"
	case daysRemaining == 0:
		return "today"
	case daysRemaining == -1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", -daysRemaining)
	}
}
