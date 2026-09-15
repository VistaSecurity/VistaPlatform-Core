package producers

import (
	"math"

	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// CVSS → severity and score, per the registry's `score_source: cvss_x10`.
//
// The convention is the one models.RiskBands is anchored to: a 0-100 score is
// the CVSS base score times ten, and the bands land exactly on the CVSS v3.1 /
// v4.0 qualitative severity ratings. That is why the registry names
// `cvss_x10` rather than a number — the mapping is published, and copying it
// into a second table in Go would be a second opinion about a standard.
//
//	CVSS       score   band
//	9.0-10.0    90-100  critical
//	7.0-8.9     70-89   high
//	4.0-6.9     40-69   medium
//	0.1-3.9     1-39    low
//	0.0         0       none → reported as `info`
//
// # A CVE with no CVSS score is NOT harmless
//
// The catalogue's `cvss_score` is nullable: NVD has not scored every CVE, and
// OSV records carry a vector for some ecosystems and nothing for others. The
// registry says so in as many words — "A CVE with no CVSS score scores 0 and is
// reported as not scored, never as harmless" — so an unscored advisory produces
// a finding at score 0 and severity `info`, with `cvss_scored: false` in its
// evidence. It is still raised. Dropping it would be the three-valued-logic
// failure this repository has paid for repeatedly: "we could not grade this"
// rendered as "there is nothing here".

// cvssSeverity maps a CVSS base score onto the registry ladder and the 0-100
// score.
//
// scored=false means the catalogue had no number. The caller puts that in the
// evidence so the UI can say "not scored" rather than showing an Informational
// badge that reads as a judgement.
func cvssSeverity(cvss *float64) (severity string, score int, scored bool) {
	if cvss == nil {
		return producer.SeverityInfo, 0, false
	}
	v := *cvss
	if v < 0 {
		v = 0
	}
	if v > 10 {
		v = 10
	}
	// Round rather than truncate: CVSS publishes one decimal place, so 7.9
	// is 79 exactly and floating-point representation must not turn it into 78.
	score = int(math.Round(v * 10))

	switch {
	case score >= 90:
		return producer.SeverityCritical, score, true
	case score >= 70:
		return producer.SeverityHigh, score, true
	case score >= 40:
		return producer.SeverityMedium, score, true
	case score >= 1:
		return producer.SeverityLow, score, true
	default:
		// CVSS 0.0 is the "None" rating, which models.RiskBands displays as
		// Informational. It is a real grade — somebody looked and said this
		// scores nothing — and is distinct from the nil case above, which is
		// "nobody has graded it".
		return producer.SeverityInfo, 0, true
	}
}

// worseCVSS picks the more severe of two advisories, worst-wins.
//
// An install with twelve CVEs carries one finding (the identity index allows
// one open row per subject, and the unit of remediation is "upgrade this
// package" rather than "fix this CVE"), so the finding's severity has to be the
// worst of them: a package with a critical and eleven lows is a critical
// problem, and averaging would hide it.
//
// A scored advisory always beats an unscored one, whatever the unscored one's
// `info` would compare as — otherwise a single ungraded CVE alongside a real
// 9.8 could not lower the finding, but an install carrying ONLY ungraded CVEs
// would be indistinguishable from one carrying a genuine CVSS 0.0.
func worseCVSS(aSev string, aScore int, aScored bool, bSev string, bScore int, bScored bool) (string, int, bool) {
	switch {
	case aScored && !bScored:
		return aSev, aScore, aScored
	case bScored && !aScored:
		return bSev, bScore, bScored
	case bScore > aScore:
		return bSev, bScore, bScored
	case bScore < aScore:
		return aSev, aScore, aScored
	case producer.SeverityAtLeast(bSev, aSev):
		return bSev, bScore, bScored
	default:
		return aSev, aScore, aScored
	}
}
