package findings

import "sort"

// Which kinds feed the per-asset risk rollup (ADR-0005 D4).
//
// The list is DERIVED from the generated registry, never written out. A
// hand-maintained copy is the shape this repository keeps re-finding: the
// registry says `feeds_risk: false` for hygiene, somebody adds a hygiene kind,
// and a literal list somewhere else silently starts inflating a security score
// with a data-quality complaint. Deriving it means the YAML is the only place
// the question is answered, and `make audit` already guards the YAML against
// the generated Go.

// RiskKey is the composite the rollup filters on: a kind is identified by its
// producer AND its key, because `kind` is only documented as unique across the
// registry — not enforced to be. Two producers could legitimately both emit a
// kind named `stale`, and a filter keyed on the kind alone would take both.
func RiskKey(producer, kind string) string { return producer + "/" + kind }

// RiskFeedingKeys returns `<producer>/<kind>` for every kind whose feeds_risk
// is true, sorted so the SQL a caller builds from it is stable (a query whose
// text changes run to run defeats the statement cache and makes a golden test
// flap).
//
// Computed on each call rather than cached in a package var: the slice is
// handed to callers who bind it as a query parameter, and a shared backing
// array that one of them sorted or appended to in place would change what every
// other caller filters on.
func RiskFeedingKeys() []string {
	out := make([]string, 0, len(All))
	for _, k := range All {
		if k.FeedsRisk {
			out = append(out, RiskKey(k.Producer, k.Key))
		}
	}
	sort.Strings(out)
	return out
}

// RiskFeedingProducers returns the producers that have at least one kind
// feeding the rollup, sorted.
//
// It is what `assets.risk_assessed_by` may contain, and the distinction from
// the full coverage record is a decision rather than an implementation detail
// (orchestrator,: the array means "the RISK score on this asset is a
// real answer", and the inventory UI reads a non-empty array as exactly that. A
// producer whose every kind carries `feeds_risk: false` — `hygiene` — has looked
// at the asset, but it has not evaluated anything that could move the score, so
// an asset only hygiene has seen must still read NOT ASSESSED for risk.
//
// Coverage for EVERY producer, hygiene included, lives in
// `producer_assessments`; this is its risk-feeding subset, and it is the ONE
// place that subset is computed.
func RiskFeedingProducers() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(Producers))
	for _, k := range All {
		if k.FeedsRisk && !seen[k.Producer] {
			seen[k.Producer] = true
			out = append(out, k.Producer)
		}
	}
	sort.Strings(out)
	return out
}
