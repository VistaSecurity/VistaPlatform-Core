package alertcatalog

import "sort"

// Rung is one trigger point on an escalating alert ladder. For time ladders
// (cert expiry) Days is "days remaining at which this rung is crossed".
// Source records where the rung came from: "baseline" (product default),
// "preference" (tenant's replacement of the baseline), or the name of the
// contributing framework ("policy:<framework>").
type Rung struct {
	Days     int    `json:"days"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
}

// BuildLadder assembles the effective rung ladder per the decided trigger
// model (NOTIFICATION_ALERTING_ARCHITECTURE.md §8.3):
//
//   - the tenant preference rung REPLACES the baseline rung (same kind of
//     thing: a warning preference)
//   - policy rungs are ALWAYS additive — activating a framework can only add
//     warning, never remove it
//   - rungs colliding on the same day take the max severity
//   - result is sorted most-days-first (the earliest warning first)
//
// typeEnabled=false drops baseline+preference rungs but KEEPS policy rungs:
// a tenant can silence the product's warning schedule but cannot fake posture
// against a framework they've activated.
func BuildLadder(baseline *Rung, preference *Rung, policy []Rung, typeEnabled bool) []Rung {
	byDay := map[int]Rung{}

	add := func(r Rung) {
		if r.Days < 0 || r.Severity == "" {
			return
		}
		if existing, ok := byDay[r.Days]; ok {
			if severityRank(r.Severity) > severityRank(existing.Severity) {
				byDay[r.Days] = r
			}
			return
		}
		byDay[r.Days] = r
	}

	if typeEnabled {
		if preference != nil {
			p := *preference
			p.Source = "preference"
			add(p)
		} else if baseline != nil {
			b := *baseline
			b.Source = "baseline"
			add(b)
		}
	}
	for _, r := range policy {
		add(r)
	}

	out := make([]Rung, 0, len(byDay))
	for _, r := range byDay {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Days > out[j].Days })
	return out
}

// EffectiveSeverity returns the severity for a subject at daysRemaining given
// the ladder: the max severity among crossed rungs (rung.Days >=
// daysRemaining), or "" when no rung is crossed (no alert should be open).
func EffectiveSeverity(ladder []Rung, daysRemaining int) string {
	best := ""
	for _, r := range ladder {
		if daysRemaining <= r.Days && severityRank(r.Severity) > severityRank(best) {
			best = r.Severity
		}
	}
	return best
}

// MaxDays returns the largest rung threshold (the earliest warning point).
func MaxDays(ladder []Rung) int {
	max := -1
	for _, r := range ladder {
		if r.Days > max {
			max = r.Days
		}
	}
	return max
}

// severityRank mirrors the alert engine's ordering. "" ranks below info so
// EffectiveSeverity can use it as the no-rung-crossed sentinel.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// NormalizeControlSeverity maps framework-control severity vocabulary
// (Low/Med/High/Critical) onto the platform enum.
func NormalizeControlSeverity(s string) string {
	switch s {
	case "Critical", "critical":
		return "critical"
	case "High", "high":
		return "high"
	case "Med", "Medium", "medium":
		return "medium"
	case "Low", "low":
		return "low"
	default:
		return "medium"
	}
}

// Get returns the registry entry for an alert type id.
func Get(id string) (*Entry, bool) {
	for i := range Registry {
		if Registry[i].ID == id {
			return &Registry[i], true
		}
	}
	return nil, false
}
