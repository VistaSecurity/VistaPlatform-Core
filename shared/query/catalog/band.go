package catalog

import "strings"

// BandLadder supplies the score→label ladder a band-typed field is compared
// through (§5.5).
//
// It is an interface because the one true ladder lives in
// services/inventory-service/internal/models/risk_bands.go and shared/ may not
// import a service. The caller passes it in; the translator generates every
// band predicate from it and never writes a threshold of its own. That is the
// whole point: badges at >= 60 while facets used >= 70 is the drift this
// indirection exists to make impossible.
type BandLadder interface {
	// Bands returns the ladder ordered highest-first, each with its inclusive
	// lower bound. models.RiskBands satisfies this shape directly.
	Bands() []Band
}

// Band is one rung: a label and its inclusive lower bound.
type Band struct {
	Label string
	Min   int
}

// NotAssessed is the pseudo-band meaning "nobody scored this" (§5.2). It is not
// a rung of the ladder: `risk:informational` is assessed and scored zero, and
// `risk:not_assessed` is a different set. Only a band field whose accessor
// names an AssessedBy column accepts it.
const NotAssessed = "not_assessed"

// BandLabels returns the ladder's labels, highest-first, plus not_assessed when
// the field supports it. Used for error messages and autocomplete.
func BandLabels(l BandLadder, withNotAssessed bool) []string {
	bands := l.Bands()
	out := make([]string, 0, len(bands)+1)
	for _, b := range bands {
		out = append(out, strings.ToLower(b.Label))
	}
	if withNotAssessed {
		out = append(out, NotAssessed)
	}
	return out
}

// BandIndex finds a band by label, case-insensitively.
func BandIndex(l BandLadder, label string) (int, bool) {
	for i, b := range l.Bands() {
		if strings.EqualFold(b.Label, label) {
			return i, true
		}
	}
	return 0, false
}

// BandBounds returns the half-open score interval [min, max) a label covers.
// hasMax is false for the top band, which is unbounded above.
func BandBounds(l BandLadder, label string) (min int, max int, hasMax bool, ok bool) {
	i, found := BandIndex(l, label)
	if !found {
		return 0, 0, false, false
	}
	bands := l.Bands()
	if i == 0 {
		return bands[i].Min, 0, false, true
	}
	return bands[i].Min, bands[i-1].Min, true, true
}

// BandAtLeast returns the inclusive lower bound of a label, which is what
// "high and above" means.
func BandAtLeast(l BandLadder, label string) (int, bool) {
	i, ok := BandIndex(l, label)
	if !ok {
		return 0, false
	}
	return l.Bands()[i].Min, true
}
