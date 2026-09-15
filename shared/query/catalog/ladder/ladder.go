// Package ladder builds a catalog.BandLadder from its rungs.
//
// The one true ladder is models.RiskBands in services/inventory-service, which
// shared/ may not import (QUERY_LANGUAGE §5.5, and catalog.BandLadder's own
// doc). A service passes that slice in. Everything else — a shared package's
// tests, a tool, a default for a caller that has no service context — needs the
// same five rungs without the import, and this is the one place they are
// written down so a copy cannot be spelled differently in two files.
//
// The rung VALUES are the caller's; only the labels and their order are fixed.
// That is the whole shape of the thing: a ladder is five labels, highest first,
// each with an inclusive lower bound, and the bottom rung is always 0 because
// a score of zero is still a score (§5.2 — "not assessed" is a separate answer,
// catalog.NotAssessed, and never a rung).
package ladder

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// Labels are the five band labels, highest first. They are the CVSS v3.1/v4.0
// qualitative severity ratings, with CVSS's "None" displayed as
// "Informational" — the product has always used that word, and
// models.RiskBands says so too.
var Labels = [5]string{"Critical", "High", "Medium", "Low", "Informational"}

// Ladder is a catalog.BandLadder over fixed labels and caller-supplied rungs.
type Ladder struct {
	bands []catalog.Band
}

// Bands implements catalog.BandLadder. It hands back a copy: the ladder is
// usually a package-level value, and a caller that sorted or truncated the
// slice in place would move every band predicate in the process.
func (l Ladder) Bands() []catalog.Band {
	out := make([]catalog.Band, len(l.bands))
	copy(out, l.bands)
	return out
}

// FromRungs builds the ladder from the four inclusive lower bounds above zero.
// Informational is always 0 and is not a parameter: there is no ladder in which
// the lowest band starts anywhere else.
//
// It panics on rungs that are not strictly descending and above zero, the way
// regexp.MustCompile panics on a bad pattern: the rungs are a code constant, a
// misordered ladder is a programming error, and silently accepting one would
// make every band comparison in the product wrong while every test still
// passed. (BandBounds reads rung i-1 as rung i's exclusive upper bound, so a
// non-descending ladder yields empty or overlapping intervals — the exact
// 60-vs-70 drift this indirection exists to prevent.)
func FromRungs(critical, high, medium, low int) Ladder {
	mins := [5]int{critical, high, medium, low, 0}
	for i := 1; i < len(mins); i++ {
		if mins[i] >= mins[i-1] {
			panic(fmt.Sprintf(
				"query/catalog/ladder: rungs must be strictly descending and above zero; "+
					"%s=%d is not below %s=%d",
				Labels[i], mins[i], Labels[i-1], mins[i-1]))
		}
	}
	bands := make([]catalog.Band, 0, len(Labels))
	for i, label := range Labels {
		bands = append(bands, catalog.Band{Label: label, Min: mins[i]})
	}
	return Ladder{bands: bands}
}

// CVSS is the CVSS v3.1/v4.0 qualitative severity ratings ×10 — Critical ≥ 90,
// High 70–89, Medium 40–69, Low 1–39, Informational 0 — which is what
// models.RiskBands holds.
//
// It is the default for a caller with no service context. A SERVICE must pass
// models.RiskBands itself rather than rely on this: the two are pinned equal by
// services/inventory-service/internal/services/query_registry_catalog_test.go,
// and that test is the only thing standing between a copy and a second opinion.
var CVSS = FromRungs(90, 70, 40, 1)
