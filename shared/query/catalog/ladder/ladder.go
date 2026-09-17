// Package ladder adapts canonical risk bands to query catalogues.
package ladder

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

// Labels retain the query adapter's five-rung API, derived from the risk owner.
var Labels = func() [5]string {
	var labels [5]string
	if len(riskbands.RiskBands) != len(labels) {
		panic("query risk ladder must have five bands")
	}
	for i, band := range riskbands.RiskBands {
		labels[i] = band.Label
	}
	return labels
}()

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

// CVSS adapts the canonical risk owner; no local threshold copy is permitted.
var CVSS = fromRiskBands()

func fromRiskBands() Ladder {
	bands := make([]catalog.Band, 0, len(riskbands.RiskBands))
	for _, band := range riskbands.RiskBands {
		bands = append(bands, catalog.Band{Label: band.Label, Min: band.Min})
	}
	return Ladder{bands: bands}
}
