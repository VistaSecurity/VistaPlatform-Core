package services

// The PRODUCTION query catalogue, wired to the production ladder.
//
// query_ladder_parity_test.go (workstream 0.8b) holds the first seam: the band
// thresholds the translator emits come from models.RiskBands, and the COPY
// shared/query tests against — testcatalog.CVSSLadder — equals it rung for
// rung. This file is the second seam, added with the registry catalogue
// (workstream 0.8d), and it deliberately does not repeat any of that:
//
//  1. shared/query/catalog/ladder now holds a SECOND copy of the same five
//     rungs, ladder.CVSS, because registrycatalog needs a default for a caller
//     with no service context. A second copy is a second chance to drift.
//  2. ladder.FromRungs fixes the LABELS and takes the rungs. Feeding it
//     models.RiskBands' numbers must reproduce models.RiskBands exactly —
//     labels included, which is the half a numbers-only check would miss.
//  3. The registry catalogue, built on models.RiskBands, must bind those rungs.
//     The band comparison is generated from the ladder the CATALOGUE carries
//     (query.DefaultOptionsFor), so this is the only place that proves the
//     production catalogue and the production ladder meet correctly.
//
// Why it is here and not in shared/: shared/ may not import a service, and
// models.RiskBands is in one. Every assertion below is of the form "the copy
// over there equals the original over here", and only this side can make it.

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/ladder"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
)

// TestSharedLadderMatchesRiskBands pins shared/query/catalog/ladder's default
// against models.RiskBands, rung for rung and label for label.
//
// ladder.CVSS is what query.DefaultCatalog() uses when no service supplies a
// ladder. If it drifted from models.RiskBands, a caller that took the default
// would band an asset one way while the badge beside it banded the same asset
// another — with nothing failing anywhere. That is the 60-vs-70 drift with an
// extra layer of indirection in front of it.
func TestSharedLadderMatchesRiskBands(t *testing.T) {
	assertSameLadder(t, "ladder.CVSS", ladder.CVSS.Bands())
}

// TestFromRungsReproducesRiskBands checks the CONSTRUCTOR, not just the
// constant: feed FromRungs the numbers out of models.RiskBands and it must
// produce models.RiskBands.
//
// FromRungs fixes the labels and takes only the four rungs above zero, so this
// is where a relabelled band would show up — "None" for "Informational", say,
// or a rung list that drifted out of order. Checking the numbers alone would
// pass on a ladder whose labels had been renamed underneath them.
func TestFromRungsReproducesRiskBands(t *testing.T) {
	if len(models.RiskBands) != 5 {
		t.Fatalf("models.RiskBands has %d rungs; ladder.FromRungs takes exactly five "+
			"(four above zero plus Informational). One of the two has to change deliberately.",
			len(models.RiskBands))
	}
	built := ladder.FromRungs(
		models.RiskBands[0].Min,
		models.RiskBands[1].Min,
		models.RiskBands[2].Min,
		models.RiskBands[3].Min,
	)
	assertSameLadder(t, "ladder.FromRungs(models.RiskBands…)", built.Bands())

	// The bottom rung is not a parameter: a score of zero is still a score,
	// and "not assessed" is a separate answer (§5.2, catalog.NotAssessed).
	if last := models.RiskBands[len(models.RiskBands)-1]; last.Min != 0 {
		t.Errorf("the lowest band starts at %d; ladder.FromRungs assumes 0", last.Min)
	}
}

// TestRegistryCatalogUsesRiskBands is the end-to-end half: build the production
// catalogue on models.RiskBands and compile a band comparison per rung. The
// bound threshold must be the rung — from the catalogue's own ladder, through
// query.DefaultOptionsFor, into the SQL.
func TestRegistryCatalogUsesRiskBands(t *testing.T) {
	cat := registrycatalog.New(registrycatalog.Options{Ladder: riskBandLadder{}})
	opts := query.DefaultOptionsFor(cat)

	for _, band := range models.RiskBands {
		label := strings.ToLower(band.Label)
		c, err := query.Compile("risk >= "+label, "asset", cat, opts)
		if err != nil {
			t.Fatalf("risk >= %s: %v", label, err)
		}
		if len(c.Args) != 1 || c.Args[0] != band.Min {
			t.Errorf("risk >= %s bound %v, want the RiskBands rung %d", label, c.Args, band.Min)
		}
	}

	// A finding's severity is the same ladder over a different column pair.
	c, err := query.Compile("severity >= high", "finding", cat, opts)
	if err != nil {
		t.Fatalf("severity >= high on finding: %v", err)
	}
	high, ok := catalog.BandAtLeast(riskBandLadder{}, "high")
	if !ok {
		t.Fatal("models.RiskBands has no High rung")
	}
	if len(c.Args) != 1 || c.Args[0] != high {
		t.Errorf("severity >= high bound %v, want %d", c.Args, high)
	}
}

// TestDefaultCatalogAgreesWithRiskBands is the reason ladder.CVSS is allowed to
// exist at all. A service SHOULD pass models.RiskBands; if one takes the
// package default instead, it must get the same answer.
func TestDefaultCatalogAgreesWithRiskBands(t *testing.T) {
	def := query.DefaultCatalog()
	explicit := registrycatalog.New(registrycatalog.Options{Ladder: riskBandLadder{}})

	for _, band := range models.RiskBands {
		q := "risk:" + strings.ToLower(band.Label)
		a, err := query.Compile(q, "asset", def, query.DefaultOptionsFor(def))
		if err != nil {
			t.Fatalf("%q on the default catalogue: %v", q, err)
		}
		b, err := query.Compile(q, "asset", explicit, query.DefaultOptionsFor(explicit))
		if err != nil {
			t.Fatalf("%q on models.RiskBands: %v", q, err)
		}
		if a.Where != b.Where {
			t.Errorf("%q:\n  default      %s\n  RiskBands    %s", q, a.Where, b.Where)
		}
		if len(a.Args) != len(b.Args) {
			t.Fatalf("%q bound %v by default and %v from RiskBands", q, a.Args, b.Args)
		}
		for i := range a.Args {
			if a.Args[i] != b.Args[i] {
				t.Errorf("%q bound %v by default and %v from RiskBands", q, a.Args, b.Args)
			}
		}
	}
}

func assertSameLadder(t *testing.T, what string, got []catalog.Band) {
	t.Helper()
	if len(got) != len(models.RiskBands) {
		t.Fatalf("%s has %d rungs, models.RiskBands has %d", what, len(got), len(models.RiskBands))
	}
	for i, want := range models.RiskBands {
		if got[i].Label != want.Label || got[i].Min != want.Min {
			t.Errorf("%s rung %d: {%s %d}, models.RiskBands has {%s %d}",
				what, i, got[i].Label, got[i].Min, want.Label, want.Min)
		}
	}
}

// TestSoftwareLensDrillThroughTermsCompile pins the cross-language seam the
// Inventory software lens depends on.
//
// `productDrillThroughQuery` in frontend-v2/src/sections/inventory/
// software-queries.ts builds a query-language term in TypeScript, and the
// PRODUCTION catalogue in this repository is what has to accept it. Nothing
// else joins those two halves: the lens's own vitest asserts the STRING it
// produces, which proves the shape and not that the shape parses, and every
// test of the parser uses terms written in Go.
//
// So the four shapes the lens can emit are written out here and compiled
// against the real registry catalogue. The list is a transcription and can
// drift from the TypeScript — that is a weaker guarantee than generating one
// from the other, and it is stated rather than implied. What it does catch is
// the direction that has already bitten: a field renamed or retyped on this
// side, which turns every drill-through link in the lens into a parse error
// with nothing on this side failing.
//
// The `version="latest"` case is the one that found a live defect. `version` is
// a VERSION-typed field, so the validator refuses a literal with no numeric
// component — and the lens used to emit exactly that for any product whose
// `version_sort` is NULL. It now falls back to the name, which is why that
// shape is absent below and `name`-only is present.
func TestSoftwareLensDrillThroughTermsCompile(t *testing.T) {
	cat := registrycatalog.New(registrycatalog.Options{Ladder: riskBandLadder{}})
	opts := query.DefaultOptionsFor(cat)

	for _, src := range []string{
		// purl — the first rung, and the percent-encoded form a scoped npm
		// package actually publishes.
		`software:(purl="pkg:npm/%40angular/core@17.0.0")`,
		// CPE — the second rung.
		`software:(cpe="cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*")`,
		// name + version, used only when the row has a version_sort.
		`software:(name="openssl" and version="3.0.13")`,
		// name alone — no purl, no CPE, or a version with no sort key.
		`software:(name="mytool")`,
	} {
		if _, err := query.Compile(src, "asset", cat, opts); err != nil {
			t.Errorf("the software lens emits %s, which the production catalogue refuses: %v", src, err)
		}
	}

	// The polarity that made the fix necessary: a version the query language
	// cannot turn into a sort key must still be REFUSED here. If this ever
	// starts compiling, the lens's version_sort guard is free to go — and until
	// it does, removing that guard puts the broken link straight back.
	if _, err := query.Compile(`software:(name="mytool" and version="latest")`, "asset", cat, opts); err == nil {
		t.Error("`version=\"latest\"` compiled; the lens guards against emitting it because it did not")
	}
}
