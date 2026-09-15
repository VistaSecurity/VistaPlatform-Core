package services

// Parity between the query language's band ladder and models.RiskBands.
//
// shared/query cannot import a service, so `risk >= high` is generated from a
// catalog.BandLadder the CALLER supplies (QUERY_LANGUAGE §5.5, and the README's
// "Plugging in the band ladder"). That indirection is the whole safety
// mechanism: every band predicate comes from one ladder and never from a
// threshold written in the translator.
//
// An indirection is only as good as the thing plugged into it. These tests are
// the two ends of it:
//
//  1. Wire models.RiskBands in and compile every band comparison. The bound
//     threshold must be RiskBands' rung — so a change to the ladder moves the
//     query language with it, and a hard-coded number in the translator would
//     fail here.
//  2. testcatalog.CVSSLadder, the copy shared/ tests against because it may not
//     import this package, must equal models.RiskBands rung for rung. Without
//     this the two can drift silently: every test in shared/query would keep
//     passing against a ladder production does not use.

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
)

// riskBandLadder was a COPY of the adapter, written here when nothing in
// production used one. asset_query.go has the real one now, so this is an alias
// rather than a second implementation: a test that exercised its own copy would
// keep passing while production's drifted, which is the exact failure this file
// exists to prevent one layer down.
type riskBandLadder = RiskBandLadder

// TestQueryBandThresholdsComeFromRiskBands compiles a band comparison per rung,
// at both ends of the ladder, and asserts the bound threshold is the rung's Min
// from models.RiskBands — not a number the translator chose.
func TestQueryBandThresholdsComeFromRiskBands(t *testing.T) {
	cat := testcatalog.New()
	opts := query.DefaultOptions(riskBandLadder{})

	for i, band := range models.RiskBands {
		label := strings.ToLower(band.Label)

		// `risk >= <band>` binds the rung's inclusive lower bound, and nothing
		// else. That is the comparison §5.5 names explicitly, and the one the
		// 60-vs-70 drift was found in.
		c, err := query.Compile("risk >= "+label, "asset", cat, opts)
		if err != nil {
			t.Fatalf("risk >= %s: %v", label, err)
		}
		if len(c.Args) != 1 || c.Args[0] != band.Min {
			t.Errorf("risk >= %s bound %v, want the RiskBands rung %d", label, c.Args, band.Min)
		}

		// `risk < <band>` is the same rung from below.
		c, err = query.Compile("risk < "+label, "asset", cat, opts)
		if err != nil {
			t.Fatalf("risk < %s: %v", label, err)
		}
		if len(c.Args) != 1 || c.Args[0] != band.Min {
			t.Errorf("risk < %s bound %v, want the RiskBands rung %d", label, c.Args, band.Min)
		}

		// `risk:<band>` is the half-open interval [this rung, next rung up),
		// unbounded for the top band. Both ends come from RiskBands.
		c, err = query.Compile("risk:"+label, "asset", cat, opts)
		if err != nil {
			t.Fatalf("risk:%s: %v", label, err)
		}
		if i == 0 {
			if len(c.Args) != 1 || c.Args[0] != band.Min {
				t.Errorf("risk:%s bound %v, want just the rung %d (the top band is unbounded above)",
					label, c.Args, band.Min)
			}
			continue
		}
		upper := models.RiskBands[i-1].Min
		if len(c.Args) != 2 || c.Args[0] != band.Min || c.Args[1] != upper {
			t.Errorf("risk:%s bound %v, want [%d, %d)", label, c.Args, band.Min, upper)
		}
	}

	// And the whole-ladder range: bottom rung's Min to the top rung's Min.
	lowest := models.RiskBands[len(models.RiskBands)-1]
	highest := models.RiskBands[0]
	c, err := query.Compile("risk:["+strings.ToLower(lowest.Label)+" to "+
		strings.ToLower(models.RiskBands[1].Label)+"]", "asset", cat, opts)
	if err != nil {
		t.Fatalf("risk range: %v", err)
	}
	if len(c.Args) != 2 || c.Args[0] != lowest.Min || c.Args[1] != highest.Min {
		t.Errorf("the ladder-wide range bound %v, want [%d, %d)", c.Args, lowest.Min, highest.Min)
	}
}

// TestTestCatalogLadderMatchesRiskBands is the seam's other end. shared/ may not
// import this package, so its tests run against testcatalog.CVSSLadder — a COPY.
// A copy that drifts is worse than no copy: every test in shared/query would go
// on passing against a ladder production does not use.
func TestTestCatalogLadderMatchesRiskBands(t *testing.T) {
	copyBands := testcatalog.CVSSLadder{}.Bands()
	if len(copyBands) != len(models.RiskBands) {
		t.Fatalf("testcatalog.CVSSLadder has %d rungs, models.RiskBands has %d",
			len(copyBands), len(models.RiskBands))
	}
	for i, want := range models.RiskBands {
		got := copyBands[i]
		if got.Label != want.Label || got.Min != want.Min {
			t.Errorf("rung %d: testcatalog has {%s %d}, models.RiskBands has {%s %d}",
				i, got.Label, got.Min, want.Label, want.Min)
		}
	}
	// Order is load-bearing in both: highest first, walked top-down.
	for i := 1; i < len(copyBands); i++ {
		if copyBands[i].Min >= copyBands[i-1].Min {
			t.Errorf("rung %d (%s, %d) is not below rung %d (%s, %d); the ladder must be highest-first",
				i, copyBands[i].Label, copyBands[i].Min,
				i-1, copyBands[i-1].Label, copyBands[i-1].Min)
		}
	}
}

// TestQueryBandsAgreeWithGetRiskLevel closes the loop the other way: for every
// score 0–100, the band whose query predicate matches it must be the band
// models.GetRiskLevel names. The query language and the badge cannot disagree
// about one asset.
func TestQueryBandsAgreeWithGetRiskLevel(t *testing.T) {
	ladder := riskBandLadder{}
	for score := 0; score <= 100; score++ {
		want := models.GetRiskLevel(score)
		var got string
		for _, b := range ladder.Bands() {
			min, max, hasMax, ok := catalog.BandBounds(ladder, b.Label)
			if !ok {
				t.Fatalf("BandBounds(%s) failed", b.Label)
			}
			if score >= min && (!hasMax || score < max) {
				got = b.Label
				break
			}
		}
		if got != want {
			t.Errorf("score %d: the query ladder says %q, GetRiskLevel says %q", score, got, want)
		}
	}
}
