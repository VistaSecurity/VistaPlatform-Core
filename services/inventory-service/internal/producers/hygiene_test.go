package producers

// The hygiene producer's decisions, without a database.
//
// Three things live here: the stale ladder's join to the registry (the same
// shape ladder_test.go uses for end-of-life), the placeholder-class set's join
// to the asset-class taxonomy, and the day arithmetic.

import (
	"strconv"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// TestStaleLadderMatchesRegistry is the join between the two halves of the
// ladder: this package owns the day boundaries, the registry owns what each
// rung MEANS, and the writer refuses any pair that is not one of its rungs.
//
// If somebody edits standards/findings-registry.yaml — adds a rung, reorders
// them, rewords a threshold — this fails, and the person who did it has to
// decide what the day boundaries should be rather than discovering later that
// findings stopped escalating.
func TestStaleLadderMatchesRegistry(t *testing.T) {
	k, ok := findings.Get(findings.ProducerHygiene, findings.KindStale)
	if !ok {
		t.Fatal("stale is not registered under the hygiene producer")
	}
	if k.SeverityModel != "ladder" {
		t.Fatalf("severity_model=%q, want ladder — this producer picks rungs", k.SeverityModel)
	}
	if len(k.Rungs) != len(staleLadderDays) {
		t.Fatalf("the registry has %d rungs and this producer maps %d; staleRungFor indexes them positionally",
			len(k.Rungs), len(staleLadderDays))
	}

	wantThresholds := []string{
		"not seen for 30 days",
		"not seen for 90 days",
		"not seen for 180 days",
	}
	for i, want := range wantThresholds {
		if k.Rungs[i].Threshold != want {
			t.Errorf("rung %d threshold = %q, want %q — the day boundary in this package no longer describes what the registry says",
				i, k.Rungs[i].Threshold, want)
		}
	}

	// Severities escalate and scores do not. Every hygiene kind is feeds_risk
	// false, so every rung's score must be 0: the writer refuses anything else,
	// and a stale record must never inflate a security number.
	for i, r := range k.Rungs {
		if r.Score != 0 {
			t.Errorf("rung %d scores %d; hygiene feeds no risk and the writer refuses a non-zero score on it", i, r.Score)
		}
		if i > 0 && !producer.SeverityAtLeast(r.Severity, k.Rungs[i-1].Severity) {
			t.Errorf("rung %d is %q, milder than rung %d's %q — rungs are ordered worst-last",
				i, r.Severity, i-1, k.Rungs[i-1].Severity)
		}
	}

	// And the threshold WORDING has to contain the number this package uses.
	// A rung labelled "not seen for 30 days" whose producer fires at 45 is a
	// registry that documents a decision nobody took.
	for i, days := range staleLadderDays {
		if want := "not seen for " + strconv.Itoa(days) + " days"; k.Rungs[i].Threshold != want {
			t.Errorf("rung %d: this package fires at %d days, the registry says %q",
				i, days, k.Rungs[i].Threshold)
		}
	}
}

// The ladder's boundaries, both directions. Mutation check: move any boundary
// in staleLadderDays and a case here goes red; widen the comparison from >= to
// > and the exact-boundary cases go red.
func TestStaleRungFor(t *testing.T) {
	cases := []struct {
		days    int
		wantOK  bool
		wantIdx int
		want    int
	}{
		{days: 0, wantOK: false},
		{days: 29, wantOK: false},
		{days: 30, wantOK: true, wantIdx: 0, want: 30},
		{days: 89, wantOK: true, wantIdx: 0, want: 30},
		{days: 90, wantOK: true, wantIdx: 1, want: 90},
		{days: 179, wantOK: true, wantIdx: 1, want: 90},
		{days: 180, wantOK: true, wantIdx: 2, want: 180},
		{days: 4000, wantOK: true, wantIdx: 2, want: 180},
		// Negative is a clock skew, not freshness from the future. It must not
		// report a rung.
		{days: -5, wantOK: false},
	}
	for _, tc := range cases {
		gotDays, gotIdx, ok := staleRungFor(tc.days)
		if ok != tc.wantOK {
			t.Errorf("staleRungFor(%d) ok=%v, want %v", tc.days, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if gotIdx != tc.wantIdx || gotDays != tc.want {
			t.Errorf("staleRungFor(%d) = (%d days, rung %d), want (%d days, rung %d)",
				tc.days, gotDays, gotIdx, tc.want, tc.wantIdx)
		}
		// Every index the ladder returns must exist in the registry.
		if _, err := producer.Rung(findings.ProducerHygiene, findings.KindStale, gotIdx); err != nil {
			t.Errorf("staleRungFor(%d) returned rung %d, which the registry does not have: %v", tc.days, gotIdx, err)
		}
	}
}

// The detail is the RUNG's boundary, not the exact day count, so an open
// finding's summary does not get rewritten every night.
func TestStaleDetailIsStableWithinARung(t *testing.T) {
	a, _, _ := staleRungFor(31)
	b, _, _ := staleRungFor(88)
	if staleDetail(a) != staleDetail(b) {
		t.Errorf("31 days reads %q and 88 days reads %q; both are on the 30-day rung and the summary must not churn nightly",
			staleDetail(a), staleDetail(b))
	}
	c, _, _ := staleRungFor(95)
	if staleDetail(b) == staleDetail(c) {
		t.Error("the 30-day and 90-day rungs read the same; escalation would be invisible in the list")
	}
}

// The placeholder set must name classes the taxonomy actually has, and must not
// quietly grow to include real classes. The taxonomy's own model section is
// explicit that an intermediate class is a real answer: "classifying a box as
// `hardware` when we know no more than that is the honest answer".
func TestPlaceholderClassesAreRealAndNarrow(t *testing.T) {
	if len(placeholderClasses) == 0 {
		t.Fatal("no placeholder classes; no_class could never fire")
	}
	for key := range placeholderClasses {
		if _, ok := assetclass.Get(key); !ok {
			t.Errorf("%q is not a class in standards/asset-classes.yaml", key)
		}
	}
	if !placeholderClasses[assetclass.KeyUnknownHost] {
		t.Error("unknown_host is not in the placeholder set; it is the one class the taxonomy describes as a real gap, and IH-002 matches on it")
	}
	// A sample of genuinely-classified keys that must NOT be treated as gaps.
	for _, real := range []string{
		assetclass.KeyHardware, assetclass.KeyServer, assetclass.KeyNetworkDevice,
		assetclass.KeySwitch, assetclass.KeyExternal,
	} {
		if isPlaceholderClass(real) {
			t.Errorf("%q is treated as unclassified; it is a real class and an asset on it is classified, coarsely and truthfully", real)
		}
	}
	// The empty string is the one value that is neither.
	if !isPlaceholderClass("") {
		t.Error("an empty class_key is not treated as unclassified; the least-classified asset in the estate would be the only one with no finding")
	}
}

// Calendar days, not 24-hour periods — a record does not become stale eleven
// hours early because the pass started in the afternoon.
func TestDaysBetweenCountsCalendarDays(t *testing.T) {
	base := time.Date(2026, 3, 10, 23, 30, 0, 0, time.UTC)
	if got := daysBetween(base, base.Add(2*time.Hour)); got != 1 {
		t.Errorf("23:30 to 01:30 the next day = %d days, want 1 (one calendar day)", got)
	}
	if got := daysBetween(base, base.Add(23*time.Hour)); got != 1 {
		t.Errorf("same-calendar-day-plus-one = %d, want 1", got)
	}
	if got := daysBetween(base, base); got != 0 {
		t.Errorf("a subject seen just now = %d days, want 0", got)
	}
	// Across a month boundary, and in a zone that is not UTC on either side.
	tz := time.FixedZone("UTC+13", 13*3600)
	from := time.Date(2026, 2, 26, 1, 0, 0, 0, tz)
	to := time.Date(2026, 3, 8, 1, 0, 0, 0, tz)
	if got := daysBetween(from, to); got != 10 {
		t.Errorf("26 Feb to 8 Mar = %d days, want 10", got)
	}
}

// Every hygiene kind is feeds_risk false with a zero score. This is the
// registry-side half of the writer's refusal, asserted here so that flipping
// one kind to feeds_risk true fails in this package rather than at the first
// upsert of the night.
func TestHygieneKindsFeedNoRisk(t *testing.T) {
	if len(hygieneKinds) == 0 {
		t.Fatal("the hygiene producer emits no kinds")
	}
	for _, key := range hygieneKinds {
		k, ok := findings.Get(findings.ProducerHygiene, key)
		if !ok {
			t.Fatalf("%q is in hygieneKinds but not in the registry", key)
		}
		if k.FeedsRisk {
			t.Errorf("kind %q feeds risk; hygiene is data quality and must never inflate a security score", key)
		}
		if k.Score != 0 {
			t.Errorf("kind %q scores %d; a feeds_risk-false kind must write 0", key, k.Score)
		}
	}
}
