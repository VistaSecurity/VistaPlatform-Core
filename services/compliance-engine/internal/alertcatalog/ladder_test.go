package alertcatalog

import "testing"

// Pins the decided trigger model (NOTIFICATION_ALERTING_ARCHITECTURE.md §8.3,
// decision log #2): preference REPLACES baseline; policy rungs are ADDITIVE
// (more policies = more warning, never less); same-day collisions take max
// severity; disabling a type drops baseline/preference but keeps policy rungs.
func TestBuildLadder(t *testing.T) {
	baseline := &Rung{Days: 60, Severity: "medium"}

	t.Run("baseline only", func(t *testing.T) {
		l := BuildLadder(baseline, nil, nil, true)
		if len(l) != 1 || l[0].Days != 60 || l[0].Severity != "medium" || l[0].Source != "baseline" {
			t.Fatalf("got %+v", l)
		}
	})

	t.Run("preference replaces baseline", func(t *testing.T) {
		l := BuildLadder(baseline, &Rung{Days: 45, Severity: "medium"}, nil, true)
		if len(l) != 1 || l[0].Days != 45 || l[0].Source != "preference" {
			t.Fatalf("preference must replace baseline, got %+v", l)
		}
	})

	t.Run("policy rungs additive above and below baseline", func(t *testing.T) {
		policy := []Rung{
			{Days: 90, Severity: "low", Source: "policy:90-Day Notice"},
			{Days: 30, Severity: "high", Source: "policy:PCI-DSS"},
			{Days: 0, Severity: "critical", Source: "policy:Not Expired"},
		}
		l := BuildLadder(baseline, nil, policy, true)
		if len(l) != 4 {
			t.Fatalf("want 4 rungs, got %+v", l)
		}
		// Sorted most-days-first: 90, 60, 30, 0.
		wantDays := []int{90, 60, 30, 0}
		for i, d := range wantDays {
			if l[i].Days != d {
				t.Fatalf("rung %d: want days %d, got %+v", i, d, l)
			}
		}
	})

	t.Run("same-day collision takes max severity", func(t *testing.T) {
		policy := []Rung{{Days: 60, Severity: "high", Source: "policy:PCI-DSS"}}
		l := BuildLadder(baseline, nil, policy, true)
		if len(l) != 1 || l[0].Severity != "high" || l[0].Source != "policy:PCI-DSS" {
			t.Fatalf("collision must take max severity, got %+v", l)
		}
	})

	t.Run("collision never downgrades", func(t *testing.T) {
		policy := []Rung{{Days: 60, Severity: "low", Source: "policy:weak"}}
		l := BuildLadder(baseline, nil, policy, true)
		if len(l) != 1 || l[0].Severity != "medium" || l[0].Source != "baseline" {
			t.Fatalf("lower-severity collision must not downgrade, got %+v", l)
		}
	})

	t.Run("disabled type keeps only policy rungs", func(t *testing.T) {
		policy := []Rung{{Days: 30, Severity: "high", Source: "policy:PCI-DSS"}}
		l := BuildLadder(baseline, &Rung{Days: 45, Severity: "medium"}, policy, false)
		if len(l) != 1 || l[0].Days != 30 || l[0].Source != "policy:PCI-DSS" {
			t.Fatalf("disabled type must keep policy rungs only, got %+v", l)
		}
	})

	t.Run("disabled type with no policy is empty", func(t *testing.T) {
		if l := BuildLadder(baseline, nil, nil, false); len(l) != 0 {
			t.Fatalf("want empty ladder, got %+v", l)
		}
	})
}

// Pins the crossing semantics: severity at N days remaining = max severity of
// crossed rungs; above every rung = "" (no alert open; auto-resolve signal).
func TestEffectiveSeverity(t *testing.T) {
	ladder := []Rung{
		{Days: 90, Severity: "low"},
		{Days: 60, Severity: "medium"},
		{Days: 30, Severity: "high"},
		{Days: 0, Severity: "critical"},
	}
	cases := []struct {
		days int
		want string
	}{
		{120, ""},        // above all rungs — nothing open
		{91, ""},         // just above the earliest rung
		{90, "low"},      // crosses 90
		{61, "low"},      // still only 90 crossed
		{45, "medium"},   // 90+60 crossed
		{30, "high"},     // 90+60+30
		{7, "high"},      // between 30 and 0
		{0, "critical"},  // expired
		{-3, "critical"}, // past expiry stays critical
	}
	for _, tc := range cases {
		if got := EffectiveSeverity(ladder, tc.days); got != tc.want {
			t.Errorf("EffectiveSeverity(%d) = %q, want %q", tc.days, got, tc.want)
		}
	}
	if MaxDays(ladder) != 90 {
		t.Errorf("MaxDays = %d, want 90", MaxDays(ladder))
	}
}
