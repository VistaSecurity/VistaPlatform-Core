package services

import (
	"testing"
	"time"
)

func TestRiskIndex(t *testing.T) {
	cases := []struct {
		high, total, want int
	}{
		{0, 0, 0},   // no assets → 0 (not a divide-by-zero)
		{0, 100, 0}, // none high-risk
		{8, 120, 7}, // 6.66% → rounds to 7
		{50, 100, 50},
		{1, 3, 33}, // 33.33% → 33
		{2, 3, 67}, // 66.66% → 67
	}
	for _, c := range cases {
		if got := riskIndex(c.high, c.total); got != c.want {
			t.Errorf("riskIndex(%d,%d) = %d, want %d", c.high, c.total, got, c.want)
		}
	}
}

func TestBuildPostureTrend(t *testing.T) {
	// Fixed "today" so dates are deterministic.
	today := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	d := func(daysAgo int) string { return today.AddDate(0, 0, -daysAgo).Format("2006-01-02") }

	t.Run("new tenant with no snapshots is seeded flat at live posture", func(t *testing.T) {
		pts := buildPostureTrend(map[string]int{}, 12, 5, today)
		if len(pts) != 5 {
			t.Fatalf("len = %d, want 5", len(pts))
		}
		// Days 4..1 ago are seeded; today is live (not seeded). All carry the live value.
		for i, p := range pts {
			if p.RiskIndex != 12 {
				t.Errorf("point %d risk_index = %d, want 12", i, p.RiskIndex)
			}
			wantSeeded := i != len(pts)-1 // only the last point (today) is non-seeded
			if p.Seeded != wantSeeded {
				t.Errorf("point %d (%s) seeded = %v, want %v", i, p.Date, p.Seeded, wantSeeded)
			}
		}
		if pts[len(pts)-1].Date != d(0) {
			t.Errorf("last point date = %s, want today %s", pts[len(pts)-1].Date, d(0))
		}
	})

	t.Run("pre-history seeded, real snapshots used, gaps carried forward, today live", func(t *testing.T) {
		// Real snapshots only on 3-days-ago (40) and 2-days-ago (30). 4 & 1 days ago absent.
		real := map[string]int{d(3): 40, d(2): 30}
		pts := buildPostureTrend(real, 25, 5, today) // live posture = 25

		want := []struct {
			date      string
			riskIndex int
			seeded    bool
		}{
			{d(4), 25, true},  // before first real snapshot → seeded at live
			{d(3), 40, false}, // real
			{d(2), 30, false}, // real
			{d(1), 30, false}, // gap after real → carry forward last real (30)
			{d(0), 25, false}, // today → live posture, never seeded
		}
		if len(pts) != len(want) {
			t.Fatalf("len = %d, want %d", len(pts), len(want))
		}
		for i, w := range want {
			if pts[i].Date != w.date || pts[i].RiskIndex != w.riskIndex || pts[i].Seeded != w.seeded {
				t.Errorf("point %d = %+v, want {date:%s risk:%d seeded:%v}", i, pts[i], w.date, w.riskIndex, w.seeded)
			}
		}
	})

	t.Run("real snapshot of risk-index 0 is not mistaken for an absent day", func(t *testing.T) {
		// A genuine 0 on 2-days-ago must be Seeded=false (real), not carried/seeded.
		real := map[string]int{d(2): 0}
		pts := buildPostureTrend(real, 9, 4, today)
		// pts: d(3) pre-history seeded@9, d(2) real 0, d(1) carry 0, d(0) live 9
		if pts[1].Date != d(2) || pts[1].RiskIndex != 0 || pts[1].Seeded {
			t.Errorf("real-zero point = %+v, want {date:%s risk:0 seeded:false}", pts[1], d(2))
		}
		if pts[0].RiskIndex != 9 || !pts[0].Seeded {
			t.Errorf("pre-history point = %+v, want risk:9 seeded:true", pts[0])
		}
	})
}
