package jobs

import "testing"

// currentTier drives the escalation boundaries of the certificate-expiry scan: an
// alert fires once per tier crossed (tightest = lowest number; 0 = expired), and a
// cert more than 30 days out has no tier. Pure, so no database.
func TestCurrentTier(t *testing.T) {
	cases := []struct {
		days    int
		tier    int
		applies bool
	}{
		{days: 40, tier: 0, applies: false}, // comfortably valid
		{days: 31, tier: 0, applies: false}, // just outside the widest tier
		{days: 30, tier: 30, applies: true}, // enters 30-day tier
		{days: 20, tier: 30, applies: true}, // still 30-day tier
		{days: 14, tier: 14, applies: true}, // escalates to 14
		{days: 10, tier: 14, applies: true}, // still 14
		{days: 7, tier: 7, applies: true},   // escalates to 7
		{days: 3, tier: 7, applies: true},   // still 7
		{days: 0, tier: 0, applies: true},   // expired
		{days: -10, tier: 0, applies: true}, // long expired
	}
	for _, c := range cases {
		tier, applies := currentTier(c.days)
		if tier != c.tier || applies != c.applies {
			t.Errorf("currentTier(%d) = (%d, %v), want (%d, %v)", c.days, tier, applies, c.tier, c.applies)
		}
	}
}
