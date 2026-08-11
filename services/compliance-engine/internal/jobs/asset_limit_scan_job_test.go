package jobs

import "testing"

func TestAssetSeverity(t *testing.T) {
	const warn, high = 80, 95
	cases := []struct {
		name string
		pct  float64
		want string
	}{
		{"empty", 0, ""},
		{"below warn", 79.9, ""},
		{"at warn", 80, "info"},
		{"between rungs", 90, "info"},
		{"just below high", 94.99, "info"},
		{"at high", 95, "high"},
		{"over limit", 130, "high"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := assetSeverity(c.pct, warn, high); got != c.want {
				t.Errorf("assetSeverity(%v, %d, %d) = %q, want %q", c.pct, warn, high, got, c.want)
			}
		})
	}
}

// A tenant-moved warn rung shifts where info begins without touching the high rung.
func TestAssetSeverity_CustomWarnRung(t *testing.T) {
	const high = 95
	if got := assetSeverity(85, 90, high); got != "" {
		t.Errorf("with warn=90, 85%% should be below warn, got %q", got)
	}
	if got := assetSeverity(92, 90, high); got != "info" {
		t.Errorf("with warn=90, 92%% should be info, got %q", got)
	}
	if got := assetSeverity(96, 90, high); got != "high" {
		t.Errorf("with warn=90, 96%% should still be high, got %q", got)
	}
}
