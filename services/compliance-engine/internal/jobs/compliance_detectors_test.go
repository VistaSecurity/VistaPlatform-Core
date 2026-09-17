package jobs

import "testing"

func TestControlSeverityToAlert(t *testing.T) {
	cases := map[string]string{
		"critical": "critical",
		"high":     "high",
		"medium":   "medium",
		"low":      "low",
		"  high  ": "",
		"":         "", // unknown → safe default
		"weird":    "",
	}
	for in, want := range cases {
		got, err := controlSeverityToAlert(in)
		if (err != nil) != (want == "") {
			t.Errorf("input %q validation err=%v", in, err)
		}
		if got != want {
			t.Errorf("controlSeverityToAlert(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsSignificantDrop(t *testing.T) {
	const thr = 10
	cases := []struct {
		ref, cur int
		want     bool
	}{
		{90, 90, false}, // no change
		{90, 80, false}, // exactly 10 — not > threshold
		{90, 79, true},  // 11-point drop
		{100, 50, true}, // big drop
		{50, 60, false}, // improved
	}
	for _, c := range cases {
		if got := isSignificantDrop(c.ref, c.cur, thr); got != c.want {
			t.Errorf("isSignificantDrop(%d, %d, %d) = %v, want %v", c.ref, c.cur, thr, got, c.want)
		}
	}
}
