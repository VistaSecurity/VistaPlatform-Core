package services

import (
	"strings"
	"testing"
)

func TestDigestWindowMinutes(t *testing.T) {
	four := 240
	cases := []struct {
		freq     string
		override *int
		want     int
	}{
		{"immediate", nil, 0},
		{"", nil, 0},
		{"digest_hourly", nil, 60},
		{"digest_daily", nil, 1440},
		{"digest_weekly", nil, 10080},
		{"digest_hourly", &four, 240}, // per-rule override wins
	}
	for _, c := range cases {
		if got := digestWindowMinutes(c.freq, c.override); got != c.want {
			t.Errorf("digestWindowMinutes(%q,%v)=%d want %d", c.freq, c.override, got, c.want)
		}
	}
}

func TestIsDigestFrequency(t *testing.T) {
	for freq, want := range map[string]bool{
		"immediate": false, "": false, "digest_hourly": true, "digest_daily": true, "digest_weekly": true,
	} {
		if got := isDigestFrequency(freq); got != want {
			t.Errorf("isDigestFrequency(%q)=%v want %v", freq, got, want)
		}
	}
}

func TestComposeDigest(t *testing.T) {
	items := []digestItem{
		{alertType: "certificate_expiring", severity: "medium", message: "cert A expires soon"},
		{alertType: "sensor_offline", severity: "high", message: "sensor B offline"},
		{alertType: "control_noncompliant", severity: "low", message: "control C"},
	}
	subject, body, top := composeDigest(items)
	if top != "high" {
		t.Errorf("top severity = %q, want high", top)
	}
	if !strings.Contains(subject, "3") {
		t.Errorf("subject should mention count: %q", subject)
	}
	for _, want := range []string{"sensor_offline", "certificate_expiring", "control_noncompliant"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

func TestTruncateMessage(t *testing.T) {
	if got := truncateMessage("short", 100); got != "short" {
		t.Errorf("short unchanged: %q", got)
	}
	long := strings.Repeat("x", 200)
	got := truncateMessage(long, 50)
	if len([]rune(got)) != 50 {
		t.Errorf("truncated len = %d runes, want 50", len([]rune(got)))
	}
}
