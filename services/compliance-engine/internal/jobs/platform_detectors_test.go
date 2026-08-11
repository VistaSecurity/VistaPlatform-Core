package jobs

import "testing"

func TestHealthDegradedSeverity(t *testing.T) {
	cases := map[float64]string{
		59.9: "medium",
		40:   "medium",
		39.9: "high",
		10:   "high",
		0:    "high",
	}
	for score, want := range cases {
		if got := healthDegradedSeverity(score); got != want {
			t.Errorf("healthDegradedSeverity(%v) = %q, want %q", score, got, want)
		}
	}
}

// serviceSubjectID must be stable (same name → same UUID) so an ongoing
// outage dedups to one alert and auto-resolve keys correctly.
func TestServiceSubjectID_Stable(t *testing.T) {
	a := serviceSubjectID("auth-service")
	b := serviceSubjectID("auth-service")
	c := serviceSubjectID("compliance-engine")
	if a != b {
		t.Errorf("same service name gave different UUIDs: %s != %s", a, b)
	}
	if a == c {
		t.Errorf("different service names collided: %s", a)
	}
}
