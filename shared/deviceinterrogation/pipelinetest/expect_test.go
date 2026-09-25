package pipelinetest

import (
	"fmt"
	"strings"
	"testing"
)

// recorder is a testing.TB that records instead of failing, so the helper's
// own verdicts can be asserted. Fatalf does not stop the goroutine here; the
// helper returns after calling it, which is all these cases need.
type recorder struct {
	testing.TB
	errors, fatals []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

// TestExpect_KnownGapVerdicts pins all four verdicts, because a knownGap
// helper that could not report the fix, or the drift, would turn every gap in
// the chain into a check that cannot fail.
func TestExpect_KnownGapVerdicts(t *testing.T) {
	cases := []struct {
		name       string
		e          Expectation
		wantError  string
		wantFatal  string
		wantSilent bool
	}{
		{name: "hard assertion holds", e: Expectation{What: "x", Got: 1, Want: 1}, wantSilent: true},
		{name: "hard assertion fails", e: Expectation{What: "x", Got: 2, Want: 1}, wantError: "want 1"},
		{name: "gap still open", e: Expectation{What: "x", Got: "old", Want: "new", KnownGap: "P-00 / W0.0", Current: "old"}, wantSilent: true},
		{name: "gap fixed", e: Expectation{What: "x", Got: "new", Want: "new", KnownGap: "P-00 / W0.0", Current: "old"}, wantError: "looks fixed"},
		{name: "gap drifted", e: Expectation{What: "x", Got: "other", Want: "new", KnownGap: "P-00 / W0.0", Current: "old"}, wantError: "moved off"},
		{name: "gap that cannot report its fix", e: Expectation{What: "x", Got: "old", Want: "old", KnownGap: "P-00 / W0.0", Current: "old"}, wantFatal: "cannot fail"},
		// Numbers compare after a JSON round trip, so a golden's json.Number
		// and a claim's int are the same value.
		{name: "numbers compare canonically", e: Expectation{What: "x", Got: float64(443), Want: 443}, wantSilent: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			Expect(r, tc.e)
			switch {
			case tc.wantSilent:
				if len(r.errors)+len(r.fatals) != 0 {
					t.Errorf("want no verdict, got errors %q fatals %q", r.errors, r.fatals)
				}
			case tc.wantError != "":
				if len(r.errors) != 1 || !strings.Contains(r.errors[0], tc.wantError) {
					t.Errorf("want one error containing %q, got %q", tc.wantError, r.errors)
				}
			case tc.wantFatal != "":
				if len(r.fatals) != 1 || !strings.Contains(r.fatals[0], tc.wantFatal) {
					t.Errorf("want one fatal containing %q, got %q", tc.wantFatal, r.fatals)
				}
			}
		})
	}
}
