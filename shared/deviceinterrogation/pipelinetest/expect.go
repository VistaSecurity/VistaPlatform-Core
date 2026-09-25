package pipelinetest

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Expectation is one claim a hop test makes about what the pipeline produced.
//
// Want is always the CORRECT behaviour — what the spec says a tenant should
// see. When today's code does not do that yet, KnownGap names the finding and
// the slice that will fix it ("P-04 / W1.2"), and Current pins what the code
// does TODAY. The assertion then holds the current behaviour exactly, so it:
//
//   - fails if the behaviour changes in any way that is not the fix (a
//     regression hiding behind a known gap), and
//   - fails when the fix lands, telling whoever landed it to delete Current
//     and KnownGap and turn this into a hard assertion.
//
// That second failure is the point. A known gap that quietly starts passing
// is a check that can no longer fail, and the corpus test in
// shared/deviceinterrogation/real_corpus_test.go treats its gaps the same way.
type Expectation struct {
	// What is a short sentence naming the claim, e.g. "the SSH row's version".
	What string
	// Got is what the pipeline produced.
	Got any
	// Want is the correct behaviour.
	Want any
	// KnownGap is "<finding id> / <slice id>" when today's code is still wrong.
	KnownGap string
	// Current is today's (wrong) behaviour; required with KnownGap.
	Current any
}

// Expect asserts every expectation, reporting each failure separately so one
// run lists every claim that moved.
func Expect(t testing.TB, expectations ...Expectation) {
	t.Helper()
	for _, e := range expectations {
		expectOne(t, e)
	}
}

func expectOne(t testing.TB, e Expectation) {
	t.Helper()
	if e.KnownGap == "" {
		if !Equal(t, e.Got, e.Want) {
			t.Errorf("%s:\n   got  %s\n   want %s", e.What, render(e.Got), render(e.Want))
		}
		return
	}
	// A gap whose correct and current behaviour are the same thing asserts
	// nothing about the gap: it could never report the fix.
	if Equal(t, e.Want, e.Current) {
		t.Fatalf("%s: knownGap %q pins Current == Want (%s); a gap that cannot report its fix is a check that cannot fail",
			e.What, e.KnownGap, render(e.Want))
	}
	switch {
	case Equal(t, e.Got, e.Current):
		// Still the known, wrong behaviour. Nothing to report.
	case Equal(t, e.Got, e.Want):
		t.Errorf("%s: now matches the CORRECT behaviour — knownGap %q looks fixed. "+
			"Delete KnownGap and Current so this becomes a hard assertion.\n   got %s",
			e.What, e.KnownGap, render(e.Got))
	default:
		t.Errorf("%s: moved off the pinned behaviour of knownGap %q without reaching the correct one.\n"+
			"   got     %s\n   current %s\n   want    %s\n"+
			"If this is progress on the gap, update Current; if not, it is a regression.",
			e.What, e.KnownGap, render(e.Got), render(e.Current), render(e.Want))
	}
}

func render(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(raw)
}

// GapIDs lists the known gaps a set of expectations still carries, so a hop
// test can log what it is holding open and the PR body can be generated from
// the same table the test runs.
func GapIDs(expectations []Expectation) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range expectations {
		if e.KnownGap != "" && !seen[e.KnownGap] {
			seen[e.KnownGap] = true
			out = append(out, e.KnownGap)
		}
	}
	return out
}
