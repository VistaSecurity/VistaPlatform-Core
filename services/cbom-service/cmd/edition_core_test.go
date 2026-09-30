//go:build !ee

package main

// The CORE edition's shape, asserted rather than assumed.
//
// Nothing else in the repository observes `hooks` in a Core build. The zero
// value IS the Core edition — no signer, no attestation builder, no artifact
// formatter, and no comparison routes — and every one of those absences is a
// product decision that a stray `hooks = …` in a new file would silently
// reverse. `edition()` is the line an operator reads in the first log entry to
// know which binary is running, and it is derived from two of these fields, so
// it is the one thing that would look right while being wrong.
//
// Companion: edition_ee_test.go asserts the opposite for `-tags ee`. Both
// polarities, because a test that only ever sees one of them cannot tell a
// correctly-wired build from one where the tag does nothing.

import (
	"os"
	"strings"
	"testing"
)

func TestCoreBuildWiresNoEnterpriseHooks(t *testing.T) {
	if hooks.NewSigner != nil {
		t.Error("Core wired a signer; Core artifacts are unsigned by design")
	}
	if hooks.NewAttestationBuilder != nil {
		t.Error("Core wired an attestation builder; compliance attestation is the Enterprise evidence layer")
	}
	if hooks.NewArtifactFormatter != nil {
		t.Error("Core wired an artifact formatter; SPDX and PDF are the Enterprise reporting formats and " +
			"/download answers 402 for them")
	}
	if hooks.RegisterComparisonRoutes != nil {
		t.Error("Core wired the comparison routes; artifact comparison is Enterprise and the routes are " +
			"simply never mounted in Core")
	}
	if got := edition(); got != "core" {
		t.Errorf("edition() = %q, want %q — this is the first line of the service log and what an operator "+
			"reads to know which binary is running", got, "core")
	}
}

// A Core build must MOUNT the 402 stubs for comparison, not leave the paths
// unrouted. The hook being nil (asserted above) only says the Enterprise routes
// are absent; whether the refusal stands in for them is a line in main.go that
// nothing else observes — delete it and every other test stays green while an
// MCP agent gets a bare 404 and concludes the artifacts do not exist.
func TestCoreMountsComparisonUnavailableStubs(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	main := string(src)

	call := "cbom.RegisterUnavailableComparisonRoutes(api)"
	idx := strings.Index(main, call)
	if idx < 0 {
		t.Fatalf("main.go no longer calls %q — a Core build would answer a bare 404 on /cbom/compare "+
			"instead of 402 'not included in your subscription'", call)
	}
	// It has to be the ELSE of the hook check, or Enterprise would register
	// the same paths twice and gin would panic at start-up.
	before := main[:idx]
	hookCheck := strings.LastIndex(before, "if hooks.RegisterComparisonRoutes != nil {")
	elseAt := strings.LastIndex(before, "} else {")
	if hookCheck < 0 || elseAt < hookCheck {
		t.Errorf("%q must sit in the else branch of `if hooks.RegisterComparisonRoutes != nil`", call)
	}
}
