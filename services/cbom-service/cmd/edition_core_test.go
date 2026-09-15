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

import "testing"

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
