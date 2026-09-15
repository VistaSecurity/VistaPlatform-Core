package handlers

// This service mounts two generative HTTP routes on its API server: the
// remediator's /findings/:id/remediation/draft (this package) and the
// author's /custom-policies/draft-controls (services/compliance-engine/ee/author,
// registered from cmd/main.go). The author's single provider call is the
// slowest configured anywhere on the platform — 90s, ee/author's
// defaultDraftTimeout — which is exactly what seams.GenerativeWriteTimeout is
// sized around (see that constant's doc comment in shared/ai/seams/wire.go).
//
// Before that constant existed, this server's WriteTimeout was a hard-coded
// 15 * time.Second, well under either seam's own per-call timeout. A gin
// handler runs to completion regardless of whether the server is still
// listening, so a draft that took anywhere near its seam's own timeout to
// produce (or to fail over to a rule-based answer) still lost the response:
// past WriteTimeout the write fails and the client sees a dropped connection
// with no body, at full model cost, instead of the answer or the honest
// error the handler produced.

import (
	"strings"
	"testing"
)

// TestAPIServerWriteTimeoutReadsTheSharedGenerativeConstant reads the REAL
// main.go source — constructing the real http.Server isn't practical from a
// test, it needs live certs and a live DB — and checks two things at once:
//
//  1. The API server, in both the mTLS branch and the plaintext fallback,
//     sets WriteTimeout from seams.GenerativeWriteTimeout rather than a
//     hard-coded literal that could silently drift from the other two
//     services' servers, or fall back under either seam's own timeout.
//  2. The plaintext /health server's WriteTimeout is untouched by that
//     change: it answers a static body, never calls a seam, and has no
//     reason to wait as long as the slowest generative route might.
//
// Mutation-proven: reverting either apiServer assignment to a numeric
// literal, or switching the health server onto the shared constant, fails
// this.
func TestAPIServerWriteTimeoutReadsTheSharedGenerativeConstant(t *testing.T) {
	main := readSource(t, "../../cmd/main.go")

	apiCount := strings.Count(main, "apiServer.WriteTimeout = seams.GenerativeWriteTimeout") +
		strings.Count(main, "WriteTimeout:      seams.GenerativeWriteTimeout,")
	if apiCount != 2 {
		t.Errorf("expected exactly 2 apiServer WriteTimeout assignments wired to "+
			"seams.GenerativeWriteTimeout (the mTLS branch and the plaintext fallback), found %d",
			apiCount)
	}

	healthIdx := strings.Index(main, "healthServer := &http.Server{")
	if healthIdx < 0 {
		t.Fatal("could not find the healthServer struct literal in main.go — this guard cannot run")
	}
	closeIdx := strings.Index(main[healthIdx:], "\n\t}")
	if closeIdx < 0 {
		t.Fatal("could not find the end of the healthServer struct literal in main.go")
	}
	healthBlock := main[healthIdx : healthIdx+closeIdx]

	if !strings.Contains(healthBlock, "WriteTimeout:      15 * time.Second,") {
		t.Errorf("healthServer no longer declares a plain 15s WriteTimeout literal — it should never "+
			"read seams.GenerativeWriteTimeout, which exists for generative routes it never serves:\n%s",
			healthBlock)
	}
	if strings.Contains(healthBlock, "GenerativeWriteTimeout") {
		t.Errorf("healthServer's block references GenerativeWriteTimeout — the plaintext health "+
			"server must keep its own short, independent timeout:\n%s", healthBlock)
	}
}
