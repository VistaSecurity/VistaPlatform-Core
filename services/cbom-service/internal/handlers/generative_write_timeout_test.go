package handlers

// This service's API server can reach one generative HTTP route: the
// narrator inside /cbom/compare (services/cbom-service/ee/diff), registered
// from cmd/main.go behind an edition hook. Its own per-call timeout
// (defaultNarrateTimeout, ee/diff/narrator_llm.go) is 20s — the shortest of
// any seam on the platform, but still well past the 15s WriteTimeout this
// server used to hard-code.
//
// seams.GenerativeWriteTimeout (shared/ai/seams/wire.go) exists so this
// server, inventory-service's and compliance-engine's all read the SAME
// Core-visible ceiling rather than three independently hard-coded literals
// that could drift out of step with each other or with any one seam's own
// timeout. It is sized around the platform's slowest configured seam
// (compliance-engine's author, a single 90s call), which is comfortably
// above this service's own 20s narrator.
//
// Before that constant existed, a comparison whose narration took anywhere
// near 20s risked losing its response entirely: a gin handler runs to
// completion regardless of whether the server is still listening, so past
// WriteTimeout the write fails and the client sees a dropped connection with
// no body — full model cost, no readable answer — instead of the narrated
// (or rule-fallback) comparison the handler produced.

import (
	"os"
	"path/filepath"
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
//     services' servers, or fall back under the narrator's own timeout.
//  2. The plaintext /health server's WriteTimeout is untouched by that
//     change: it answers a static body, never calls a seam, and has no
//     reason to wait as long as the slowest generative route (on ANY of the
//     three services) might.
//
// Mutation-proven: reverting either apiServer assignment to a numeric
// literal, or switching the health server onto the shared constant, fails
// this.
func TestAPIServerWriteTimeoutReadsTheSharedGenerativeConstant(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	main := string(src)

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
