package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryEngineIsBuiltWithTheOutboundGuard — the OCSP SSRF ( W5.13b
// review, B1) comes back the moment this service builds a shared/discovery
// prober or unit engine without the platform's fetch guard: a scanned
// server's certificate could then point the platform at 169.254.169.254,
// loopback or an in-cluster Service. Since WP5 the only scan code here
// is the shared engine, built in one place (work_unit_engine.go newUnitEngine,
// with dispatchguard.PlatformFetchGuard); this keeps it that way.
// plan_execution_handler_integration_test.go proves the guard on a real scan.
func TestEveryEngineIsBuiltWithTheOutboundGuard(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		text := string(src)
		if strings.Contains(text, "shareddisc.NewProber(") {
			t.Errorf("%s builds a prober with shareddisc.NewProber — scan through the shared engine (newUnitEngine) so certificate-driven fetches stay guarded", f)
		}
		if f != "work_unit_engine.go" && strings.Contains(text, "shareddisc.NewUnitEngine(") {
			t.Errorf("%s builds a unit engine directly — use newUnitEngine, which passes the platform fetch guard", f)
		}
		for _, bare := range []string{"shareddisc.ValidateAndClassifyCertChain(", "shareddisc.CheckOCSPRevocation(", "shareddisc.ClassifyCertChainFromPEMs("} {
			if strings.Contains(text, bare) {
				t.Errorf("%s calls %s, which queries OCSP with an unguarded client", f, bare)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("scanned only %d source files — the glob is not looking where the engine is built", checked)
	}
	src, err := os.ReadFile("work_unit_engine.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "shareddisc.NewUnitEngine(pace, otProbes, dispatchguard.PlatformFetchGuard()") {
		t.Fatal("newUnitEngine no longer passes dispatchguard.PlatformFetchGuard() — the engine's OCSP fetches would be unguarded")
	}
}
