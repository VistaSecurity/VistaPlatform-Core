package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryProberIsBuiltWithTheOutboundGuard — the OCSP SSRF ( W5.13b
// review, B1) came back the moment one prober is built with a bare
// shareddisc.NewProber. The TLS test drives NewTLSProber; this keeps the SSH
// and OT probers — and any prober added later — on platformProber too.
func TestEveryProberIsBuiltWithTheOutboundGuard(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "platform_prober.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if strings.Contains(string(src), "shareddisc.NewProber(") {
			t.Errorf("%s builds a prober with shareddisc.NewProber — use platformProber so certificate-driven fetches stay guarded", f)
		}
		for _, bare := range []string{"shareddisc.ValidateAndClassifyCertChain(", "shareddisc.CheckOCSPRevocation(", "shareddisc.ClassifyCertChainFromPEMs("} {
			if strings.Contains(string(src), bare) {
				t.Errorf("%s calls %s, which queries OCSP with an unguarded client", f, bare)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("scanned only %d source files — the glob is not looking where the probers are", checked)
	}
}
