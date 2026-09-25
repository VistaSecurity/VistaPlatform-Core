package services

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// This service classifies certificates a device or a cloud API reported, and
// the OCSP responder URL is in those certificates. It runs in the cluster, so
// the query must go through the guarded client ( W5.13b review, B1).

func TestCertificateClassificationUsesTheGuardedOCSPClient(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	uses := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(f)
		s := string(src)
		for _, bare := range []string{"discovery.ClassifyCertChainFromPEMs(", "discovery.ValidateAndClassifyCertChain(", "discovery.CheckOCSPRevocation("} {
			if strings.Contains(s, bare) {
				t.Errorf("%s calls %s, which queries OCSP with an unguarded client", f, bare)
			}
		}
		uses += strings.Count(s, "platformOCSPClient()")
	}
	if uses < 2 {
		t.Fatalf("platformOCSPClient() is used %d time(s); the result processor and cloud discovery both classify chains", uses)
	}
}

func TestPlatformOCSPClientRefusesInternalAddresses(t *testing.T) {
	for _, url := range []string{"http://127.0.0.1:1/", "http://169.254.169.254/latest/meta-data/", "http://10.43.0.1/", "http://[::1]:1/"} {
		resp, err := platformOCSPClient().Post(url, "application/ocsp-request", strings.NewReader("x"))
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, discovery.ErrOutboundAddressRefused) {
			t.Errorf("POST %s: err=%v, want ErrOutboundAddressRefused", url, err)
		}
	}
	if platformOCSPClient().CheckRedirect == nil || platformOCSPClient().CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("the OCSP client follows redirects")
	}
}
