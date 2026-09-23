package devicetest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

func get(t *testing.T, url string) error {
	t.Helper()
	client := di.NewDeviceHTTPClient(false, 2*time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func requireGuardRefusal(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: request succeeded; the SSRF guard must refuse it", what)
	}
	if !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("%s: failed with %v, want an 'ssrf guard' refusal", what, err)
	}
}

// The seam opens exactly the listener it names, for exactly the test that
// named it. All three halves are asserted against the REAL guard: this package
// has no TestMain, so the production dialer is what is installed here.
func TestAllowListener_OpensOneListenerForOneTest(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	allowed := httptest.NewServer(http.HandlerFunc(ok))
	defer allowed.Close()
	other := httptest.NewServer(http.HandlerFunc(ok))
	defer other.Close()

	// Before: the guard refuses loopback, which is why the seam exists.
	requireGuardRefusal(t, get(t, allowed.URL), "before AllowListener")

	t.Run("while open", func(t *testing.T) {
		AllowListener(t, allowed.Listener.Addr().String())

		if err := get(t, allowed.URL); err != nil {
			t.Fatalf("the named listener was not reachable through the seam: %v", err)
		}
		// Narrowness: a second loopback port is NOT opened by the first.
		requireGuardRefusal(t, get(t, other.URL), "a loopback listener the test did not name")
		// And the addresses the guard exists for stay refused.
		requireGuardRefusal(t, get(t, "http://169.254.169.254/latest/meta-data/"), "cloud metadata")
	})

	// After: restored when the test that opened it ended.
	requireGuardRefusal(t, get(t, allowed.URL), "after the opening test ended")
}

// fatalRecorder captures Fatalf so the refusal of a bad address can be
// asserted without failing this test.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (f *fatalRecorder) Helper() {}
func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
}

func TestAllowListener_RefusesAnythingButALoopbackLiteral(t *testing.T) {
	for _, addr := range []string{
		"169.254.169.254:80", // metadata
		"10.0.0.5:443",       // a real appliance address: the guard already permits it, the seam must not widen it
		"localhost:8080",     // a NAME: resolution is exactly what the guard exists to re-check
		"127.0.0.1",          // no port
	} {
		rec := &fatalRecorder{TB: t}
		AllowListener(rec, addr)
		if rec.msg == "" {
			t.Errorf("AllowListener(%q) accepted an address that is not a loopback IP literal with a port", addr)
		}
	}
}

// The guard is process-wide, so a parallel test holding the seam would widen it
// for every test running alongside. t.Setenv is what refuses that.
func TestAllowListener_RefusesParallelTests(t *testing.T) {
	t.Run("parallel", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("AllowListener ran inside a parallel test; it must refuse")
			}
		}()
		AllowListener(t, "127.0.0.1:1")
	})
}
