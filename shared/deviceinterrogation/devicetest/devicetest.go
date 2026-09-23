// Package devicetest lets a test OUTSIDE shared/deviceinterrogation drive a
// real collector against a fake appliance.
//
// Fake appliances are httptest servers, and httptest binds 127.0.0.1 — the one
// address the device dial guard refuses outright, because on the in-cluster
// platform agent loopback is OUR host, never the tenant's. A service's
// DB-integration test that interrogates such a server through the real
// registry therefore fails at login with an "ssrf guard" refusal and never
// reaches the code it exists to exercise.
//
// The obvious fixes are the bug: letting loopback through the guard, or
// giving the service a way to swap the dialer wholesale. This package does
// neither. [AllowListener] opens exactly ONE loopback host:port, for exactly
// one test, and every other address — other loopback ports, the metadata
// endpoint, link-local — still goes through the production guard. It refuses
// to run outside a test binary, so importing it from production code buys
// nothing.
package devicetest

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/internal/dialguard"
)

// seamEnv is set for the duration of an AllowListener. Nothing reads it; it is
// set through t.Setenv because t.Setenv PANICS in a parallel test, and the dial
// guard is process-wide state — a parallel test holding the seam open would
// widen it for every other test running at the same time.
const seamEnv = "VISTA_DEVICETEST_ALLOWED_LISTENER"

// AllowListener lets device HTTP clients built during t dial addr — the
// host:port of a loopback test listener, e.g. an httptest server's
// Listener.Addr().String() — without the SSRF guard. Every other address is
// still dialled through the production guard, and the guard is restored when
// t ends.
//
// addr must be a loopback IP literal with a port. Anything else fails the test:
// the seam exists to reach a fake appliance on this host, and a name or a
// routable address would turn it into a general bypass.
//
// The guard is read when a client is BUILT, so call this before the
// interrogation that builds one. It must not be used from a parallel test.
func AllowListener(t testing.TB, addr string) {
	t.Helper()
	if !testing.Testing() {
		// Not reachable through a real *testing.T, which only a test binary
		// constructs; stated anyway so the property does not rest on that.
		panic("devicetest.AllowListener called outside a test binary")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("devicetest.AllowListener(%q): want host:port: %v", addr, err)
		return
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("devicetest.AllowListener(%q): only a loopback IP literal may be opened; "+
			"the seam is for a fake appliance on this host, not a way past the guard", addr)
		return
	}
	t.Setenv(seamEnv, addr)

	saved := dialguard.Dial
	dialguard.Dial = func(timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
		guarded := saved(timeout)
		plain := (&net.Dialer{Timeout: timeout}).DialContext
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == addr {
				return plain(ctx, network, address)
			}
			return guarded(ctx, network, address)
		}
	}
	t.Cleanup(func() { dialguard.Dial = saved })
}
