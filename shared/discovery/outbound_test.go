package discovery

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// TestGuardedHTTPClient_NeverUsesAnEnvironmentProxy (review M1): a proxy from
// HTTP_PROXY/HTTPS_PROXY would move the connect target out of the guard's
// sight — the guard would judge the proxy's address, and the proxy would fetch
// whatever the certificate named.
//
// Two checks, because Go caches the environment's proxy settings once per
// process: the transport must carry no Proxy func at all, and a request to a
// non-loopback name (loopback is never proxied, which would make the check
// vacuous) must not reach a recording proxy the guard would otherwise allow.
func TestGuardedHTTPClient_NeverUsesAnEnvironmentProxy(t *testing.T) {
	var hits int32
	ln, err := net.Listen("tcp", "127.0.0.3:0")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.3: %v", err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	proxyURL := "http://" + ln.Addr().String()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		t.Setenv(k, proxyURL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	proxyAddr := netip.MustParseAddr("127.0.0.3")
	client := GuardedHTTPClient(func(a netip.Addr) error {
		if a == proxyAddr {
			return nil // allowed ONLY so that a proxied request would be seen
		}
		return errors.New("refused by test guard")
	}, 2*time.Second)

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("the guarded transport has a Proxy func: an environment proxy would carry the fetch past the guard")
	}

	for _, url := range []string{"http://ocsp.example.invalid/", "https://ocsp.example.invalid/"} {
		resp, err := client.Get(url)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("GET %s succeeded; want a refusal or a resolution failure", url)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the environment proxy received %d request(s)", n)
	}
}

// TestGuardedHTTPClient_RefusesAndDoesNotRedirect covers the other two
// properties directly, independent of any prober.
func TestGuardedHTTPClient_RefusesAndDoesNotRedirect(t *testing.T) {
	client := GuardedHTTPClient(func(netip.Addr) error { return errors.New("no") }, time.Second)
	if _, err := client.Get("http://127.0.0.1:1/"); !errors.Is(err, ErrOutboundAddressRefused) {
		t.Fatalf("err = %v, want ErrOutboundAddressRefused", err)
	}
	for _, code := range []int{301, 302, 303, 307, 308} {
		if client.CheckRedirect(&http.Request{Response: &http.Response{StatusCode: code}}, nil) != http.ErrUseLastResponse {
			t.Errorf("a %d redirect would be followed", code)
		}
	}
}
