package network

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The SSRF dialer must refuse internal targets at connect time. These
// drive the real dialer/transport against loopback, which isPrivateIP blocks.

func TestSafeDialTimeout_BlocksLoopback(t *testing.T) {
	// Stand up a real listener on loopback so the address resolves and would
	// otherwise connect; the guard must refuse it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	_, err = SafeDialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err == nil {
		t.Fatal("SafeDialTimeout connected to loopback; want SSRF refusal")
	}
	if !strings.Contains(err.Error(), "internal address") {
		t.Errorf("error = %v, want it to mention the internal-address refusal", err)
	}
}

func TestSafeDialTimeout_AllowsPublicShapedHost(t *testing.T) {
	// 8.8.8.8:0 won't actually connect, but the guard must NOT be the thing
	// that rejects it — a public IP passes the Control hook, then the dial
	// fails for an ordinary network reason (refused/timeout), not an SSRF error.
	_, err := SafeDialTimeout("tcp", "8.8.8.8:9", 1*time.Second)
	if err != nil && strings.Contains(err.Error(), "internal address") {
		t.Fatalf("public IP wrongly refused by SSRF guard: %v", err)
	}
}

func TestValidateDialAddr(t *testing.T) {
	bad := []string{
		"127.0.0.1:22",
		"169.254.169.254:80", // cloud metadata
		"10.1.2.3:443",
		"192.168.1.1:22",
		"[::1]:22",
	}
	for _, a := range bad {
		if err := ValidateDialAddr(a); err == nil {
			t.Errorf("ValidateDialAddr(%q) = nil, want refusal", a)
		}
	}
	if err := ValidateDialAddr("8.8.8.8:443"); err != nil {
		t.Errorf("ValidateDialAddr(public) = %v, want nil", err)
	}
	if err := ValidateDialAddr("not-an-addr"); err == nil {
		t.Error("ValidateDialAddr(garbage) = nil, want error")
	}
}

func TestSafeHTTPClient_BlocksLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// srv.URL is http://127.0.0.1:<port> — a real, reachable server. The
	// SSRF-guarded client must refuse it; a plain client would 200.
	_, err := SafeHTTPClient(2 * time.Second).Get(srv.URL)
	if err == nil {
		t.Fatal("SafeHTTPClient reached a loopback server; want SSRF refusal")
	}
	if !strings.Contains(err.Error(), "internal address") {
		t.Errorf("error = %v, want internal-address refusal", err)
	}
}
