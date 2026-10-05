package discovery

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingDial wraps a plain dialer and records every address it is asked to
// reach, so a test can prove that EVERY connection the SSH probe opens went
// through the caller's dialer — the property device interrogation's dial guard
// depends on.
type recordingDial struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.calls = append(r.calls, address)
	r.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (r *recordingDial) addresses() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// A server that answers the KEXINIT pass but never completes a key exchange:
// the probe makes the handshake connection and the KEXINIT connection, both
// through the injected dialer.
func TestProbeSSHEndpoint_EveryConnectionGoesThroughTheInjectedDialer(t *testing.T) {
	addr := modernServer().start(t)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	rec := &recordingDial{}
	res, err := NewProber(time.Second).ProbeSSHEndpoint(context.Background(), host, port, SSHEndpointOptions{Dial: rec.dial})
	if err != nil {
		t.Fatalf("ProbeSSHEndpoint: %v", err)
	}
	if got, _ := res.Metadata["ssh_kex_algorithm"].(string); got == "" {
		t.Errorf("the KEXINIT pass produced nothing, so it may not have run: %+v", res.Metadata)
	}
	calls := rec.addresses()
	if len(calls) != 2 {
		t.Fatalf("dialer saw %d connections %v, want 2 (handshake + KEXINIT)", len(calls), calls)
	}
	for _, c := range calls {
		if c != addr {
			t.Errorf("dialled %q, want %q", c, addr)
		}
	}
}

// The banner-only fallback is the third connection, the one that used to call
// net.DialTimeout directly. The fixture sends a version line and hangs up, the
// shape that sends the probe down the fallback path.
func TestProbeSSHEndpoint_BannerFallbackGoesThroughTheInjectedDialer(t *testing.T) {
	const version = "SSH-2.0-Appliance_1.0 firmware-7.2"
	host, port := serveRawBanner(t, version+"\r\n")

	rec := &recordingDial{}
	res, err := NewProber(3*time.Second).ProbeSSHEndpoint(context.Background(), host, port, SSHEndpointOptions{Dial: rec.dial})
	if err != nil {
		t.Fatalf("ProbeSSHEndpoint: %v", err)
	}
	if res.SSHBanner != version {
		t.Fatalf("SSHBanner = %q, want %q — the fallback did not run, so this test proves nothing", res.SSHBanner, version)
	}
	want := net.JoinHostPort(host, strconv.Itoa(port))
	calls := rec.addresses()
	if len(calls) != 3 {
		t.Fatalf("dialer saw %d connections %v, want 3 (handshake, KEXINIT, banner fallback)", len(calls), calls)
	}
	for _, c := range calls {
		if c != want {
			t.Errorf("dialled %q, want %q", c, want)
		}
	}
}

// A dialer that refuses (the guard's verdict on a forbidden address) means no
// connection of any kind reaches the target: the probe stops at the first dial
// and never falls back to a dial of its own.
func TestProbeSSHEndpoint_RefusingDialerMeansNoConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)

	var asked atomic.Int32
	refuse := func(context.Context, string, string) (net.Conn, error) {
		asked.Add(1)
		return nil, errors.New("ssrf guard: address refused")
	}
	_, err = NewProber(time.Second).ProbeSSHEndpoint(context.Background(), addr.IP.String(), addr.Port, SSHEndpointOptions{Dial: refuse})
	if err == nil || !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("err = %v, want the guard's refusal", err)
	}
	if asked.Load() != 1 {
		t.Errorf("dialer asked %d times, want exactly 1", asked.Load())
	}
	time.Sleep(100 * time.Millisecond) // let a stray connection show up
	if n := accepted.Load(); n != 0 {
		t.Errorf("target accepted %d connections despite the refusing dialer", n)
	}
}

// The behavioural tests above prove today's call sites; this is the cheap
// structural guard that no direct dial comes back to the SSH probe's files
// (the banner fallback had one for years). Only sshDial may touch net.Dialer.
func TestSSHProbeFilesDoNotDialDirectly(t *testing.T) {
	direct := regexp.MustCompile(`net\.(Dial|DialTimeout|DialTCP)\(|\(&net\.Dialer\{`)
	for _, f := range []string{"probe_ssh.go", "probe_ssh_kexinit.go"} {
		if loc := direct.FindString(readSourceForTest(t, f)); loc != "" {
			t.Errorf("%s dials directly with %q; take the connection from sshDial so the caller's dialer sees it", f, loc)
		}
	}
}
