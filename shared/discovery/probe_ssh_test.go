package discovery

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// readSourceForTest reads a file in THIS package's own directory as text, for
// a wiring test that checks the real call site rather than a helper's
// behaviour in isolation.
func readSourceForTest(t *testing.T, filename string) string {
	t.Helper()
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	return string(b)
}

func TestSSHProbeShouldFallbackToBanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		err             error
		hasSSHConn      bool
		hostKeyCaptured bool
		want            bool
	}{
		{name: "no error", err: nil, hasSSHConn: false, want: false},
		{
			name:       "handshake failed due to algorithm mismatch",
			err:        errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"),
			hasSSHConn: false,
			want:       true,
		},
		{
			name:       "auth failure is expected",
			err:        errors.New("ssh: handshake failed: unable to authenticate, attempted methods [none], no supported methods remain"),
			hasSSHConn: false,
			want:       false,
		},
		{
			name:       "auth failure alternate message is expected",
			err:        errors.New("ssh: handshake failed: no supported methods remain"),
			hasSSHConn: false,
			want:       false,
		},
		{
			name:       "connection already established",
			err:        errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"),
			hasSSHConn: true,
			want:       false,
		},
		{
			name:       "non handshake error does not fallback",
			err:        errors.New("unexpected EOF"),
			hasSSHConn: false,
			want:       false,
		},
		{
			// The kex completed (the host key callback ran) and THEN the
			// handshake died for a non-auth reason. A banner-only re-dial would
			// discard the host key type and fingerprint already in hand for a
			// version string, so the probe keeps what it measured instead — the
			// in-cluster prober always gated its fallback on "no host key yet",
			// and delegating it to this package must not change that.
			name:            "kex completed then failed without auth keeps the host key",
			err:             errors.New("ssh: handshake failed: EOF"),
			hasSSHConn:      false,
			hostKeyCaptured: true,
			want:            false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sshprobeShouldFallbackToBanner(tt.err, tt.hasSSHConn, tt.hostKeyCaptured); got != tt.want {
				t.Fatalf("sshprobeShouldFallbackToBanner() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSSHBannerRedactsBeforeItTruncates mirrors
// shared/hostobs.TestBoundTextRedactsBeforeItTruncates: boundSSHBanner must
// redact an embedded PEM block BEFORE truncating, not after. Truncating
// first can cut a PEM block before its END line, which redact.TextPEM's
// regex requires to match — and the fragment then ships as the device's
// banner, unredacted.
//
// The two orderings agree on every input except one that straddles the cut,
// which is why a banner short enough to fit inside maxSSHBannerLen would not
// catch a swapped ordering. An SSH server operator controls their own
// identification string, and some appliances embed a firmware/support banner
// well past 256 bytes in it, so this is the ordinary case for a banner this
// long, not a contrived one.
func TestSSHBannerRedactsBeforeItTruncates(t *testing.T) {
	const key = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIBOgIBAAJBAKjMUSTNOTSHIPabcdefghijklmnopqrstuvwxyz0123456789\n" +
		"-----END RSA PRIVATE KEY-----"

	// The key starts just inside the bound and its END line falls well
	// outside it, so truncate-first would keep a headless fragment.
	prefix := "SSH-2.0-OpenSSH_9.6 " + strings.Repeat("x", maxSSHBannerLen-60)
	in := prefix + " " + key + " trailing text"
	if begin := len(prefix) + len(" -----BEGIN RSA PRIVATE KEY-----"); begin >= maxSSHBannerLen {
		t.Fatalf("the BEGIN line ends at %d, outside the bound %d: nothing straddles the cut", begin, maxSSHBannerLen)
	}
	if len(in) <= maxSSHBannerLen {
		t.Fatalf("the input (%d bytes) fits inside the bound %d, so no truncation happens at all", len(in), maxSSHBannerLen)
	}

	got := boundSSHBanner(in)
	if len(got) > maxSSHBannerLen {
		t.Errorf("result kept %d bytes, bound is %d", len(got), maxSSHBannerLen)
	}
	for _, fragment := range []string{"PRIVATE KEY", "MIIBOgIBAAJBA"} {
		if strings.Contains(got, fragment) {
			t.Errorf("key material survived the bound: %q contains %q", got, fragment)
		}
	}
	if !strings.Contains(got, redact.Marker) {
		t.Errorf("no redaction marker, so a firing scrubber is unobservable: %q", got)
	}
	if !strings.HasPrefix(got, "SSH-2.0-OpenSSH_9.6") {
		t.Errorf("the identifying prefix was lost: %q", got)
	}

	// Inverse polarity: a PUBLIC key block is posture, not secret material,
	// and a scrubber that ate it would be the same bug pointed the other way.
	pub := "SSH-2.0-dropbear " + strings.Repeat("y", 20) +
		" -----BEGIN PUBLIC KEY-----\nMIIBpublicKeepMe\n-----END PUBLIC KEY-----"
	if kept := boundSSHBanner(pub); !strings.Contains(kept, "MIIBpublicKeepMe") {
		t.Errorf("a public key block was scrubbed: %q", kept)
	}
}

// TestSSHBannerIsBoundedWithoutAPEMBlock is the ordinary case: no secret
// material at all, just a long banner that must still be capped.
func TestSSHBannerIsBoundedWithoutAPEMBlock(t *testing.T) {
	long := "SSH-2.0-Custom_Appliance_Firmware " + strings.Repeat("z", 500)
	got := boundSSHBanner(long)
	if len(got) > maxSSHBannerLen {
		t.Errorf("result kept %d bytes, bound is %d", len(got), maxSSHBannerLen)
	}
	if strings.Contains(got, redact.Marker) {
		t.Errorf("a redaction marker appeared with no secret material present: %q", got)
	}
}

// TestSSHBannerCapturedByProbeAndFallbackAreBothBounded pins the WIRING, not
// just the helper: both places shared/discovery captures a raw SSH banner
// (the full handshake path in probeSSH and the plain-read fallback in
// sshprobeBannerOnly) must route through boundSSHBanner before it reaches
// ProbeResult.SSHBanner or Metadata["banner"]/Metadata["ssh_banner"] — those
// two Metadata keys are assigned FROM the (already bounded) SSHBanner/
// bannerStr value, so fixing the source fixes both.
//
// Mutation-proven: reverting either call site back to a bare
// strings.TrimSpace(...) (no redact, no length cap) fails this.
func TestSSHBannerCapturedByProbeAndFallbackAreBothBounded(t *testing.T) {
	src := readSourceForTest(t, "probe_ssh.go")

	if !strings.Contains(src, "result.SSHBanner = boundSSHBanner(string(sshConn.ServerVersion()))") {
		t.Error("the full-handshake path no longer routes the banner through boundSSHBanner")
	}
	// The fallback reads the identification LINE (sshReadIdentification), not
	// a raw blob — a plain Read used to return the version string with the
	// server's SSH_MSG_KEXINIT packet stapled to it — but the bounding
	// requirement is unchanged: whatever it read still goes through
	// boundSSHBanner.
	if !strings.Contains(src, "bannerStr := boundSSHBanner(raw)") {
		t.Error("the banner-only fallback no longer routes the banner through boundSSHBanner")
	}
}

// serveRawBanner listens on a loopback ephemeral port and, for every
// connection, writes payload, drains briefly, then closes. It speaks no SSH beyond the bytes it is given, so a probe against it
// gets through the version exchange on those bytes alone and dies in kex —
// which is exactly how a probe ends up on the banner-only fallback.
//
// Draining before close matters: closing with the peer's unread version line
// still in our receive buffer would send RST rather than FIN, and RST can
// discard payload the peer has not read yet.
func serveRawBanner(t *testing.T, payload string) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(payload))
				// Drain what the peer has sent (its version line, a KEXINIT)
				// so close sends FIN rather than RST, then hang up. A probe
				// on the handshake path is blocked waiting for a KEXINIT that
				// never comes, so the drain is bounded rather than waiting
				// for the peer to hang up first.
				_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// TestSSHProbeFallbackReadsTheBannerOnAFreshConnection is the regression test
// for a fallback that could never succeed. ssh.NewClientConn consumes the
// version line during the exchange and closes the net.Conn on every handshake
// error, so a banner-only read on THAT connection always failed with "use of
// closed network connection" and the whole probe returned an error — a device
// that announced itself perfectly well was recorded as an SSH probe failure.
// The fallback must dial afresh.
//
// The fixture sends a well-formed version line and then hangs up, so the
// exchange succeeds and kex fails (EOF / reset, not an auth error): the one
// shape the fallback exists for.
func TestSSHProbeFallbackReadsTheBannerOnAFreshConnection(t *testing.T) {
	const version = "SSH-2.0-Appliance_1.0 firmware-7.2"
	host, port := serveRawBanner(t, version+"\r\n")

	res, err := NewProber(3*time.Second).Probe(host, host, "SSH", port)
	if err != nil {
		t.Fatalf("Probe: %v — the banner-only fallback must read from a fresh connection, not the one NewClientConn closed", err)
	}
	if res.SSHBanner != version {
		t.Errorf("SSHBanner = %q, want %q", res.SSHBanner, version)
	}
	if got, _ := res.Metadata["ssh_banner"].(string); got != version {
		t.Errorf("Metadata[ssh_banner] = %q, want %q", got, version)
	}
	if res.SSHHostKeyType != "" || len(res.SSHKeyTypes) != 0 {
		t.Errorf("no kex happened, so no host key can have been captured: type=%q types=%v", res.SSHHostKeyType, res.SSHKeyTypes)
	}
}

// TestSSHProbeFallbackStopsAtTheIdentificationLine is the regression test for
// a banner that carried a binary packet in it.
//
// sshprobeBannerOnly used to do a plain 1024-byte Read and keep whatever came
// back. An SSH server sends its SSH_MSG_KEXINIT immediately behind the
// identification string, normally in the same TCP segment, so that read
// returned the version line with a KEXINIT packet stapled to it — algorithm
// name-lists, a 16-byte cookie and random padding — and the whole lot was
// truncated to 256 bytes and stored as the device's banner. It also made
// cryptoparse.SSHProtocolVersionCode's job harder for no reason and put
// unprintable bytes into a field the UI shows.
//
// RFC 4253 §4.2 terminates the identification string with CR LF. Stopping
// there is the fix.
func TestSSHProbeFallbackStopsAtTheIdentificationLine(t *testing.T) {
	const version = "SSH-2.0-Appliance_1.0 firmware-7.2"
	// A KEXINIT-shaped packet right behind the version line, exactly as a
	// real sshd sends it.
	trailing := string(sshWrapPacket(sshBuildKexInitPayload()))
	host, port := serveRawBanner(t, version+"\r\n"+trailing)

	res, err := sshprobeBannerOnly(NewProber(3*time.Second), net.JoinHostPort(host, strconv.Itoa(port)), port)
	if err != nil {
		t.Fatalf("sshprobeBannerOnly: %v", err)
	}
	if res.SSHBanner != version {
		t.Errorf("SSHBanner = %q, want exactly %q — the read must stop at the line terminator", res.SSHBanner, version)
	}
	if strings.ContainsAny(res.SSHBanner, "\x00\x01\x14") {
		t.Errorf("binary packet bytes reached the banner: %q", res.SSHBanner)
	}
}
