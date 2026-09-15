package services

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// These tests drive the REAL SSHProber.ProbeSSH against loopback fixtures, so
// they pin the wiring — that the in-cluster prober's output is what
// shared/discovery produces — and not a helper in isolation. A bespoke
// in-cluster copy of the handshake passed every unit test it had while
// storing the raw banner, because nothing exercised what it actually wrote
// into the finding.

// sshBannerBound mirrors shared/discovery's (unexported) maxSSHBannerLen. It
// is the contract the in-cluster finding inherits, so a change to the shared
// bound should surface here rather than pass silently.
const sshBannerBound = 256

// serveRawSSHBanner listens on a loopback ephemeral port and, for every
// connection, writes payload, drains briefly, then closes. It speaks no SSH beyond those bytes: the version exchange succeeds
// or fails on them alone and kex never completes, which is how a probe lands
// on the shared banner-only fallback — the plain read the banner bound exists
// for. Draining before close sends FIN rather than RST, so the payload is not
// discarded from the peer's receive buffer.
func serveRawSSHBanner(t *testing.T, payload string) (host string, port int) {
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

// TestSSHProbeBannerIsRedactedAndBoundedThroughTheClusterProber mirrors
// shared/discovery's TestSSHBannerRedactsBeforeItTruncates, but through the
// in-cluster prober's real entry point: a banner carrying a PEM private key
// that straddles the length cut must reach the finding redacted and capped.
// Before the in-cluster prober delegated to shared/discovery, this stored the
// key material verbatim — the fix that bounded the shared prober never reached
// the copy.
//
// The BEGIN line ends inside the bound and the END line falls outside it, so a
// truncate-first ordering (or no redaction at all) ships a headless fragment.
func TestSSHProbeBannerIsRedactedAndBoundedThroughTheClusterProber(t *testing.T) {
	const key = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIBOgIBAAJBAKjMUSTNOTSHIPabcdefghijklmnopqrstuvwxyz0123456789\n" +
		"-----END RSA PRIVATE KEY-----"

	prefix := "SSH-2.0-OpenSSH_9.6 " + strings.Repeat("x", sshBannerBound-60)
	payload := prefix + " " + key + " trailing text"
	if begin := len(prefix) + len(" -----BEGIN RSA PRIVATE KEY-----"); begin >= sshBannerBound {
		t.Fatalf("the BEGIN line ends at %d, outside the bound %d: nothing straddles the cut", begin, sshBannerBound)
	}
	if len(payload) <= sshBannerBound {
		t.Fatalf("the payload (%d bytes) fits inside the bound %d, so no truncation happens at all", len(payload), sshBannerBound)
	}

	host, port := serveRawSSHBanner(t, payload)

	data, err := NewSSHProber(3*time.Second).ProbeSSH(host, port)
	if err != nil {
		t.Fatalf("ProbeSSH: %v", err)
	}
	got, ok := data["ssh_banner"].(string)
	if !ok {
		t.Fatalf("ssh_banner missing or not a string: %#v", data["ssh_banner"])
	}
	if len(got) > sshBannerBound {
		t.Errorf("finding kept %d bytes of banner, bound is %d", len(got), sshBannerBound)
	}
	for _, fragment := range []string{"PRIVATE KEY", "MIIBOgIBAAJBA"} {
		if strings.Contains(got, fragment) {
			t.Errorf("key material reached the finding: %q contains %q", got, fragment)
		}
	}
	if !strings.Contains(got, redact.Marker) {
		t.Errorf("no redaction marker, so a firing scrubber is unobservable: %q", got)
	}
	if !strings.HasPrefix(got, "SSH-2.0-OpenSSH_9.6") {
		t.Errorf("the identifying prefix was lost: %q", got)
	}
	// The neutral spelling shared/discovery also emits must agree — a reader
	// that falls back from ssh_banner to banner must not find the raw value.
	if alt, _ := data["banner"].(string); alt != got {
		t.Errorf("banner = %q, differs from ssh_banner = %q", alt, got)
	}
}

// TestSSHProbeBannerIsBoundedWithoutAPEMBlock is the ordinary case through the
// same entry point: a long appliance banner with no secret material is still
// capped, and no redaction marker appears when nothing needed redacting.
func TestSSHProbeBannerIsBoundedWithoutAPEMBlock(t *testing.T) {
	// One version line short enough for the exchange to accept, then far more
	// text than the bound — the shape of an appliance that follows its
	// identification string with a firmware/support blurb.
	payload := "SSH-2.0-Custom_Appliance_Firmware\n" + strings.Repeat("z", 500)
	host, port := serveRawSSHBanner(t, payload)

	data, err := NewSSHProber(3*time.Second).ProbeSSH(host, port)
	if err != nil {
		t.Fatalf("ProbeSSH: %v", err)
	}
	got, _ := data["ssh_banner"].(string)
	if len(got) > sshBannerBound {
		t.Errorf("finding kept %d bytes of banner, bound is %d", len(got), sshBannerBound)
	}
	if !strings.HasPrefix(got, "SSH-2.0-Custom_Appliance_Firmware") {
		t.Errorf("the identifying prefix was lost: %q", got)
	}
	if strings.Contains(got, redact.Marker) {
		t.Errorf("a redaction marker appeared with no secret material present: %q", got)
	}
	// A banner-only fallback delivered no host key, and the finding must not
	// manufacture one: the old copy wrote ssh_key_types = [""] here.
	for _, k := range []string{"ssh_host_key_type", "ssh_host_key_fingerprint", "ssh_key_types"} {
		if v, present := data[k]; present {
			t.Errorf("%s = %#v present on a banner-only result; want absent", k, v)
		}
	}
}

// serveLoopbackSSH runs a real SSH server (golang.org/x/crypto/ssh) on a
// loopback ephemeral port with a fresh ed25519 host key and a password
// callback that rejects everything, so a probe completes the kex — delivering
// the host key — and then fails at authentication exactly as it does against
// a production server. (x/crypto's server refuses to start with NO auth
// method configured unless NoClientAuth is set, which would instead let the
// probe's "none" attempt succeed.)
func serveLoopbackSSH(t *testing.T) (host string, port int, hostKey ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return nil, errors.New("probe fixture accepts no credentials")
		},
	}
	cfg.AddHostKey(signer)

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
				srv, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return // the probe's "none" auth is rejected: expected
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "probe only")
				}
				_ = srv.Close()
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, signer.PublicKey()
}

// TestSSHProbeCapturesHostKeyThroughTheSharedCore pins the main path after the
// delegation: against a real server the in-cluster finding still carries the
// negotiated host key type, its SHA256 fingerprint and the list form of the
// key type — under the key names inventory-service's SSH ingest and asset
// identity resolution read.
func TestSSHProbeCapturesHostKeyThroughTheSharedCore(t *testing.T) {
	host, port, hostKey := serveLoopbackSSH(t)

	data, err := NewSSHProber(5*time.Second).ProbeSSH(host, port)
	if err != nil {
		t.Fatalf("ProbeSSH: %v", err)
	}
	if got, _ := data["ssh_host_key_type"].(string); got != hostKey.Type() {
		t.Errorf("ssh_host_key_type = %q, want %q", got, hostKey.Type())
	}
	if got, _ := data["ssh_host_key_fingerprint"].(string); got != ssh.FingerprintSHA256(hostKey) {
		t.Errorf("ssh_host_key_fingerprint = %q, want %q", got, ssh.FingerprintSHA256(hostKey))
	}
	types, _ := data["ssh_key_types"].([]string)
	if len(types) != 1 || types[0] != hostKey.Type() {
		t.Errorf("ssh_key_types = %#v, want [%q]", data["ssh_key_types"], hostKey.Type())
	}
	if _, present := data["ssh_banner"]; !present {
		t.Error("ssh_banner must always be present on a probe result, even when empty")
	}
}
