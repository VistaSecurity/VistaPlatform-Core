package hostinventory

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/sshtrust"
	"golang.org/x/crypto/ssh"
)

// The SSHRunner authenticates, so it is held to the pinned-host-key policy. As
// with the Cisco interrogator these tests exist to pin the WIRING: the policy
// has its own tests, and a runner that stopped passing the pin through would
// still pass those.

type hostKeyTestServer struct {
	addr string

	mu            sync.Mutex
	passwordsSeen []string
}

func (s *hostKeyTestServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.passwordsSeen))
	copy(out, s.passwordsSeen)
	return out
}

func newTestHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func startHostKeyTestServer(t *testing.T, hostKey ssh.Signer) *hostKeyTestServer {
	t.Helper()

	srv := &hostKeyTestServer{}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			srv.mu.Lock()
			srv.passwordsSeen = append(srv.passwordsSeen, string(password))
			srv.mu.Unlock()
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.addr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						_ = ch.Reject(ssh.Prohibited, "no channels in this test")
					}
				}()
				_ = sconn.Wait()
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func hostKeyTestConfig(t *testing.T, addr, pinned string) SSHConfig {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return SSHConfig{
		Host:                     host,
		Port:                     port,
		User:                     "operator",
		Password:                 "hunter2",
		PinnedHostKeyFingerprint: pinned,
		// An absent path, so the machine's own ~/.ssh/known_hosts cannot decide
		// the outcome of this test.
		KnownHostsPath: filepath.Join(t.TempDir(), "absent"),
		Timeout:        5 * time.Second,
	}
}

func TestSSHRunner_FirstContact_ConnectsAndCapturesHostKey(t *testing.T) {
	key := newTestHostKey(t)
	srv := startHostKeyTestServer(t, key)

	r, err := NewSSHRunner(hostKeyTestConfig(t, srv.addr, ""))
	if err != nil {
		t.Fatalf("first contact must succeed, got: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got, want := r.HostKeyFingerprint, ssh.FingerprintSHA256(key.PublicKey()); got != want {
		t.Errorf("HostKeyFingerprint = %q, want %q", got, want)
	}
	if r.HostKeyVerified != sshtrust.VerificationFirstUse {
		t.Errorf("HostKeyVerified = %q, want %q", r.HostKeyVerified, sshtrust.VerificationFirstUse)
	}
}

func TestSSHRunner_SameKeyOnReconnect_Allowed(t *testing.T) {
	key := newTestHostKey(t)
	srv := startHostKeyTestServer(t, key)

	r, err := NewSSHRunner(hostKeyTestConfig(t, srv.addr, ssh.FingerprintSHA256(key.PublicKey())))
	if err != nil {
		t.Fatalf("matching pinned key must be allowed, got: %v", err)
	}
	defer func() { _ = r.Close() }()

	if r.HostKeyVerified != sshtrust.VerificationPinned {
		t.Errorf("HostKeyVerified = %q, want %q", r.HostKeyVerified, sshtrust.VerificationPinned)
	}
}

func TestSSHRunner_ChangedKey_RefusesAndSendsNoCredential(t *testing.T) {
	pinnedKey := newTestHostKey(t)
	presentedKey := newTestHostKey(t)
	srv := startHostKeyTestServer(t, presentedKey)

	_, err := NewSSHRunner(hostKeyTestConfig(t, srv.addr, ssh.FingerprintSHA256(pinnedKey.PublicKey())))
	if err == nil {
		t.Fatal("a changed host key must fail the dial")
	}
	var mismatch *sshtrust.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error must unwrap to *sshtrust.MismatchError, got %T: %v", err, err)
	}
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("credentials were transmitted to a host presenting an unrecognised key: %v", got)
	}
}
