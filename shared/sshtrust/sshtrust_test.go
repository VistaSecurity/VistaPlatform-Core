package sshtrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testServer is a real in-process SSH server. It exists so the assertions below
// can be about the WIRE — "did a password reach the far end?" — rather than
// about whether a function returned an error. A test that only checks the error
// would still pass if the handshake failed AFTER the credential was sent, which
// is precisely the property under test.
type testServer struct {
	addr     string
	listener net.Listener

	mu sync.Mutex
	// passwordsSeen records every password the server was offered. On a host-key
	// mismatch this MUST stay empty: x/crypto/ssh runs the host-key callback
	// during key exchange, before any auth method.
	passwordsSeen []string
}

func (s *testServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.passwordsSeen))
	copy(out, s.passwordsSeen)
	return out
}

func newHostKey(t *testing.T) ssh.Signer {
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

// startServer runs an SSH server on 127.0.0.1 with the given host key.
func startServer(t *testing.T, hostKey ssh.Signer) *testServer {
	t.Helper()

	srv := &testServer{}
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
	srv.listener = ln
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

// dial runs one authenticated connection under the given policy and reports
// whether it succeeded.
func dial(t *testing.T, addr string, p *Policy, password string) error {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "operator",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: p.Callback(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return err
	}
	_ = client.Close()
	return nil
}

func fingerprintOf(t *testing.T, signer ssh.Signer) string {
	t.Helper()
	return ssh.FingerprintSHA256(signer.PublicKey())
}

// --- polarity 1: first contact is enrolment and must keep working -----------

func TestPolicy_FirstContact_AcceptsAndCapturesFingerprint(t *testing.T) {
	key := newHostKey(t)
	srv := startServer(t, key)

	// KnownHostsPath points at a file that does not exist, so the default
	// ~/.ssh/known_hosts of whoever runs the suite cannot change the outcome.
	p := &Policy{Host: srv.addr, KnownHostsPath: filepath.Join(t.TempDir(), "absent")}
	if err := dial(t, srv.addr, p, "hunter2"); err != nil {
		t.Fatalf("first contact must succeed, got: %v", err)
	}

	if p.Verification != VerificationFirstUse {
		t.Errorf("verification = %q, want %q", p.Verification, VerificationFirstUse)
	}
	if got, want := p.Fingerprint, fingerprintOf(t, key); got != want {
		t.Errorf("captured fingerprint = %q, want %q", got, want)
	}
	if p.KeyType != key.PublicKey().Type() {
		t.Errorf("key type = %q, want %q", p.KeyType, key.PublicKey().Type())
	}
	if got := srv.seen(); len(got) != 1 || got[0] != "hunter2" {
		t.Errorf("server should have been offered the password on enrolment, saw %v", got)
	}
}

// --- polarity 2: the same key on reconnect is allowed ------------------------

func TestPolicy_SameKeyOnReconnect_Allowed(t *testing.T) {
	key := newHostKey(t)
	srv := startServer(t, key)

	p := &Policy{Host: srv.addr, Pinned: fingerprintOf(t, key)}
	if err := dial(t, srv.addr, p, "hunter2"); err != nil {
		t.Fatalf("matching pinned key must be allowed, got: %v", err)
	}
	if p.Verification != VerificationPinned {
		t.Errorf("verification = %q, want %q", p.Verification, VerificationPinned)
	}
	if got := srv.seen(); len(got) != 1 {
		t.Errorf("expected one authentication attempt, saw %v", got)
	}
}

// --- polarity 3: the changed key is refused AND no credential is sent -------

func TestPolicy_ChangedKeyOnReconnect_RefusesAndSendsNoCredential(t *testing.T) {
	oldKey := newHostKey(t)
	newKey := newHostKey(t)
	// The server now presents a DIFFERENT key from the one pinned — a replaced
	// device, a rotated key, or an on-path attacker; indistinguishable from
	// here, which is why it fails closed.
	srv := startServer(t, newKey)

	p := &Policy{Host: srv.addr, Pinned: fingerprintOf(t, oldKey)}
	err := dial(t, srv.addr, p, "hunter2")
	if err == nil {
		t.Fatal("a changed host key must fail the connection")
	}

	var mismatch *MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error must be a *MismatchError so the caller can raise a finding, got %T: %v", err, err)
	}
	if mismatch.Expected != fingerprintOf(t, oldKey) {
		t.Errorf("Expected = %q, want the pinned fingerprint %q", mismatch.Expected, fingerprintOf(t, oldKey))
	}
	if mismatch.Observed != fingerprintOf(t, newKey) {
		t.Errorf("Observed = %q, want the presented fingerprint %q", mismatch.Observed, fingerprintOf(t, newKey))
	}

	// THE assertion. Not "an error came back" — "the password never left this
	// process". Deleting the comparison in pinnedCallback turns this red.
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("credential was transmitted to a host whose key did not match: %v", got)
	}

	// The observation is still recorded on the failing path, so the finding can
	// name the key that turned up.
	if p.Fingerprint != fingerprintOf(t, newKey) {
		t.Errorf("observed fingerprint = %q, want %q", p.Fingerprint, fingerprintOf(t, newKey))
	}
}

// --- the pin outranks InsecureSkipVerify ------------------------------------

func TestPolicy_InsecureSkipVerifyDoesNotUnpin(t *testing.T) {
	oldKey := newHostKey(t)
	newKey := newHostKey(t)
	srv := startServer(t, newKey)

	// InsecureSkipVerify is the operator's opt-in for a self-signed TLS
	// management certificate. It must not silently unpin an SSH key we have
	// already seen, or the fix is one checkbox away from being inert.
	p := &Policy{Host: srv.addr, Pinned: fingerprintOf(t, oldKey), InsecureSkipVerify: true}
	if err := dial(t, srv.addr, p, "hunter2"); err == nil {
		t.Fatal("InsecureSkipVerify must not defeat a stored pin")
	}
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("credential transmitted despite pin mismatch: %v", got)
	}
	if p.Verification != VerificationPinned {
		t.Errorf("verification = %q, want %q", p.Verification, VerificationPinned)
	}
}

// With no pin, the opt-out still works — otherwise enrolment against gear an
// operator has deliberately marked insecure would break.
func TestPolicy_InsecureSkipVerifyWithNoPin_Accepts(t *testing.T) {
	key := newHostKey(t)
	srv := startServer(t, key)

	p := &Policy{Host: srv.addr, InsecureSkipVerify: true}
	if err := dial(t, srv.addr, p, "hunter2"); err != nil {
		t.Fatalf("opt-out with no pin must still connect, got: %v", err)
	}
	if p.Verification != VerificationSkipped {
		t.Errorf("verification = %q, want %q", p.Verification, VerificationSkipped)
	}
	if p.Fingerprint != fingerprintOf(t, key) {
		t.Errorf("the key must still be recorded as evidence even when trust is skipped")
	}
}

// --- known_hosts still verifies, and still records the observation ----------

func TestPolicy_KnownHosts_VerifiesAndObserves(t *testing.T) {
	key := newHostKey(t)
	srv := startServer(t, key)

	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	line := knownHostsLine(srv.addr, key.PublicKey())
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	p := &Policy{Host: srv.addr, KnownHostsPath: path}
	if err := dial(t, srv.addr, p, "hunter2"); err != nil {
		t.Fatalf("known_hosts match must be allowed, got: %v", err)
	}
	if p.Verification != VerificationKnownHosts {
		t.Errorf("verification = %q, want %q", p.Verification, VerificationKnownHosts)
	}
	if p.Fingerprint != fingerprintOf(t, key) {
		t.Errorf("known_hosts path must still record the observed fingerprint")
	}

	// And the negative polarity: a known_hosts file naming a DIFFERENT key
	// refuses, with no credential sent.
	other := newHostKey(t)
	badPath := filepath.Join(dir, "known_hosts_wrong")
	if err := os.WriteFile(badPath, []byte(knownHostsLine(srv.addr, other.PublicKey())), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	before := len(srv.seen())
	p2 := &Policy{Host: srv.addr, KnownHostsPath: badPath}
	if err := dial(t, srv.addr, p2, "hunter2"); err == nil {
		t.Fatal("a known_hosts mismatch must refuse")
	}
	if got := srv.seen(); len(got) != before {
		t.Fatalf("credential transmitted on a known_hosts mismatch: %v", got)
	}
}

func knownHostsLine(addr string, key ssh.PublicKey) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return "[" + host + "]:" + port + " " + string(ssh.MarshalAuthorizedKey(key))
}
