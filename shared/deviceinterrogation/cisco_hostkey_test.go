package deviceinterrogation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/sshtrust"
	"golang.org/x/crypto/ssh"
)

// These tests drive the REAL CiscoInterrogator against a real in-process SSH
// server. The unit tests in shared/sshtrust pin the policy; these pin the
// WIRING — delete the `Pinned:` line in newCiscoSSHClient and the policy still
// passes its own tests while the interrogator hands the password to anything
// that answers. That is the failure shape this repo keeps rediscovering, so the
// assertion here is about the server's side of the wire.

type ciscoTestServer struct {
	addr string

	mu            sync.Mutex
	passwordsSeen []string
}

func (s *ciscoTestServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.passwordsSeen))
	copy(out, s.passwordsSeen)
	return out
}

func ciscoNewHostKey(t *testing.T) ssh.Signer {
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

// startCiscoTestServer accepts a session channel and answers every exec request
// with empty output, which is enough for the interrogator to complete.
func startCiscoTestServer(t *testing.T, hostKey ssh.Signer) *ciscoTestServer {
	t.Helper()

	srv := &ciscoTestServer{}
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
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					ch, chReqs, acceptErr := newCh.Accept()
					if acceptErr != nil {
						continue
					}
					go func() {
						for req := range chReqs {
							if req.WantReply {
								_ = req.Reply(req.Type == "exec", nil)
							}
							if req.Type == "exec" {
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								_ = ch.Close()
							}
						}
					}()
				}
				_ = sconn.Wait()
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

// ciscoDeviceFor also points HOME at an empty directory, so the known_hosts
// tier cannot fire from whatever the machine running the suite happens to have
// in ~/.ssh. Without this the first-contact case passes or fails depending on
// the developer's own laptop, which is not a test.
func ciscoDeviceFor(t *testing.T, addr string, pinned string) DeviceInfo {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return DeviceInfo{
		DeviceType:            "cisco",
		IPAddress:             host,
		Port:                  port,
		SSHHostKeyFingerprint: pinned,
	}
}

// First contact: no pin, so the interrogation proceeds and reports the key it
// was shown. This is the enrolment case and must keep working — a fix that
// breaks it would simply be turned off.
func TestCiscoInterrogator_FirstContact_ConnectsAndReportsHostKey(t *testing.T) {
	key := ciscoNewHostKey(t)
	srv := startCiscoTestServer(t, key)

	interrogator := &CiscoInterrogator{}
	result, err := interrogator.Interrogate(context.Background(),
		ciscoDeviceFor(t, srv.addr, ""),
		Credentials{Username: "admin", Password: "hunter2"})
	if err != nil {
		t.Fatalf("first contact must succeed, got: %v", err)
	}

	want := ssh.FingerprintSHA256(key.PublicKey())
	var got string
	var verification string
	for i := range result.Assets {
		if info := result.Assets[i].SSHInfo; info != nil && info.HostKeyFingerprint != "" {
			got = info.HostKeyFingerprint
			if v, ok := result.Assets[i].Metadata["ssh_host_key_verification"].(string); ok {
				verification = v
			}
		}
	}
	if got != want {
		t.Fatalf("reported host key fingerprint = %q, want %q — the platform pins this value, so an empty one means nothing gets pinned", got, want)
	}
	if verification != sshtrust.VerificationFirstUse {
		t.Errorf("verification = %q, want %q", verification, sshtrust.VerificationFirstUse)
	}
	if len(srv.seen()) != 1 {
		t.Errorf("expected one authentication on enrolment, saw %v", srv.seen())
	}
}

// Same key on the next contact: allowed, and reported as pinned rather than as
// another first use.
func TestCiscoInterrogator_SameKeyOnReconnect_Allowed(t *testing.T) {
	key := ciscoNewHostKey(t)
	srv := startCiscoTestServer(t, key)

	interrogator := &CiscoInterrogator{}
	result, err := interrogator.Interrogate(context.Background(),
		ciscoDeviceFor(t, srv.addr, ssh.FingerprintSHA256(key.PublicKey())),
		Credentials{Username: "admin", Password: "hunter2"})
	if err != nil {
		t.Fatalf("a matching pinned key must be allowed, got: %v", err)
	}

	var verification string
	for i := range result.Assets {
		if v, ok := result.Assets[i].Metadata["ssh_host_key_verification"].(string); ok {
			verification = v
		}
	}
	if verification != sshtrust.VerificationPinned {
		t.Errorf("verification = %q, want %q", verification, sshtrust.VerificationPinned)
	}
	if len(srv.seen()) != 1 {
		t.Errorf("expected one authentication, saw %v", srv.seen())
	}
}

// The one that matters: a device whose key changed gets no credential.
func TestCiscoInterrogator_ChangedKey_RefusesAndSendsNoCredential(t *testing.T) {
	pinnedKey := ciscoNewHostKey(t)
	presentedKey := ciscoNewHostKey(t)
	srv := startCiscoTestServer(t, presentedKey)

	interrogator := &CiscoInterrogator{}
	_, err := interrogator.Interrogate(context.Background(),
		ciscoDeviceFor(t, srv.addr, ssh.FingerprintSHA256(pinnedKey.PublicKey())),
		Credentials{Username: "admin", Password: "hunter2"})
	if err == nil {
		t.Fatal("a changed host key must fail the interrogation")
	}

	var mismatch *sshtrust.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("the error must unwrap to *sshtrust.MismatchError so the service can raise a finding; got %T: %v", err, err)
	}

	// Not "an error was returned" — "the device administrator password never
	// left this process".
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("device credentials were transmitted to a host presenting an unrecognised key: %v", got)
	}
}
