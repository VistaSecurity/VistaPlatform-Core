package deviceinterrogation

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Cisco Identify over a REAL in-process SSH server: the server checks the
// password and answers `show version` / `show inventory` with fixture output,
// so the identity asserted below is the production parser reading the
// production transport.

type ciscoIdentifyFixtures struct {
	version   string
	inventory string
	// hang, when set, completes the SSH handshake and then never answers a
	// command — the device that accepts a connection and goes quiet.
	hang bool
}

type ciscoIdentifyServer struct {
	addr string
	mu   sync.Mutex
	seen []string
	cmds []string
}

func (s *ciscoIdentifyServer) passwords() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func (s *ciscoIdentifyServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

func startCiscoIdentifyServer(t *testing.T, fx ciscoIdentifyFixtures) *ciscoIdentifyServer {
	t.Helper()
	srv, _ := startCiscoIdentifyServerWithKey(t, fx)
	return srv
}

func startCiscoIdentifyServerWithKey(t *testing.T, fx ciscoIdentifyFixtures) (*ciscoIdentifyServer, ssh.Signer) {
	t.Helper()
	hostKey := ciscoNewHostKey(t)
	srv := &ciscoIdentifyServer{}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			srv.mu.Lock()
			srv.seen = append(srv.seen, string(password))
			srv.mu.Unlock()
			if string(password) != identifyGoodPass {
				return nil, ssh.ErrNoAuth
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })

	answer := func(command string) string {
		switch command {
		case "show version":
			return fx.version
		case "show inventory":
			return fx.inventory
		}
		return "% Invalid input detected at '^' marker.\n"
	}

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
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range chReqs {
							if req.Type != "exec" {
								if req.WantReply {
									_ = req.Reply(false, nil)
								}
								continue
							}
							var payload struct{ Command string }
							_ = ssh.Unmarshal(req.Payload, &payload)
							srv.mu.Lock()
							srv.cmds = append(srv.cmds, payload.Command)
							srv.mu.Unlock()
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
							if fx.hang {
								continue // never answer, never close
							}
							_, _ = ch.Write([]byte(answer(payload.Command)))
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							_ = ch.Close()
						}
					}()
				}
				_ = sconn.Wait()
			}()
		}
	}()
	return srv, hostKey
}

func ciscoIdentifyDevice(t *testing.T, addr string) DeviceInfo {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // no known_hosts from the machine running the suite
	return DeviceInfo{DeviceType: "cisco", ManagementURL: "ssh://" + addr}
}

func TestCiscoIdentify_IOSXEFromShowVersionAndInventory(t *testing.T) {
	srv := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{
		version:   ciscoFixture(t, "cisco_iosxe_show_version.txt"),
		inventory: ciscoFixture(t, "cisco_iosxe_show_inventory.txt"),
	})
	got, err := NewRegistry().Identify(context.Background(), ciscoIdentifyDevice(t, srv.addr),
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	want := map[string][2]string{
		"vendor":   {got.Vendor, ciscoVendor},
		"model":    {got.Model, "C9300-48P"},
		"serial":   {got.SerialNumber, "FCW2140L0GH"},
		"firmware": {got.FirmwareVersion, "17.09.04a"},
		"hostname": {got.Hostname, "sw-core-01"},
	}
	for field, pair := range want {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", field, pair[0], pair[1])
		}
	}
	host, portStr, _ := net.SplitHostPort(srv.addr)
	port, _ := strconv.Atoi(portStr)
	if got.TargetHost != host || got.TargetPort != port {
		t.Errorf("target = %s:%d, want %s", got.TargetHost, got.TargetPort, srv.addr)
	}
	// Only the identity commands — never the crypto config the full sweep reads.
	for _, cmd := range srv.commands() {
		if cmd != "show version" && cmd != "show inventory" {
			t.Errorf("Identify ran %q", cmd)
		}
	}
}

// Real captured ASA output (ntc-templates corpus): the model comes from
// `show inventory`'s chassis PID and the hostname from the "up" line.
func TestCiscoIdentify_RealASAOutput(t *testing.T) {
	srv := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{
		version:   ciscoFixture(t, "real/cisco/cisco_asa/show_version.txt"),
		inventory: ciscoFixture(t, "real/cisco/cisco_asa/show_inventory.txt"),
	})
	got, err := NewRegistry().Identify(context.Background(), ciscoIdentifyDevice(t, srv.addr),
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Model != "ASA5515" || got.SerialNumber != "REDACTEDSN1" || got.FirmwareVersion != "9.5(2)204" || got.Hostname != "asa1" {
		t.Errorf("identity = %+v, hostname %q", got.DeviceIdentity, got.Hostname)
	}
}

func TestCiscoIdentify_WrongPasswordIsAuthenticationFailed(t *testing.T) {
	srv := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{version: ciscoFixture(t, "cisco_iosxe_show_version.txt")})
	_, err := NewRegistry().Identify(context.Background(), ciscoIdentifyDevice(t, srv.addr),
		Credentials{Username: identifyGoodUser, Password: "wrong-password"})
	assertIdentifyCode(t, err, IdentifyAuthenticationFailed)
	if len(srv.commands()) != 0 {
		t.Errorf("commands ran without authentication: %v", srv.commands())
	}
}

// An SSH server that is not a Cisco CLI answers `show version` with text that
// names no Cisco version or model.
func TestCiscoIdentify_NonCiscoSSHServerIsUnsupportedResponse(t *testing.T) {
	srv := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{version: "bash: show: command not found\n"})
	_, err := NewRegistry().Identify(context.Background(), ciscoIdentifyDevice(t, srv.addr),
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyUnsupportedResponse)
}

func TestCiscoIdentify_PinnedKeyMismatchSendsNoPassword(t *testing.T) {
	srv := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{version: ciscoFixture(t, "cisco_iosxe_show_version.txt")})
	device := ciscoIdentifyDevice(t, srv.addr)
	device.SSHHostKeyFingerprint = ssh.FingerprintSHA256(ciscoNewHostKey(t).PublicKey())
	_, err := NewRegistry().Identify(context.Background(), device,
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyHostKeyMismatch)
	if n := len(srv.passwords()); n != 0 {
		t.Fatalf("the password was offered %d time(s) to a host with the wrong key", n)
	}
}

// deadlineOnlyCtx carries a deadline but never reports it through Err or
// Done: exactly the moment in which the connection's read deadline has
// already killed the session and ctx's own timer has not fired yet.
type deadlineOnlyCtx struct {
	context.Context
	deadline time.Time
}

func (c deadlineOnlyCtx) Deadline() (time.Time, bool) { return c.deadline, true }

// The CI flake, made deterministic: past the deadline, a command killed by the
// connection deadline is a timeout (connection_failed), not a device that
// failed to answer (discovery_failed) — whether or not ctx.Err() is set yet.
func TestCiscoIdentify_DeadlineWinsEvenBeforeCtxErrIsSet(t *testing.T) {
	srv := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{hang: true})
	ctx := deadlineOnlyCtx{Context: context.Background(), deadline: time.Now().Add(400 * time.Millisecond)}
	_, err := NewRegistry().Identify(ctx, ciscoIdentifyDevice(t, srv.addr),
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyConnectionFailed)
}

// session.Run cannot be cancelled, so the deadline is enforced by closing the
// connection. Without that, this test hangs until the package timeout.
func TestCiscoIdentify_DeviceThatGoesQuietHonoursTheDeadline(t *testing.T) {
	srv := startCiscoIdentifyServer(t, ciscoIdentifyFixtures{hang: true})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewRegistry().Identify(ctx, ciscoIdentifyDevice(t, srv.addr),
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	assertIdentifyCode(t, err, IdentifyConnectionFailed)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Identify took %s against a 500ms deadline", elapsed)
	}
}

func TestCiscoIdentifyTarget(t *testing.T) {
	for _, tc := range []struct {
		device   DeviceInfo
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{DeviceInfo{ManagementURL: "192.0.2.10"}, "192.0.2.10", 22, false},
		{DeviceInfo{ManagementURL: "192.0.2.10:2222"}, "192.0.2.10", 2222, false},
		{DeviceInfo{ManagementURL: "ssh://192.0.2.10:2200"}, "192.0.2.10", 2200, false},
		{DeviceInfo{ManagementURL: "https://192.0.2.10:8443"}, "192.0.2.10", 22, false},
		{DeviceInfo{IPAddress: "198.51.100.4", ManagementURL: "ssh://192.0.2.10"}, "198.51.100.4", 22, false},
		{DeviceInfo{ManagementURL: "ssh://admin:pw@192.0.2.10"}, "", 0, true},
		{DeviceInfo{ManagementURL: "ssh://192.0.2.10/path"}, "", 0, true},
		{DeviceInfo{ManagementURL: "ftp://192.0.2.10"}, "", 0, true},
		{DeviceInfo{ManagementURL: "ssh://192.0.2.10:99999"}, "", 0, true},
		{DeviceInfo{}, "", 0, true},
	} {
		host, port, err := ciscoIdentifyTarget(tc.device)
		if (err != nil) != tc.wantErr || host != tc.wantHost || port != tc.wantPort {
			t.Errorf("ciscoIdentifyTarget(%+v) = %q, %d, %v; want %q, %d, err=%v",
				tc.device, host, port, err, tc.wantHost, tc.wantPort, tc.wantErr)
		}
	}
}

func TestCiscoHostnameFromVersion(t *testing.T) {
	for file, want := range map[string]string{
		"cisco_ios_show_version.txt":                  "sw-access-01",
		"cisco_asa_show_version.txt":                  "fw-edge-01",
		"cisco_nxos_show_version.txt":                 "nx-core-1",
		"real/cisco/cisco_ios/show_version_iosxe.txt": "AKBTESTW01",
		"real/cisco/cisco_nxos/show_version.txt":      "",
		"real/cisco/cisco_asa/show_version.txt":       "asa1",
	} {
		got := ciscoHostnameFromVersion(ciscoFixture(t, file))
		if want == "" {
			// Only asserted not to be the NX-OS kernel line.
			if got == "Kernel" {
				t.Errorf("%s: read the kernel uptime line as a hostname", file)
			}
			continue
		}
		if got != want {
			t.Errorf("%s: hostname = %q, want %q", file, got, want)
		}
	}
}

// The identification reports the host key it authenticated through, so a
// caller can pin it on the device it creates ( review NB-6).
func TestCiscoIdentify_ReportsTheHostKeyItTrusted(t *testing.T) {
	srv, key := startCiscoIdentifyServerWithKey(t, ciscoIdentifyFixtures{version: ciscoFixture(t, "cisco_iosxe_show_version.txt")})
	got, err := NewRegistry().Identify(context.Background(), ciscoIdentifyDevice(t, srv.addr),
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if want := ssh.FingerprintSHA256(key.PublicKey()); got.SSHHostKeyFingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", got.SSHHostKeyFingerprint, want)
	}
	if got.SSHHostKeyType != key.PublicKey().Type() {
		t.Errorf("key type = %q, want %q", got.SSHHostKeyType, key.PublicKey().Type())
	}
}

// The "Skip TLS verification" flag must not become an SSH host-key opt-out.
// known_hosts names a DIFFERENT key for this address; the identification has
// to refuse — with the flag set — and send no password ( review B1/NB-7).
// Forcing the policy to skip verification turns this red.
func TestCiscoIdentify_TLSSkipFlagDoesNotSkipHostKeyVerification(t *testing.T) {
	srv, _ := startCiscoIdentifyServerWithKey(t, ciscoIdentifyFixtures{version: ciscoFixture(t, "cisco_iosxe_show_version.txt")})
	device := ciscoIdentifyDevice(t, srv.addr) // HOME is now a temp dir
	home, _ := os.UserHomeDir()
	other := ciscoNewHostKey(t)
	host, port, _ := net.SplitHostPort(srv.addr)
	line := knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(host, port))}, other.PublicKey())
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := NewRegistry().Identify(context.Background(), device,
		Credentials{Username: identifyGoodUser, Password: identifyGoodPass, InsecureSkipVerify: true})
	assertIdentifyCode(t, err, IdentifyHostKeyMismatch)
	if n := len(srv.passwords()); n != 0 {
		t.Fatalf("the password was offered %d time(s) to a host known_hosts does not recognise", n)
	}
}
