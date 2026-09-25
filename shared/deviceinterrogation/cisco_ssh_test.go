package deviceinterrogation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A fake Cisco CLI over a real in-process SSH server, driving the REAL
// CiscoInterrogator: authentication (public key, password, keyboard-
// interactive), exec channels, and an interactive PTY shell with a user/
// privileged prompt, `enable`, and a pager. The assertions are about what
// crossed the wire and what came out the other end, not about helpers.

// fakeCiscoPW is long and distinctive on purpose: the secret-leak assertions
// search the whole marshalled result, and a two-letter password turns up by
// chance inside a random host-key fingerprint (which is what made
// TestCiscoSSH_WrongEnableSecretIsAWarning flake).
const fakeCiscoPW = "login-pw-5e8b"

const fakeCiscoInvalid = "                     ^\n% Invalid input detected at '^' marker.\n"

type fakeCiscoConfig struct {
	password           string        // "" = password auth refused
	keyboardOnly       bool          // offer keyboard-interactive instead of password
	authorizedKey      ssh.PublicKey // nil = public-key auth refused
	enableSecret       string        // "" = enable has no secret configured
	startLevel         int           // the account's privilege level
	execRefused        bool          // reject every exec channel request
	pageAfter          int           // >0: page output longer than this many lines
	ignorePagerOff     bool          // keep paging after `terminal length 0`
	execPagerHangs     bool          // exec: page and then wait forever
	execNoExitStatus   bool          // exec: close without sending an exit status
	execHangs          bool          // exec: accept the command and never answer
	ptyHangs           bool          // never answer a pty-req (the client blocks on it)
	hostname           string
	outputs            map[string]string // privilege-15 command output
	userLevelResponses map[string]string // commands a level-1 account may run
}

type fakeCisco struct {
	cfg  fakeCiscoConfig
	addr string

	mu             sync.Mutex
	authMethods    []string
	passwordsSeen  []string
	execCommands   []string
	shellLines     []string // every line written to a shell, except at a password prompt
	enableAttempts []string // what was typed at the enable password prompt
	shells         sync.WaitGroup
}

// waitForShells blocks until every shell the fake served has ended, so what it
// recorded includes the `exit` a client writes as it closes. Interrogate
// returns once it has written that line; the fake reads it a moment later.
func (f *fakeCisco) waitForShells(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { f.shells.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a fake shell never ended")
	}
}

func (f *fakeCisco) record(dst *[]string, v string) {
	f.mu.Lock()
	*dst = append(*dst, v)
	f.mu.Unlock()
}

func (f *fakeCisco) snapshot(src *[]string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), *src...)
}

// respond is what a command answers at a privilege level.
func (f *fakeCisco) respond(command string, level int) string {
	switch command {
	case "show privilege":
		return "Current privilege level is " + strconv.Itoa(level) + "\n"
	case "show curpriv":
		return "Username : netops\nCurrent privilege level : " + strconv.Itoa(level) + "\nCurrent Mode/s : P_UNPR\n"
	}
	if out, ok := f.cfg.userLevelResponses[command]; ok {
		return out
	}
	if level < 15 {
		return fakeCiscoInvalid
	}
	if out, ok := f.cfg.outputs[command]; ok {
		return out
	}
	return fakeCiscoInvalid
}

func startFakeCisco(t *testing.T, cfg fakeCiscoConfig) *fakeCisco {
	t.Helper()
	if cfg.hostname == "" {
		cfg.hostname = "edge-rtr1"
	}
	if cfg.startLevel == 0 {
		cfg.startLevel = 15
	}
	f := &fakeCisco{cfg: cfg}

	server := &ssh.ServerConfig{
		AuthLogCallback: func(_ ssh.ConnMetadata, method string, _ error) {
			if method != "none" {
				f.record(&f.authMethods, method)
			}
		},
	}
	if cfg.password != "" && !cfg.keyboardOnly {
		server.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			f.record(&f.passwordsSeen, string(password))
			if string(password) == cfg.password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("denied")
		}
	}
	if cfg.password != "" && cfg.keyboardOnly {
		server.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(answers) != 1 {
				return nil, errors.New("denied")
			}
			f.record(&f.passwordsSeen, answers[0])
			if answers[0] == cfg.password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("denied")
		}
	}
	if cfg.authorizedKey != nil {
		server.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), cfg.authorizedKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unknown key")
		}
	}
	server.AddHostKey(ciscoNewHostKey(t))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, server)
		}
	}()
	return f
}

func (f *fakeCisco) serve(conn net.Conn, server *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, server)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go f.session(ch, chReqs)
	}
	_ = sconn.Wait()
}

func (f *fakeCisco) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "window-change":
			if req.Type == "pty-req" && f.cfg.ptyHangs {
				continue
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			f.record(&f.execCommands, payload.Command)
			if f.cfg.execRefused {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go f.exec(ch, payload.Command)
		case "shell":
			_ = req.Reply(true, nil)
			f.shells.Add(1)
			go func() {
				defer f.shells.Done()
				f.shell(ch)
			}()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (f *fakeCisco) exec(ch ssh.Channel, command string) {
	if f.cfg.execHangs {
		return
	}
	out := f.respond(command, f.cfg.startLevel)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if f.cfg.execPagerHangs && f.cfg.pageAfter > 0 && len(lines) > f.cfg.pageAfter {
		_, _ = ch.Write([]byte(strings.Join(lines[:f.cfg.pageAfter], "\n") + "\n --More-- "))
		return // and never finish: an exec channel cannot answer a pager
	}
	_, _ = ch.Write([]byte(out))
	if !f.cfg.execNoExitStatus {
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	}
	_ = ch.Close()
}

// shell is a minimal IOS CLI: a prompt that says the level, `enable` with a
// secret, `terminal length 0`, a pager, and `exit`.
func (f *fakeCisco) shell(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	level := f.cfg.startLevel
	pagerOff := false
	prompt := func() string {
		if level >= 15 {
			return f.cfg.hostname + "#"
		}
		return f.cfg.hostname + ">"
	}
	write := func(s string) { _, _ = ch.Write([]byte(strings.ReplaceAll(s, "\n", "\r\n"))) }

	// A banner whose last line ends in '#', to prove the prompt is learned
	// from a confirmed fresh line, not from the banner.
	write("\n*** authorised use only ***\nbanner motd #\n" + prompt())

	const (
		stateLine = iota
		statePassword
		statePaging
	)
	state, attempts := stateLine, 0
	var line []byte
	buf := make([]byte, 256)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		for _, b := range buf[:n] {
			if state == statePaging {
				// Any key stops the listing here (IOS: q; we accept any).
				state = stateLine
				write("\n" + prompt())
				continue
			}
			if b == '\r' {
				continue
			}
			if b != '\n' {
				line = append(line, b)
				continue
			}
			text := strings.TrimSpace(string(line))
			line = line[:0]

			if state == statePassword {
				f.record(&f.enableAttempts, text)
				if text == f.cfg.enableSecret {
					level, state = 15, stateLine
					write("\n" + prompt())
					continue
				}
				attempts++
				if attempts < 3 {
					write("\nPassword: ")
					continue
				}
				state = stateLine
				write("\n% Bad secrets\n\n" + prompt())
				continue
			}

			f.record(&f.shellLines, text)
			write(text + "\n") // echo
			switch text {
			case "":
				write(prompt())
			case "enable":
				switch {
				case level >= 15:
					write(prompt())
				case f.cfg.enableSecret == "":
					write("% No password set\n" + prompt())
				default:
					state, attempts = statePassword, 0
					write("Password: ")
				}
			case "terminal length 0", "terminal pager 0":
				pagerOff = !f.cfg.ignorePagerOff
				write(prompt())
			case "exit":
				return
			default:
				out := strings.TrimRight(f.respond(text, level), "\n")
				lines := strings.Split(out, "\n")
				if f.cfg.pageAfter > 0 && !pagerOff && len(lines) > f.cfg.pageAfter {
					write(strings.Join(lines[:f.cfg.pageAfter], "\n") + "\n --More-- ")
					state = statePaging
					continue
				}
				write(out + "\n" + prompt())
			}
		}
	}
}

// --- fixtures -------------------------------------------------------------------

func fakeCiscoOutputs(t *testing.T) map[string]string {
	return map[string]string{
		"show crypto ipsec sa": readRealFixture(t, "cisco_ios", "show_crypto_ipsec_sa_detail.txt"),
		"show running-config | include ^line vty|transport input": "line vty 0 4\n transport input ssh\n",
	}
}

func fakeCiscoUserLevel(t *testing.T) map[string]string {
	return map[string]string{
		"show version": readRealFixture(t, "cisco_ios", "show_version_iosxe.txt"),
	}
}

func newClientKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "vista test key")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer, string(pem.EncodeToMemory(block))
}

func encryptedClientKey(t *testing.T, passphrase string) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "vista test key", []byte(passphrase))
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer, string(pem.EncodeToMemory(block))
}

// interrogateFake runs the real interrogator, through the same sanitizing
// decorator Registry.Get applies in production.
func interrogateFake(t *testing.T, f *fakeCisco, creds Credentials) (*InterrogateResult, error) {
	t.Helper()
	interrogator := sanitizingInterrogator{inner: &CiscoInterrogator{}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return interrogator.Interrogate(ctx, ciscoDeviceFor(t, f.addr, ""), creds)
}

// assertNoSecretsIn fails if any secret appears anywhere in the result — its
// assets, facts, warnings, identity.
func assertNoSecretsIn(t *testing.T, result *InterrogateResult, secrets ...string) {
	t.Helper()
	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(string(blob), secret) {
			t.Errorf("a credential reached the result: %q in %s", secret, blob)
		}
	}
	for _, marker := range []string{"PRIVATE KEY", "BEGIN OPENSSH"} {
		if strings.Contains(string(blob), marker) {
			t.Errorf("key material reached the result (%s)", marker)
		}
	}
}

func vpnPeers(result *InterrogateResult) []string {
	var peers []string
	for _, a := range result.Assets {
		if p, ok := a.Metadata[ciscoVPNPeerKey].(string); ok {
			peers = append(peers, p)
		}
	}
	return peers
}

// --- authentication -------------------------------------------------------------

func TestCiscoSSH_PublicKeyAuth(t *testing.T) {
	signer, keyPEM := newClientKey(t)
	f := startFakeCisco(t, fakeCiscoConfig{authorizedKey: signer.PublicKey(), outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})

	result, err := interrogateFake(t, f, Credentials{Username: "netops", Custom: map[string]interface{}{ciscoCredPrivateKey: keyPEM}})
	if err != nil {
		t.Fatalf("key-only credentials must authenticate: %v", err)
	}
	if got := f.snapshot(&f.authMethods); !contains(got, "publickey") || contains(got, "password") {
		t.Errorf("auth methods tried = %v, want publickey and no password", got)
	}
	if len(vpnPeers(result)) == 0 {
		t.Errorf("no VPN rows collected over a key-authenticated session")
	}
	assertNoSecretsIn(t, result, keyPEM)
}

func TestCiscoSSH_EncryptedKeyWithPassphrase(t *testing.T) {
	signer, keyPEM := encryptedClientKey(t, "correct horse")
	f := startFakeCisco(t, fakeCiscoConfig{authorizedKey: signer.PublicKey(), outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Custom: map[string]interface{}{
		ciscoCredPrivateKey: keyPEM, ciscoCredPassphrase: "correct horse",
	}})
	if err != nil {
		t.Fatalf("an encrypted key with its passphrase must authenticate: %v", err)
	}
	assertNoSecretsIn(t, result, keyPEM, "correct horse")
}

// AAA-backed IOS and ASA commonly offer keyboard-interactive and NOT password;
// a password-only client could not log in at all.
func TestCiscoSSH_KeyboardInteractiveAuth(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{password: "s3cret-pw", keyboardOnly: true, outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: "s3cret-pw"})
	if err != nil {
		t.Fatalf("keyboard-interactive must authenticate: %v", err)
	}
	if got := f.snapshot(&f.authMethods); !contains(got, "keyboard-interactive") {
		t.Errorf("auth methods tried = %v, want keyboard-interactive", got)
	}
	assertNoSecretsIn(t, result, "s3cret-pw")
}

// The key-parse errors reach the job's failure reason, so they name the field
// and never the key.
func TestCiscoAuthMethods_KeyErrorsNeverRepeatTheKey(t *testing.T) {
	sentinel := "SENTINEL-KEY-BYTES-7f3a"
	garbage := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + sentinel + "\n-----END OPENSSH PRIVATE KEY-----\n"
	_, encrypted := encryptedClientKey(t, "right")

	for _, tc := range []struct {
		name  string
		creds Credentials
		want  string
	}{
		{"unparseable", Credentials{Username: "u", Custom: map[string]interface{}{ciscoCredPrivateKey: garbage}}, "could not be parsed"},
		{"passphrase missing", Credentials{Username: "u", Custom: map[string]interface{}{ciscoCredPrivateKey: encrypted}}, "passphrase-protected"},
		{"passphrase wrong", Credentials{Username: "u", Custom: map[string]interface{}{ciscoCredPrivateKey: encrypted, ciscoCredPassphrase: "wrong-" + sentinel}}, "does not decrypt"},
		{"nothing to authenticate with", Credentials{Username: "u"}, "password or an SSH private key"},
	} {
		_, err := ciscoAuthMethods(tc.creds)
		if err == nil {
			t.Errorf("%s: no error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q, want it to mention %q", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: the error repeats key material or the passphrase: %q", tc.name, err)
		}
	}
}

// A pinned host key that does not match aborts the handshake before ANY
// credential — here a public-key signature — is offered.
func TestCiscoSSH_ChangedHostKeyOffersNoKey(t *testing.T) {
	signer, keyPEM := newClientKey(t)
	f := startFakeCisco(t, fakeCiscoConfig{authorizedKey: signer.PublicKey()})
	wrongPin := ssh.FingerprintSHA256(ciscoNewHostKey(t).PublicKey())
	_, err := (&CiscoInterrogator{}).Interrogate(context.Background(), ciscoDeviceFor(t, f.addr, wrongPin),
		Credentials{Username: "netops", Custom: map[string]interface{}{ciscoCredPrivateKey: keyPEM}})
	if err == nil {
		t.Fatal("a changed host key must fail the interrogation")
	}
	if got := f.snapshot(&f.authMethods); len(got) != 0 {
		t.Errorf("authentication was attempted against an unrecognised host: %v", got)
	}
}

// --- privilege and enable -----------------------------------------------------

// A level-1 account with an enable secret: the collector opens a shell,
// enables, turns the pager off, and collects what needs level 15 — which an
// exec channel could never do.
func TestCiscoSSH_EnableRaisesALevelOneAccount(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{
		password: "pw-level1", startLevel: 1, enableSecret: "en-4bd2", pageAfter: 20,
		outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t),
	})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: "pw-level1", Custom: map[string]interface{}{ciscoCredEnableSecret: "en-4bd2"}})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	if got := vpnPeers(result); !contains(got, "198.51.100.2") || !contains(got, "203.0.113.2") {
		t.Errorf("the level-15 IPsec state was not collected after enable: peers %v, warnings %+v", got, result.Warnings)
	}
	for _, w := range result.Warnings {
		if w.Reason == WarningPermissionDenied || w.Reason == WarningTruncated {
			t.Errorf("unexpected warning after a successful enable: %+v", w)
		}
	}
	lines := f.snapshot(&f.shellLines)
	if !contains(lines, "enable") || !contains(lines, "terminal length 0") {
		t.Errorf("shell lines = %v, want enable and terminal length 0", lines)
	}
	// The secret went once, at the password prompt — never as a command.
	if got := f.snapshot(&f.enableAttempts); len(got) != 1 || got[0] != "en-4bd2" {
		t.Errorf("enable password prompt answered %v, want exactly the secret once", got)
	}
	if contains(lines, "en-4bd2") {
		t.Error("the enable secret was typed as a command line")
	}
	assertShellWroteOnlyAllowedLines(t, lines)
	assertNoSecretsIn(t, result, "pw-level1", "en-4bd2")
}

// A wrong enable secret is a permission_denied warning, the collection
// continues at the account's level, and the secret is not repeated at the
// device's re-prompts.
func TestCiscoSSH_WrongEnableSecretIsAWarning(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{
		password: fakeCiscoPW, startLevel: 1, enableSecret: "the-real-one",
		outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t),
	})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW, Custom: map[string]interface{}{ciscoCredEnableSecret: "not-it-91"}})
	if err != nil {
		t.Fatalf("a refused enable must not fail the interrogation: %v", err)
	}
	w := findWarning(t, result, "enable")
	assertWarning(t, w, ciscoCollector, WarningPermissionDenied, "privileged exec not reached")
	if got := f.snapshot(&f.enableAttempts); len(got) == 0 || got[0] != "not-it-91" || contains(got[1:], "not-it-91") {
		t.Errorf("password prompt answers = %v, want the secret once and only empty re-answers", got)
	}
	if !hasFact(result, factOSName) {
		t.Error("the user-level facts were lost with the enable")
	}
	assertNoSecretsIn(t, result, "not-it-91", "the-real-one", fakeCiscoPW)
}

// No enable secret for a below-15 account: say so, don't fail, don't pretend.
func TestCiscoSSH_LowPrivilegeWithoutSecretIsAWarning(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{
		password: fakeCiscoPW, startLevel: 1,
		outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t),
	})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	w := findWarning(t, result, "show privilege")
	assertWarning(t, w, ciscoCollector, WarningPermissionDenied, "privilege level 1")
	if lines := f.snapshot(&f.shellLines); len(lines) != 0 {
		t.Errorf("a shell was opened with no enable secret to use: %v", lines)
	}
}

// A privilege-15 account never opens a shell: exec channels are the simpler,
// stateless path and stay the default.
func TestCiscoSSH_Level15StaysOnExec(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW, Custom: map[string]interface{}{ciscoCredEnableSecret: "unused"}})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	if lines := f.snapshot(&f.shellLines); len(lines) != 0 {
		t.Errorf("a level-15 account opened a shell: %v", lines)
	}
	if len(vpnPeers(result)) == 0 {
		t.Error("no VPN rows over exec")
	}
	for _, w := range result.Warnings {
		if w.Reason == WarningPermissionDenied {
			t.Errorf("a level-15 account got a privilege warning: %+v", w)
		}
	}
}

// A device that closes an exec channel without an exit status still answered;
// x/crypto reports that as an error, and treating it as a failed command
// would throw away every row the device sent.
func TestCiscoSSH_ExecWithoutExitStatusIsNotAFailure(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, execNoExitStatus: true, outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	if !contains(vpnPeers(result), "198.51.100.2") || !hasFact(result, factOSName) {
		t.Errorf("output of exec channels closed without a status was discarded: warnings %+v", result.Warnings)
	}
	for _, w := range result.Warnings {
		if w.Endpoint == "show crypto ipsec sa" || w.Endpoint == "show version" {
			t.Errorf("a command that answered was reported as failed: %+v", w)
		}
	}
}

// A device that refuses exec channels outright is collected over a shell.
func TestCiscoSSH_ExecRefusedFallsBackToShell(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, execRefused: true, outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	if !hasFact(result, factOSName) || len(vpnPeers(result)) == 0 {
		t.Errorf("nothing collected over the fallback shell: facts %v, warnings %+v", factKeys(result), result.Warnings)
	}
	if lines := f.snapshot(&f.shellLines); !contains(lines, "show version") || !contains(lines, "terminal length 0") {
		t.Errorf("shell lines = %v", lines)
	}
	assertShellWroteOnlyAllowedLines(t, f.snapshot(&f.shellLines))
}

// --- paging -------------------------------------------------------------------

// An exec channel that pages: the device waits for a key that never comes. The
// collector must stop at the pager (not wait for the command timeout), keep
// the rows before it, and say the output is partial.
func TestCiscoSSH_ExecPagerIsTruncationNotAHang(t *testing.T) {
	old := ciscoCommandTimeout
	ciscoCommandTimeout = 20 * time.Second
	t.Cleanup(func() { ciscoCommandTimeout = old })

	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, pageAfter: 30, execPagerHangs: true, outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})
	start := time.Now()
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("the collector waited %s on a pager", elapsed)
	}
	w := findWarning(t, result, "show crypto ipsec sa")
	assertWarning(t, w, ciscoCollector, WarningTruncated, "pager")
	// The first 30 lines hold Tunnel1's flow up to its peer but not its
	// transform, so no SA row is reported from the partial table.
	if peers := vpnPeers(result); contains(peers, "203.0.113.2") {
		t.Errorf("a row from past the pager was reported: %v", peers)
	}
}

// A shell whose device keeps paging although paging was turned off: stopped at
// the first pager, reported truncated, and the session is still usable.
func TestCiscoSSH_ShellPagerIsStoppedAndReported(t *testing.T) {
	f := startFakeCisco(t, fakeCiscoConfig{
		password: fakeCiscoPW, startLevel: 1, enableSecret: "en", pageAfter: 30, ignorePagerOff: true,
		outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t),
	})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW, Custom: map[string]interface{}{ciscoCredEnableSecret: "en"}})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	assertWarning(t, findWarning(t, result, "show crypto ipsec sa"), ciscoCollector, WarningTruncated, "pager")
	// Commands after the paged ones still ran and still answered.
	lines := f.snapshot(&f.shellLines)
	if !contains(lines, "show crypto ikev2 sa") {
		t.Errorf("the session stopped after a pager: %v", lines)
	}
}

// The shell output cleaner: echo and prompt removed, the pager and what the
// terminal did to erase it cut, backspaces applied.
func TestCiscoShellOutputCleaning(t *testing.T) {
	isPrompt := func(s string) bool { s = strings.TrimSpace(s); return s == "r1#" || s == "r1>" }
	raw := "show ip arp\r\nInternet  192.0.2.1  -  aabb.cc00.0100  ARPA  Gi0/0\r\nInternet  192.0.2.2  5  aabb.cc00.0200  ARPA  Gi0/0\r\nr1#"
	if got := ciscoCleanShellOutput(raw, "show ip arp", isPrompt); strings.Contains(got, "show ip arp") || strings.Contains(got, "r1#") || len(ciscoParseARP(got)) != 2 {
		t.Errorf("cleaned = %q", got)
	}
	paged := "row 1\nrow 2\n --More-- \b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\brow 3\n"
	text, cut := ciscoStripPager(paged)
	if !cut || text != "row 1\nrow 2\n" {
		t.Errorf("stripPager = %q, %v", text, cut)
	}
	if _, cut := ciscoStripPager("<--- More --->"); !cut {
		t.Error("the ASA pager was not recognised")
	}
	if _, cut := ciscoStripPager("Description: more than one uplink"); cut {
		t.Error("the word 'more' in ordinary output was taken for a pager")
	}
}

// The prompt is the learned hostname followed by > or #, not any line ending
// in '#': a `banner motd #` or a description must not end a command early.
func TestCiscoShell_PromptIsTheLearnedHostname(t *testing.T) {
	s := &ciscoShell{prompt: "RP/0/RSP0/CPU0:edge"}
	for line, want := range map[string]bool{
		"RP/0/RSP0/CPU0:edge#": true,
		"RP/0/RSP0/CPU0:edge>": true,
		"banner motd #":        false,
		"other-host#":          false,
		"edge#":                false,
	} {
		if got := s.isPrompt(line); got != want {
			t.Errorf("isPrompt(%q) = %v, want %v", line, got, want)
		}
	}
}

func assertShellWroteOnlyAllowedLines(t *testing.T, lines []string) {
	t.Helper()
	for _, line := range lines {
		if line == "" {
			continue
		}
		if !contains(ciscoAllowedCommands, line) && !contains(ciscoAllowedSessionCommands, line) {
			t.Errorf("the shell wrote %q, which is on neither allowlist", line)
		}
	}
}
