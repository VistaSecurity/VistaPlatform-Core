package deviceinterrogation

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Adversarial devices, adopted from the security review of. Each one
// misbehaves in a way a real CLI can — echoes everything, prompts for a
// password forever, never prompts, asks for a username, refuses enable,
// answers late — and the assertions are about the wire: how many times the
// enable secret crossed it, where, and whether any secret reached the result.

type advDevice struct {
	addr   string
	mu     sync.Mutex
	raw    []byte // every byte written to any shell
	execs  []string
	shellF func(ch ssh.Channel, rec func([]byte))
}

func (d *advDevice) rawString() string { d.mu.Lock(); defer d.mu.Unlock(); return string(d.raw) }

func startAdv(t *testing.T, showVersion string, level string, shellF func(ch ssh.Channel, rec func([]byte))) *advDevice {
	t.Helper()
	d := &advDevice{shellF: shellF}
	server := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == "LOGINPW-zz9" {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("no")
		},
	}
	server.AddHostKey(ciscoNewHostKey(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, chans, reqs, err := ssh.NewServerConn(conn, server)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range creqs {
							switch req.Type {
							case "pty-req":
								_ = req.Reply(true, nil)
							case "exec":
								var p struct{ Command string }
								_ = ssh.Unmarshal(req.Payload, &p)
								d.mu.Lock()
								d.execs = append(d.execs, p.Command)
								d.mu.Unlock()
								_ = req.Reply(true, nil)
								out := "% Invalid input detected at '^' marker.\n"
								switch p.Command {
								case "show version":
									out = showVersion
								case "show privilege":
									out = "Current privilege level is " + level + "\n"
								}
								go func() {
									_, _ = ch.Write([]byte(out))
									_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
									_ = ch.Close()
								}()
							case "shell":
								_ = req.Reply(true, nil)
								go d.shellF(ch, func(b []byte) { d.mu.Lock(); d.raw = append(d.raw, b...); d.mu.Unlock() })
							default:
								if req.WantReply {
									_ = req.Reply(false, nil)
								}
							}
						}
					}()
				}
			}()
		}
	}()
	return d
}

// scriptedShell answers each line with onLine(line, state); echo also echoes
// every byte typed, including at a password prompt.
func scriptedShell(echo bool, onLine func(line string, st *int) string) func(ch ssh.Channel, rec func([]byte)) {
	return func(ch ssh.Channel, rec func([]byte)) {
		defer func() { _ = ch.Close() }()
		w := func(s string) { _, _ = ch.Write([]byte(strings.ReplaceAll(s, "\n", "\r\n"))) }
		w("\nr1>")
		st := 0
		var line []byte
		buf := make([]byte, 256)
		for {
			n, err := ch.Read(buf)
			if err != nil {
				return
			}
			rec(buf[:n])
			if echo {
				_, _ = ch.Write(buf[:n])
			}
			for _, b := range buf[:n] {
				if b == '\r' {
					continue
				}
				if b != '\n' {
					line = append(line, b)
					continue
				}
				text := string(line)
				line = line[:0]
				if text == "exit" {
					return
				}
				w(onLine(text, &st))
			}
		}
	}
}

const advSecret = "ENSECRET-q7x"

func advRun(t *testing.T, d *advDevice) (*InterrogateResult, time.Duration, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	res, err := (sanitizingInterrogator{inner: &CiscoInterrogator{}}).Interrogate(ctx, ciscoDeviceFor(t, d.addr, ""),
		Credentials{Username: "u", Password: "LOGINPW-zz9", Custom: map[string]interface{}{ciscoCredEnableSecret: advSecret}})
	return res, time.Since(start), err
}

func advFast(t *testing.T) {
	oc, op := ciscoCommandTimeout, ciscoPromptTimeout
	ciscoCommandTimeout, ciscoPromptTimeout = 400*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { ciscoCommandTimeout, ciscoPromptTimeout = oc, op })
}

// advCheck: the secret crossed the wire exactly wantSends times, never on a
// command line, and no secret reached the result.
func advCheck(t *testing.T, d *advDevice, res *InterrogateResult, wantSends int) {
	t.Helper()
	raw := d.rawString()
	if got := strings.Count(raw, advSecret); got != wantSends {
		t.Errorf("secret sent %d times, want %d; raw=%q", got, wantSends, raw)
	}
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "enable") && strings.Contains(l, advSecret) {
			t.Errorf("secret on a command line: %q", l)
		}
	}
	if res == nil {
		t.Fatal("no result")
	}
	b, _ := json.Marshal(res)
	for _, s := range []string{advSecret, "LOGINPW-zz9", "ENSECRET", "LOGINPW"} {
		if strings.Contains(string(b), s) {
			t.Errorf("secret %q reached result: %s", s, b)
		}
	}
}

func advEnableWarning(t *testing.T, res *InterrogateResult) {
	t.Helper()
	assertWarning(t, findWarning(t, res, "enable"), ciscoCollector, WarningPermissionDenied, "privileged exec not reached")
}

// advRanOverExec: after a failed enable the collection went back to exec
// channels, which still work, rather than into a shell stuck at a prompt.
func advRanOverExec(t *testing.T, d *advDevice) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !contains(d.execs, "show inventory") {
		t.Errorf("after a failed enable the collection did not continue over exec; exec commands: %v", d.execs)
	}
}

func iosVer(t *testing.T) string { return readRealFixture(t, "cisco_ios", "show_version_iosxe.txt") }

// A device that echoes every byte, the secret included, and prints the secret
// inside command output.
func TestCiscoAdversarial_EchoEverything(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(true, func(line string, st *int) string {
		switch {
		case *st == 1:
			*st = 2
			return "\nr1#"
		case line == "enable":
			*st = 1
			return "\nPassword: "
		case *st == 2:
			return "\n" + advSecret + "\nline with " + advSecret + " inside\nr1#"
		}
		return "\nr1>"
	}))
	res, _, err := advRun(t, d)
	if err != nil {
		t.Fatal(err)
	}
	advCheck(t, d, res, 1)
}

// A device that asks for the password again whatever it is given.
func TestCiscoAdversarial_PasswordForever(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		if line == "enable" || *st == 1 {
			*st = 1
			return "\nPassword: "
		}
		return "\nr1>"
	}))
	res, dur, err := advRun(t, d)
	if err != nil {
		t.Fatal(err)
	}
	advCheck(t, d, res, 1)
	advEnableWarning(t, res)
	if dur > 15*time.Second {
		t.Errorf("took %s", dur)
	}
	// The shell existed only to enable; collection went back to exec.
	if !hasFact(res, factOSName) {
		t.Errorf("facts lost: %v", factKeys(res))
	}
	advRanOverExec(t, d)
}

// A device that says nothing after `enable`.
func TestCiscoAdversarial_NeverPrompts(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		if line == "enable" || *st == 1 {
			*st = 1
			return ""
		}
		return "\nr1>"
	}))
	res, dur, err := advRun(t, d)
	if err != nil {
		t.Fatal(err)
	}
	advCheck(t, d, res, 0)
	advEnableWarning(t, res)
	if dur > 15*time.Second {
		t.Errorf("took %s", dur)
	}
	advRanOverExec(t, d)
}

// A device that asks for a username: not a password prompt, no secret.
func TestCiscoAdversarial_UsernameMidSession(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		if line == "enable" {
			return "\nUsername: "
		}
		return "\nPassword: "
	}))
	res, _, _ := advRun(t, d)
	advCheck(t, d, res, 0)
	advEnableWarning(t, res)
}

// A device with a working prompt that answers `enable` with a prompt that is
// NOT a password prompt ("Username:", as an enable backed by per-user AAA
// asks). The secret must not be typed at it. (The device above answers the
// prompt-confirming newline with "Password:" too, so its shell never opens
// and it never reaches `enable`; this one does.)
func TestCiscoAdversarial_EnableAsksForAUsername(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		switch {
		case line == "enable":
			*st = 1
			return "\nUsername: "
		case *st == 1:
			*st = 0
			return "\n% Authentication failed\nr1>"
		}
		return "\nr1>"
	}))
	res, _, _ := advRun(t, d)
	advCheck(t, d, res, 0)
	advEnableWarning(t, res)
	if !strings.Contains(d.rawString(), "enable") {
		t.Fatal("the collector never reached `enable`; this test would pass for the wrong reason")
	}
}

// "Enter password:" is a password prompt; the secret goes once.
func TestCiscoAdversarial_EnterPassword(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		if line == "enable" {
			*st = 1
			return "\nEnter password: "
		}
		if *st == 1 {
			*st = 2
			return "\nr1#"
		}
		if *st == 2 {
			return "\nPassword: "
		}
		return "\nr1>"
	}))
	res, _, _ := advRun(t, d)
	advCheck(t, d, res, 1)
}

// "% Access denied" and back to the user prompt: no password prompt, no secret.
func TestCiscoAdversarial_AccessDenied(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		if line == "enable" {
			return "\n% Access denied\n\nr1>"
		}
		return "\nr1>"
	}))
	res, _, _ := advRun(t, d)
	advCheck(t, d, res, 0)
	advEnableWarning(t, res)
}

// `enable` answered with the user prompt again: no secret.
func TestCiscoAdversarial_ReturnsToPrompt(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		return "\nr1>"
	}))
	res, _, _ := advRun(t, d)
	advCheck(t, d, res, 0)
	advEnableWarning(t, res)
}

// A secret that is a substring of real data must not corrupt it (B2).
func TestCiscoAdversarial_ShortSecretDoesNotCorruptOutput(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
		switch {
		case line == "enable":
			*st = 1
			return "\nPassword: "
		case *st == 1:
			*st = 2
			return "\nr1#"
		case line == "show inventory":
			return "\nNAME: \"Chassis\", DESCR: \"Cisco Catalyst 9300 48-port\"\nPID: C9300-48P         , VID: V02  , SN: FOC2233X0AB\nr1#"
		}
		return "\nr1#"
	}))
	res, err := (&CiscoInterrogator{}).Interrogate(context.Background(), ciscoDeviceFor(t, d.addr, ""),
		Credentials{Username: "u", Password: "LOGINPW-zz9", Custom: map[string]interface{}{ciscoCredEnableSecret: "C9300"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "[REDACTED]") {
		t.Errorf("a short secret masked ordinary output: identity=%+v", res.DeviceIdentity)
	}
	if res.DeviceIdentity == nil || res.DeviceIdentity.Model != "C9300-48P" {
		t.Errorf("model = %+v, want C9300-48P", res.DeviceIdentity)
	}
}

// A command that times out may still answer; the next command must not read
// that answer as its own (N1). After a timeout the shell is abandoned.
func TestCiscoAdversarial_LateOutputNeverShiftsAttribution(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "15", scriptedShell(false, func(line string, st *int) string {
		if line == "" {
			return "\nr1#"
		}
		if line == "slow" {
			time.Sleep(600 * time.Millisecond)
		}
		return "\nOUT-FOR:" + line + "\nr1#"
	}))
	cfg := &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.Password("LOGINPW-zz9")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err := ssh.Dial("tcp", d.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	s, err := openCiscoShell(context.Background(), client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, _, err := s.run(context.Background(), "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow: err = %v, want a timeout", err)
	}
	time.Sleep(400 * time.Millisecond) // the late answer arrives now
	for _, c := range []string{"a", "b", "c"} {
		out, _, err := s.run(context.Background(), c)
		if err == nil && !strings.Contains(out, "OUT-FOR:"+c) {
			t.Errorf("command %q returned another command's output: %q", c, out)
		}
		if !errors.Is(err, errCiscoShellAbandoned) {
			t.Errorf("command %q after a timeout: err = %v, want the shell abandoned", c, err)
		}
	}
}

// A device that stops reading: the write is bounded (N2).
func TestCiscoAdversarial_WriteToADeviceThatStopsReading(t *testing.T) {
	advFast(t)
	d := startAdv(t, iosVer(t), "15", func(ch ssh.Channel, rec func([]byte)) {
		_, _ = ch.Write([]byte("\r\nr1#"))
		buf := make([]byte, 64)
		// Read the prompt-confirming newline, then never read again.
		_, _ = ch.Read(buf)
		_, _ = ch.Write([]byte("\r\nr1#"))
		time.Sleep(10 * time.Second)
		_ = ch.Close()
	})
	cfg := &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.Password("LOGINPW-zz9")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err := ssh.Dial("tcp", d.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	s, err := openCiscoShell(context.Background(), client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	start := time.Now()
	// Larger than the channel window, so the write blocks once it is full.
	_, _, err = s.run(context.Background(), "show "+strings.Repeat("x", 8<<20))
	if err == nil {
		t.Fatal("a write the device never read completed")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the write was bounded only after %s", elapsed)
	}
	if !s.abandoned.Load() {
		t.Error("the shell was left in use after a stuck write")
	}
}

// Repeated misbehaving sessions leave no goroutines behind.
func TestCiscoAdversarial_NoGoroutineLeak(t *testing.T) {
	advFast(t)
	before := runtime.NumGoroutine()
	for i := 0; i < 3; i++ {
		d := startAdv(t, iosVer(t), "1", scriptedShell(false, func(line string, st *int) string {
			if line == "enable" || *st == 1 {
				*st = 1
				return "\nPassword: "
			}
			return ""
		}))
		_, _, _ = advRun(t, d)
	}
	deadline := time.Now().Add(5 * time.Second)
	after := runtime.NumGoroutine()
	for after-before > 12 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		after = runtime.NumGoroutine()
	}
	if after-before > 12 { // the three listeners' accept loops are still open
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Errorf("leak: %d -> %d\n%s", before, after, buf[:n])
	}
}
