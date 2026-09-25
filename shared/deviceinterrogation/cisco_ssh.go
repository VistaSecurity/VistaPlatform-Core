package deviceinterrogation

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/internal/dialguard"
	"golang.org/x/crypto/ssh"
)

// The Cisco session layer: how the collector authenticates, how each command is
// run and bounded, and how it reaches privileged EXEC when the account does not
// start there (finding C-03).
//
// Two ways to run a command:
//
//   - EXEC (the default): one SSH `exec` channel per command. Nothing carries
//     over between commands, which is what makes it simple and safe — and also
//     why it cannot use an enable secret: `enable` in one exec channel raises
//     the privilege of that channel only, and the next command starts again at
//     the account's own level.
//   - SHELL: one interactive, PTY-backed channel for the whole run. Used when
//     the account has to `enable` to privilege 15, and when the device refuses
//     exec channels outright. Commands are written to it and their output is
//     read up to the next prompt, which the shell learns when it opens.
//
// Both are bounded by ciscoMaxCommandBytes and by a per-command timeout, and
// both detect a pager (`--More--`, `<--- More --->`): paged output is partial,
// and is reported as truncated rather than parsed as if it were whole.
//
// Secrets: the password, the private key and its passphrase, and the enable
// secret are read from the credentials and never written anywhere but the
// SSH transport — not to an error, not to a warning, not to the result. Output
// read back from a shell has any secret it happens to contain masked before a
// parser sees it.

// Credential keys read from Credentials.Custom. The device form's connection
// options (W3.1) will populate them; until then they arrive in the credential
// blob, which the device agent already forwards whole as Custom.
const (
	ciscoCredPrivateKey   = "ssh_private_key"
	ciscoCredPassphrase   = "ssh_private_key_passphrase"
	ciscoCredEnableSecret = "enable_secret"
)

// Timeouts. Variables, not constants, so the session tests can run in
// milliseconds; nothing in production assigns them.
var (
	// ciscoCommandTimeout bounds one command. `show interfaces` on a large
	// chassis takes seconds; a device that has not answered in a minute is
	// not going to.
	ciscoCommandTimeout = 60 * time.Second
	// ciscoPromptTimeout bounds each step of opening a shell and of `enable`,
	// and each write to a shell.
	ciscoPromptTimeout = 15 * time.Second
	// ciscoInterrogationTimeout bounds the whole interrogation of one device.
	ciscoInterrogationTimeout = 5 * time.Minute
	// ciscoHandshakeTimeout bounds the TCP connect AND the SSH handshake. A
	// peer that accepts the connection and never speaks SSH would otherwise
	// hold the dial forever when the caller's context has no deadline.
	ciscoHandshakeTimeout = 10 * time.Second
)

// ciscoCustomString reads a string credential from Credentials.Custom.
func ciscoCustomString(creds Credentials, key string) string {
	if creds.Custom == nil {
		return ""
	}
	s, _ := creds.Custom[key].(string)
	return s
}

// ciscoAuthMethods returns the SSH authentication methods the credentials
// support, in the order they are offered: public key first (when a key is
// supplied), then password, then keyboard-interactive answered with the same
// password. Keyboard-interactive is what an IOS or ASA configured for AAA
// through RADIUS/TACACS+ usually offers INSTEAD of password, so a
// password-only client could not log in to it at all.
func ciscoAuthMethods(creds Credentials) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if key := ciscoCustomString(creds, ciscoCredPrivateKey); strings.TrimSpace(key) != "" {
		signer, err := ciscoParsePrivateKey(key, ciscoCustomString(creds, ciscoCredPassphrase))
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if creds.Password != "" {
		methods = append(methods,
			ssh.Password(creds.Password),
			ssh.KeyboardInteractive(ciscoKeyboardInteractive(creds.Password)))
	}
	if len(methods) == 0 {
		return nil, errors.New("a password or an SSH private key (" + ciscoCredPrivateKey + ") is required for Cisco device")
	}
	return methods, nil
}

// ciscoParsePrivateKey parses a PEM/OpenSSH private key.
//
// The underlying error is deliberately NOT wrapped: a parse error describes the
// key's bytes, and this error reaches the job's failure reason. Each message is
// fixed text that names the credential field, never its value.
func ciscoParsePrivateKey(pemText, passphrase string) (ssh.Signer, error) {
	var (
		signer ssh.Signer
		err    error
	)
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(pemText), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(pemText))
	}
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return nil, errors.New(ciscoCredPrivateKey + " is passphrase-protected and no " + ciscoCredPassphrase + " was supplied")
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, errors.New(ciscoCredPassphrase + " does not decrypt " + ciscoCredPrivateKey)
	default:
		return nil, errors.New(ciscoCredPrivateKey + " could not be parsed as an OpenSSH, PKCS#1, PKCS#8 or SEC1 private key")
	}
}

// ciscoKeyboardInteractive answers a keyboard-interactive challenge with the
// password — but only a question that does not echo and asks for a password.
// An echoed question is a username or a menu, and anything else ("Passcode:",
// "Verification code:", a lone unlabelled prompt) is a second factor or a
// question this collector cannot answer: those get an empty answer and the
// server decides. The password is never offered to a question that did not ask
// for it.
func ciscoKeyboardInteractive(password string) ssh.KeyboardInteractiveChallenge {
	return func(_, _ string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, question := range questions {
			if i >= len(echos) || echos[i] {
				continue
			}
			if strings.Contains(strings.ToLower(question), "password") {
				answers[i] = password
			}
		}
		return answers, nil
	}
}

// --- output bounding and the pager ------------------------------------------

// ciscoPagerMarkers are the pager prompts IOS/IOS-XE/NX-OS/IOS-XR and ASA print
// when the terminal length is not zero.
var ciscoPagerMarkers = []string{"--More--", "<--- More --->"}

// ciscoPagerTailBytes is how much of the most recent output is kept for pager
// and prompt detection, independently of the byte bound.
const ciscoPagerTailBytes = 512

// boundedWriter accumulates at most limit bytes and records whether more were
// offered. Writes always report full acceptance so the producer sees no error.
//
// Safe for concurrent use: an exec session copies stdout and stderr into it
// from two goroutines. When pager is non-nil it is closed the first time the
// output's tail shows a pager prompt — the device is then waiting for a
// keypress an exec channel will never send.
type boundedWriter struct {
	mu        sync.Mutex
	buf       strings.Builder
	limit     int
	truncated bool

	tail      []byte
	pager     chan struct{}
	pagerSeen bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.limit - w.buf.Len()
	switch {
	case remaining <= 0:
		if len(p) > 0 {
			w.truncated = true
		}
	case len(p) > remaining:
		w.buf.Write(p[:remaining])
		w.truncated = true
	default:
		w.buf.Write(p)
	}
	if w.pager != nil && !w.pagerSeen {
		w.tail = ciscoAppendTail(w.tail, p)
		if ciscoHasPager(string(w.tail)) {
			w.pagerSeen = true
			close(w.pager)
		}
	}
	return len(p), nil
}

// String returns what was kept.
func (w *boundedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// Truncated reports whether the bound cut the output.
func (w *boundedWriter) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

func ciscoAppendTail(tail, p []byte) []byte {
	tail = append(tail, p...)
	if len(tail) > ciscoPagerTailBytes {
		tail = append([]byte(nil), tail[len(tail)-ciscoPagerTailBytes:]...)
	}
	return tail
}

func ciscoHasPager(s string) bool {
	for _, marker := range ciscoPagerMarkers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// ciscoStripPager cuts output at the first pager prompt and reports whether it
// found one. Everything from the pager line on is the pager and whatever the
// terminal did to erase it, never table rows.
func ciscoStripPager(output string) (string, bool) {
	first := -1
	for _, marker := range ciscoPagerMarkers {
		if i := strings.Index(output, marker); i >= 0 && (first < 0 || i < first) {
			first = i
		}
	}
	if first < 0 {
		return output, false
	}
	lineStart := strings.LastIndex(output[:first], "\n") + 1
	return output[:lineStart], true
}

// --- the session ----------------------------------------------------------------

// ciscoDialSSH opens the SSH connection through the collectors' SSRF dial
// guard ([dialguard.Dial], network.OnPremDialContext in production): a
// customer's private appliance is reachable, loopback and link-local — the
// cloud metadata endpoint — never are, and they are refused before a byte of
// SSH is exchanged. ssh.Dial would dial with a bare net.Dialer and bypass it.
//
// The handshake has a deadline of its own (config.Timeout, or the context's
// deadline if that is sooner): ssh.NewClientConn has none, and ssh.Dial's
// Timeout only ever covered the TCP connect. Host-key pinning is unchanged —
// it is the config's HostKeyCallback, which runs inside the handshake.
func ciscoDialSSH(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := dialguard.Dial(config.Timeout)(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(config.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// ciscoDialAddress joins host and port for dialing. net.JoinHostPort brackets an
// IPv6 literal; "%s:%d" produced "2001:db8::1:22", which dials nothing.
func ciscoDialAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// run is the ciscoRunner for this session: the shell when one is open, else a
// fresh exec channel per command.
func (c *ciscoSSHClient) run(ctx context.Context, command string) (string, bool, error) {
	if c.shell != nil {
		return c.shell.run(ctx, command)
	}
	return c.runBounded(ctx, command)
}

// runFirst runs the first command of the session. A device that refuses exec
// channels outright (the request is rejected, or nothing ever comes back) is
// retried once over an interactive shell, which every Cisco CLI supports.
func (c *ciscoSSHClient) runFirst(ctx context.Context, command string) (string, bool, error) {
	out, truncated, err := c.run(ctx, command)
	if err == nil || c.shell != nil || out != "" || !ciscoExecRefused(err) {
		return out, truncated, err
	}
	shell, shellErr := openCiscoShell(ctx, c.client, c.secrets)
	if shellErr != nil {
		return out, truncated, err
	}
	c.shell = shell
	return c.shell.run(ctx, command)
}

// ensurePrivilege makes sure the session runs at privilege 15 where it can, and
// says so on the result where it cannot (finding C-03).
//
// IOS, IOS-XE and ASA give an SSH session the ACCOUNT's privilege level, and
// most of what this collector reads — crypto state, the filtered running-config
// reads — needs 15. With an enable secret, a below-15 account is raised in an
// interactive shell (an exec channel cannot hold a privilege change from one
// command to the next). Without one, the collection continues at the account's
// level and a permission_denied warning names the gap, so a half-empty result
// is never mistaken for a device with nothing configured. NX-OS and IOS-XR
// authorise by role and have nothing to enable to.
func (c *ciscoSSHClient) ensurePrivilege(ctx context.Context, result *InterrogateResult) {
	if !ciscoUsesEnable(c.osName) {
		return
	}

	openedForEnable := false
	if c.shell == nil {
		command := "show privilege"
		if c.osName == "ASA" {
			command = "show curpriv"
		}
		out, _, err := c.runBounded(ctx, command)
		if err != nil {
			return // no answer is not evidence of a low privilege
		}
		level, ok := ciscoParsePrivilege(out)
		if !ok || level >= 15 {
			return
		}
		if c.enableSecret == "" {
			result.warnAs(WarningPermissionDenied, command,
				fmt.Sprintf("The account is at privilege level %d and no enable secret was supplied; commands that need level 15 may be refused and their data is missing", level), "")
			return
		}
		shell, err := openCiscoShell(ctx, c.client, c.secrets)
		if err != nil {
			result.warnAs(WarningPermissionDenied, "enable",
				"Privileged EXEC not reached; collection continued at the account's own privilege level", "could not open an interactive shell to run enable")
			return
		}
		c.shell = shell
		openedForEnable = true
	}

	if !c.shell.privileged {
		if c.enableSecret == "" {
			result.warnAs(WarningPermissionDenied, "enable",
				"The session is in user EXEC and no enable secret was supplied; commands that need privilege 15 may be refused and their data is missing", "")
		} else if err := c.shell.enable(ctx, c.enableSecret); err != nil {
			detail := errCiscoEnableRefused.Error()
			if !errors.Is(err, errCiscoEnableRefused) {
				detail = "no response to enable"
			}
			result.warnAs(WarningPermissionDenied, "enable",
				"Privileged EXEC not reached; collection continued at the account's own privilege level", detail)
			if openedForEnable {
				// The shell existed only to enable. Exec channels worked
				// before it and still do; a shell left at a password prompt
				// would not.
				_ = c.shell.Close()
				c.shell = nil
				return
			}
		}
	}
	for _, command := range ciscoPagerCommands(c.osName) {
		_, _, _ = c.shell.run(ctx, command)
	}
}

// --- EXEC mode ----------------------------------------------------------------

// runBounded runs one command on its own exec channel, reading at most
// ciscoMaxCommandBytes of its output and reporting whether the bound — or a
// pager — cut it short.
//
// The bound is read-side, not a post-hoc truncation: a device that answers
// `show ip arp` with a hundred megabytes never gets to put a hundred megabytes
// in our memory. The remote end keeps writing and we keep discarding, which is
// why the writer swallows the overflow rather than erroring — closing the pipe
// mid-command would surface as a command failure and lose the rows we did read.
//
// A pager is the one case the channel IS closed early: the device has stopped
// and is waiting for a keypress, so the rows before the pager are all there
// will be. They are returned, marked truncated.
func (c *ciscoSSHClient) runBounded(ctx context.Context, command string) (string, bool, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", false, fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	out := &boundedWriter{limit: ciscoMaxCommandBytes, pager: make(chan struct{})}
	session.Stdout = out
	session.Stderr = out

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	timer := time.NewTimer(ciscoCommandTimeout)
	defer timer.Stop()

	var runErr error
	select {
	case runErr = <-done:
	case <-out.pager:
		_ = session.Close()
		ciscoAwait(done)
	case <-ctx.Done():
		_ = session.Close()
		ciscoAwait(done)
		return "", false, ctx.Err()
	case <-timer.C:
		_ = session.Close()
		ciscoAwait(done)
		return "", false, fmt.Errorf("%w: the command did not complete within %s", context.DeadlineExceeded, ciscoCommandTimeout)
	}

	text, paged := ciscoStripPager(out.String())
	truncated := out.Truncated() || paged
	if runErr != nil && !paged {
		// A channel the device closed without an exit status still delivered
		// its output — IOS does this — and is not a failed command.
		var missing *ssh.ExitMissingError
		if !errors.As(runErr, &missing) {
			return "", truncated, fmt.Errorf("command execution failed: %w", runErr)
		}
	}
	return text, truncated, nil
}

// ciscoAwait waits briefly for a closed session's Run to return, so its copy
// goroutines are done with the writer before it is read.
func ciscoAwait(done <-chan error) {
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// ciscoExecRefused reports whether an exec-mode failure means the device does
// not accept exec channels at all (the channel request was refused, or nothing
// came back in time), as opposed to the command itself failing.
func ciscoExecRefused(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "ssh: command") && strings.Contains(msg, "failed")
}

// --- privilege ------------------------------------------------------------------

// ciscoPrivilegeRE reads IOS's `show privilege` ("Current privilege level is
// 15") and ASA's `show curpriv` ("Current privilege level : 15").
var ciscoPrivilegeRE = regexp.MustCompile(`(?i)current privilege level\s*(?:is|:)\s*(\d+)`)

// ciscoParsePrivilege returns the privilege level an output states.
func ciscoParsePrivilege(output string) (int, bool) {
	m := ciscoPrivilegeRE.FindStringSubmatch(output)
	if m == nil {
		return 0, false
	}
	level, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return level, true
}

// ciscoUsesEnable reports whether an OS family has IOS-style privilege levels
// and an `enable` command. NX-OS and IOS-XR authorise by role and task group;
// there is nothing to enable to.
func ciscoUsesEnable(osName string) bool {
	switch osName {
	case "NX-OS", "IOS-XR":
		return false
	}
	return true
}

// ciscoPagerCommands are the commands that turn paging off, per OS family.
// Unknown OS: both, since each is harmless where it is not understood.
func ciscoPagerCommands(osName string) []string {
	switch osName {
	case "ASA":
		return []string{"terminal pager 0"}
	case "":
		return []string{"terminal length 0", "terminal pager 0"}
	default:
		return []string{"terminal length 0"}
	}
}

// --- SHELL mode -----------------------------------------------------------------

// errCiscoEnableRefused is the enable failure, stated without the device's
// words (which are not persisted) and without the secret (which never is).
var errCiscoEnableRefused = errors.New("the device did not grant privileged EXEC for the supplied enable secret")

// ciscoPromptRE matches a CLI prompt as the last line of output: a hostname
// (IOS-XR prefixes the route processor, "RP/0/RSP0/CPU0:router") followed by
// ">" (user EXEC) or "#" (privileged EXEC).
var ciscoPromptRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._\-/:@()]{0,127})([>#])\s*$`)

// ciscoShellBuffer receives a shell's output. It keeps at most limit bytes of
// the current command's output (head) and, separately, the last few hundred
// bytes (tail), so the closing prompt is still seen after the head is full.
type ciscoShellBuffer struct {
	mu       sync.Mutex
	head     []byte
	tail     []byte
	overflow bool
	limit    int
	closed   error
	notify   chan struct{}
}

func newCiscoShellBuffer(limit int) *ciscoShellBuffer {
	return &ciscoShellBuffer{limit: limit, notify: make(chan struct{}, 1)}
}

func (b *ciscoShellBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	room := b.limit - len(b.head)
	switch {
	case room <= 0:
		if len(p) > 0 {
			b.overflow = true
		}
	case len(p) > room:
		b.head = append(b.head, p[:room]...)
		b.overflow = true
	default:
		b.head = append(b.head, p...)
	}
	b.tail = ciscoAppendTail(b.tail, p)
	b.mu.Unlock()
	b.signal()
	return len(p), nil
}

func (b *ciscoShellBuffer) signal() {
	select {
	case b.notify <- struct{}{}:
	default:
	}
}

func (b *ciscoShellBuffer) close(err error) {
	if err == nil {
		err = io.EOF
	}
	b.mu.Lock()
	if b.closed == nil {
		b.closed = err
	}
	b.mu.Unlock()
	b.signal()
}

func (b *ciscoShellBuffer) reset() {
	b.mu.Lock()
	b.head, b.tail, b.overflow = nil, nil, false
	b.mu.Unlock()
}

func (b *ciscoShellBuffer) snapshot() (head, tail string, overflow bool, closed error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.head), string(b.tail), b.overflow, b.closed
}

// errCiscoShellAbandoned is what every command gets after the shell was given
// up on. A command that timed out may still be producing output, and the next
// command would read it as its own — `show inventory` answered with the rest of
// `show interfaces` — so after a timeout the session is closed rather than
// reused.
var errCiscoShellAbandoned = errors.New("not run: the interactive session was abandoned after an earlier step did not complete in time")

// ciscoShell is one interactive CLI session.
type ciscoShell struct {
	session    *ssh.Session
	stdin      io.WriteCloser
	out        *ciscoShellBuffer
	prompt     string // the hostname part of the prompt, learned at open
	privileged bool   // the prompt ends in '#'
	secrets    []string
	abandoned  atomic.Bool
}

// openCiscoShell opens a PTY-backed shell and learns its prompt. The PTY is
// wide so a long table row is not wrapped into two lines a parser would read
// as two rows.
func openCiscoShell(ctx context.Context, client *ssh.Client, secrets []string) (*ciscoShell, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create shell session: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("failed to open shell input: %w", err)
	}
	out := newCiscoShellBuffer(ciscoMaxCommandBytes)
	session.Stdout = out
	session.Stderr = out
	if err := session.RequestPty("vt100", 0, 511, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("the device refused a terminal: %w", err)
	}
	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("the device refused an interactive shell: %w", err)
	}
	go func() { out.close(session.Wait()) }()

	s := &ciscoShell{session: session, stdin: stdin, out: out}
	for _, secret := range secrets {
		if secret != "" {
			s.secrets = append(s.secrets, secret)
		}
	}

	// A login banner can end in anything, including a line that looks like a
	// prompt, so the prompt is confirmed on a fresh line before it is trusted.
	anyPrompt := func(tail string) bool { return ciscoPromptRE.MatchString(ciscoLastLine(tail)) }
	if err := s.waitFor(ctx, ciscoPromptTimeout, anyPrompt); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("no CLI prompt from the device: %w", err)
	}
	out.reset()
	if err := s.write(ctx, "\n"); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.waitFor(ctx, ciscoPromptTimeout, anyPrompt); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("no CLI prompt from the device: %w", err)
	}
	_, tail, _, _ := out.snapshot()
	m := ciscoPromptRE.FindStringSubmatch(ciscoLastLine(tail))
	s.prompt, s.privileged = m[1], m[2] == "#"
	return s, nil
}

// Close ends the shell. The `exit` is a courtesy so the device frees the VTY
// line at once rather than when its idle timer notices; it is bounded like
// every other write, and skipped on a shell already given up on.
func (s *ciscoShell) Close() error {
	if s == nil || s.session == nil {
		return nil
	}
	if !s.abandoned.Load() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = s.write(ctx, "exit\n")
		cancel()
	}
	return s.session.Close()
}

// abandon gives up on the shell: it is closed, and every later command fails
// with errCiscoShellAbandoned instead of reading output that is not its own.
func (s *ciscoShell) abandon() {
	if s.abandoned.CompareAndSwap(false, true) && s.session != nil {
		_ = s.session.Close()
	}
}

// write sends text to the shell, bounded. An SSH channel write blocks when the
// device stops reading (its window is full), and nothing else would ever
// unblock it: the watchdog closes the session, which makes the write return.
func (s *ciscoShell) write(ctx context.Context, text string) error {
	if s.abandoned.Load() {
		return errCiscoShellAbandoned
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(s.stdin, text)
		done <- err
	}()
	timer := time.NewTimer(ciscoPromptTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			s.abandon()
			return fmt.Errorf("failed to write to the shell: %w", err)
		}
		return nil
	case <-timer.C:
		s.abandon()
		return fmt.Errorf("%w: the device stopped reading input", context.DeadlineExceeded)
	case <-ctx.Done():
		s.abandon()
		return ctx.Err()
	}
}

// waitFor blocks until match accepts the output's tail, the shell closes, the
// timeout passes or ctx ends. Anything but a match abandons the shell: the
// device is in a state the collector did not see coming, and whatever it sends
// next belongs to that state, not to the next command.
func (s *ciscoShell) waitFor(ctx context.Context, timeout time.Duration, match func(tail string) bool) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		_, tail, _, closed := s.out.snapshot()
		if match(tail) {
			return nil
		}
		if closed != nil {
			s.abandon()
			return fmt.Errorf("the device closed the session: %w", closed)
		}
		select {
		case <-s.out.notify:
		case <-ctx.Done():
			s.abandon()
			return ctx.Err()
		case <-timer.C:
			s.abandon()
			return fmt.Errorf("%w: no prompt within %s", context.DeadlineExceeded, timeout)
		}
	}
}

// isPrompt reports whether a line is THIS device's prompt, in either mode.
// Matching the learned hostname rather than any "word#" is what keeps a
// configuration line such as `banner motd #` from ending a command early.
func (s *ciscoShell) isPrompt(line string) bool {
	line = strings.TrimSpace(line)
	return line == s.prompt+">" || line == s.prompt+"#"
}

// ciscoPasswordPrompt reports whether a line is a password prompt ("Password:",
// "Enter password:") — the only line the enable secret is ever written after.
func ciscoPasswordPrompt(line string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(line)), "password:")
}

// enable raises the session to privileged EXEC with the enable secret.
//
// The secret is written once, at a password prompt, and only there: if the
// device answers `enable` with anything but a password prompt — its own prompt
// again, "% Access denied", "Username:", or nothing at all — the secret is not
// sent. A refused secret is re-prompted by IOS up to three times; the collector
// answers the re-prompts with empty lines so the device falls back to its user
// prompt, rather than repeating the secret. The buffer is cleared once the
// device has answered, so an echoed secret is never part of a command's output.
func (s *ciscoShell) enable(ctx context.Context, secret string) error {
	if s.privileged {
		return nil
	}
	s.out.reset()
	if err := s.write(ctx, "enable\n"); err != nil {
		return err
	}
	promptOrPassword := func(tail string) bool {
		last := ciscoLastLine(tail)
		return ciscoPasswordPrompt(last) || s.isPrompt(last)
	}
	if err := s.waitFor(ctx, ciscoPromptTimeout, promptOrPassword); err != nil {
		return err
	}
	_, tail, _, _ := s.out.snapshot()
	if ciscoPasswordPrompt(ciscoLastLine(tail)) {
		s.out.reset()
		if err := s.write(ctx, secret+"\n"); err != nil {
			return err
		}
		for attempt := 0; ; attempt++ {
			if err := s.waitFor(ctx, ciscoPromptTimeout, promptOrPassword); err != nil {
				return err
			}
			_, tail, _, _ = s.out.snapshot()
			if !ciscoPasswordPrompt(ciscoLastLine(tail)) {
				break
			}
			if attempt >= 3 {
				return errCiscoEnableRefused
			}
			s.out.reset()
			if err := s.write(ctx, "\n"); err != nil {
				return err
			}
		}
	}
	_, tail, _, _ = s.out.snapshot()
	s.out.reset()
	if strings.TrimSpace(ciscoLastLine(tail)) != s.prompt+"#" {
		return errCiscoEnableRefused
	}
	s.privileged = true
	return nil
}

// run writes one command and reads its output up to the next prompt. It has
// the ciscoRunner shape, so the collection path is the same in both modes.
func (s *ciscoShell) run(ctx context.Context, command string) (string, bool, error) {
	if s.abandoned.Load() {
		return "", false, errCiscoShellAbandoned
	}
	s.out.reset()
	if err := s.write(ctx, command+"\n"); err != nil {
		return "", false, err
	}
	paged := false
	if err := s.waitFor(ctx, ciscoCommandTimeout, func(tail string) bool {
		last := ciscoLastLine(tail)
		if s.isPrompt(last) {
			return true
		}
		if ciscoHasPager(last) {
			paged = true
			return true
		}
		return false
	}); err != nil {
		return "", false, err
	}
	head, _, overflow, _ := s.out.snapshot()
	if paged {
		// Paging should be off; a device that pages anyway is stopped here
		// rather than walked page by page, and what was read is partial. A
		// device that does not come back to its prompt abandons the shell.
		if err := s.write(ctx, "q"); err == nil {
			_ = s.waitFor(ctx, ciscoPromptTimeout, func(tail string) bool { return s.isPrompt(ciscoLastLine(tail)) })
		}
	}
	// The pager is cut BEFORE control characters are applied: a terminal
	// erases "--More--" with backspaces once a key is pressed, and after that
	// erasure there is nothing left to see.
	raw, sawPager := ciscoStripPager(head)
	text := ciscoDropSecretLines(ciscoCleanShellOutput(raw, command, s.isPrompt), s.secrets)
	return text, overflow || paged || sawPager, nil
}

// ciscoDropSecretLines removes lines that ARE a secret — a device echoing what
// was typed at a password prompt. Nothing else is touched.
//
// Substrings are deliberately not masked. Masking every occurrence corrupted
// real data and made the secret recoverable from it: with an enable secret of
// "C9300" the chassis model came back as "[REDACTED]-48P", and with the common
// default "cisco" every CDP platform string was mangled. The secret is only
// ever written at a password prompt, with the buffer cleared once the device
// answers, so an echo is the one way it can reach a command's output.
func ciscoDropSecretLines(text string, secrets []string) string {
	if len(secrets) == 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	kept := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		drop := false
		for _, secret := range secrets {
			if secret != "" && trimmed == secret {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// ciscoLastLine returns the last line of a terminal tail with carriage returns
// and terminal control sequences removed.
func ciscoLastLine(tail string) string {
	clean := ciscoStripControl(tail)
	if i := strings.LastIndex(clean, "\n"); i >= 0 {
		clean = clean[i+1:]
	}
	return strings.TrimRight(clean, " \t")
}

// ciscoANSIRE matches the terminal escape sequences a pager and a PTY emit.
var ciscoANSIRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// ciscoStripControl removes ANSI escapes, carriage returns and backspaces (with
// the character each erases).
func ciscoStripControl(s string) string {
	s = ciscoANSIRE.ReplaceAllString(s, "")
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '\r':
			continue
		case '\b':
			if n := len(out); n > 0 && out[n-1] != '\n' {
				out = out[:n-1]
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// ciscoCleanShellOutput turns a shell transcript of one command into what an
// exec channel would have returned: the echoed command line and the closing
// prompt are removed.
func ciscoCleanShellOutput(raw, command string, isPrompt func(string) bool) string {
	lines := strings.Split(ciscoStripControl(raw), "\n")
	if len(lines) > 0 && strings.HasSuffix(strings.TrimSpace(lines[0]), strings.TrimSpace(command)) {
		lines = lines[1:]
	}
	if n := len(lines); n > 0 && isPrompt(lines[n-1]) {
		lines = lines[:n-1]
	}
	return strings.Join(lines, "\n")
}
