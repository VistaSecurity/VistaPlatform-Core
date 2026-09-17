package hostinventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Runner is how the collector reaches a host. It is the ONLY thing that
// differs between local and remote mode: the command set, the parsers and the
// Report shape are identical on both sides of it.
//
// Two methods, deliberately. Everything the collector needs is either the
// output of a command or the bytes of a file, and a wider interface would let a
// parser reach for something only one transport can do — which is how the two
// modes drift apart.
type Runner interface {
	// Run executes argv WITHOUT a shell and returns its output. argv[0] is the
	// program; the remaining elements are arguments passed verbatim.
	//
	// A non-zero exit is NOT an error: `dpkg-query` exits 1 on a host with no
	// dpkg, and that is an answer. err is reserved for the transport failing —
	// the connection dropped, the program does not exist, the context expired.
	Run(ctx context.Context, argv []string) (stdout, stderr []byte, exit int, err error)

	// ReadFile returns the contents of an absolute path on the target.
	// A missing or unreadable file is an error, which the caller records as a
	// step failure and never as an empty value.
	ReadFile(ctx context.Context, path string) ([]byte, error)
}

// maxOutputBytes bounds what any single command or file may contribute. A host
// with 40,000 dpkg entries is real; a host answering `ss -ltnup` with a
// gigabyte is a host we must not be killed by. The bound is read-side, and a
// runner reports truncation as an error so a partial snapshot is never marked
// complete or used to retire facts and endpoints that happened to be omitted.
const maxOutputBytes = 8 << 20 // 8 MiB

// commandTimeout bounds one command. system_profiler and a large rpm database
// are both slow; a hung SSH session is slower.
const commandTimeout = 90 * time.Second

// ErrTruncated is returned when a command's output hit maxOutputBytes.
//
// It is an ERROR rather than a flag on a successful result, deliberately. A
// truncated JSON document does not parse, so Windows and macOS would fail
// anyway — but a truncated dpkg listing parses perfectly and yields a package
// list that is silently short. Failing the step puts SectionFailed in the
// Report, which is the difference between "this host has 4,000 packages" and
// "we stopped counting at 4,000".
var ErrTruncated = errors.New("hostinventory: output exceeded the 8 MiB read bound and was truncated")

// ---------------------------------------------------------------------------
// LocalRunner
// ---------------------------------------------------------------------------

// LocalRunner executes on the host the agent is installed on.
type LocalRunner struct{}

// NewLocalRunner returns a Runner that executes locally.
func NewLocalRunner() *LocalRunner { return &LocalRunner{} }

// Run executes argv locally with no shell involved.
//
// exec.CommandContext with a slice — never a shell string — is what makes an
// argument that happens to contain a metacharacter an argument rather than a
// second command.
func (LocalRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	if len(argv) == 0 {
		return nil, nil, -1, errors.New("hostinventory: empty argv")
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	outBuf := &boundedBuffer{limit: maxOutputBytes}
	errBuf := &boundedBuffer{limit: maxOutputBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	err := cmd.Run()
	if outBuf.truncated {
		return outBuf.Bytes(), errBuf.Bytes(), -1, ErrTruncated
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return outBuf.Bytes(), errBuf.Bytes(), 0, nil
	case errors.As(err, &exitErr):
		// A non-zero exit is an answer, not a transport failure.
		return outBuf.Bytes(), errBuf.Bytes(), exitErr.ExitCode(), nil
	default:
		return outBuf.Bytes(), errBuf.Bytes(), -1, err
	}
}

// ReadFile reads a local file, bounded.
func (LocalRunner) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // paths come from this package's own constant tables
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := &boundedBuffer{limit: maxOutputBytes}
	if _, err := io.Copy(buf, f); err != nil {
		return nil, err
	}
	if buf.truncated {
		return nil, fmt.Errorf("%s: %w", path, ErrTruncated)
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// SSHRunner
// ---------------------------------------------------------------------------

// SSHConfig is what SSHRunner needs to reach a target.
type SSHConfig struct {
	Host string
	Port int
	User string
	// Password authenticates the session. Cleared by the caller after use; this
	// package never writes it anywhere.
	Password string
	// PrivateKeyPEM, when set, is used in preference to Password.
	PrivateKeyPEM string
	// Passphrase decrypts PrivateKeyPEM when it is encrypted.
	Passphrase string
	// InsecureSkipHostKeyVerify is the operator's per-target opt-out of
	// host-key verification, mirroring the interrogators' InsecureSkipVerify.
	InsecureSkipHostKeyVerify bool
	// KnownHostsPath overrides the default ~/.ssh/known_hosts lookup. Tests set
	// it; operators do not need to.
	KnownHostsPath string
	Timeout        time.Duration
}

// SSHRunner executes on a remote host over SSH.
//
// Host-key handling is the same three tiers the Cisco interrogator uses
// (shared/deviceinterrogation/cisco.go), for the same reason: a single policy
// across every SSH client this project ships, and no runtime that silently
// ignores a host key.
//
//   - InsecureSkipHostKeyVerify → ignore (operator opt-in, recorded).
//   - a usable known_hosts       → strict verification against it.
//   - otherwise                  → capture-on-first-use: accept, and record the
//     key fingerprint as evidence.
//
// It is deliberately NOT the transport for Windows. See winrm.go.
type SSHRunner struct {
	cfg SSHConfig

	mu     sync.Mutex
	client *ssh.Client

	// HostKeyFingerprint is the SHA-256 fingerprint of the key we connected
	// through; HostKeyVerified records how it was trusted ("known_hosts",
	// "first_use", "skipped").
	HostKeyFingerprint string
	HostKeyVerified    string
}

// NewSSHRunner dials the target and returns a Runner for it. The caller closes
// it.
func NewSSHRunner(cfg SSHConfig) (*SSHRunner, error) {
	if cfg.Host == "" {
		return nil, errors.New("hostinventory: ssh: no host")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}

	r := &SSHRunner{cfg: cfg}

	var hostKeyCallback ssh.HostKeyCallback
	switch {
	case cfg.InsecureSkipHostKeyVerify:
		hostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec // operator opt-in, recorded as HostKeyVerified="skipped"
		r.HostKeyVerified = "skipped"
	default:
		if cb, ok := knownHostsCallback(cfg.KnownHostsPath); ok {
			hostKeyCallback = cb
			r.HostKeyVerified = "known_hosts"
		} else {
			hostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
				r.HostKeyFingerprint = ssh.FingerprintSHA256(key)
				return nil
			}
			r.HostKeyVerified = "first_use"
		}
	}

	auth, err := sshAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)), &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("hostinventory: ssh dial %s: %w", cfg.Host, err)
	}
	r.client = client
	return r, nil
}

// sshAuthMethods prefers a private key over a password, because a key is what
// an operator should be using and a password reaching a command line is what we
// are avoiding.
func sshAuthMethods(cfg SSHConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if cfg.PrivateKeyPEM != "" {
		var signer ssh.Signer
		var err error
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cfg.PrivateKeyPEM), []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.PrivateKeyPEM))
		}
		if err != nil {
			// The error from x/crypto can quote the key block; say what failed
			// without repeating the material.
			return nil, errors.New("hostinventory: ssh: the supplied private key could not be parsed")
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("hostinventory: ssh: no credential supplied")
	}
	return methods, nil
}

// knownHostsCallback returns a strict callback when a usable known_hosts
// exists, else ok=false so the caller falls back to capture-on-first-use.
func knownHostsCallback(override string) (ssh.HostKeyCallback, bool) {
	path := override
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, false
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, false
	}
	return cb, true
}

// Run executes argv on the remote host.
//
// The argv is rendered into a single command string because SSH's exec channel
// carries one string, not an argument vector — and WHICH rendering is correct
// depends on the shell on the far side.
//
// POSIX targets get [quoteArgv], which single-quotes every element so a value
// containing a space, a semicolon or a backtick stays one argument. Every argv
// this package sends is built from its own constant tables, but the quoting is
// unconditional so that stays true of the next command someone adds.
//
// A Windows target's default OpenSSH shell is cmd.exe, which treats a single
// quote as a literal character — POSIX quoting there produces `'powershell'`,
// which cmd.exe cannot find. So a PowerShell invocation is space-joined
// instead, and [renderArgv] REFUSES any element that would need quoting. That
// refusal is why the Windows command set is built as `-EncodedCommand <base64>`
// (windows.go): base64 and bare flags are the one form that survives both
// shells untouched, so the question never arises.
func (r *SSHRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	if len(argv) == 0 {
		return nil, nil, -1, errors.New("hostinventory: empty argv")
	}
	command, err := renderArgv(argv)
	if err != nil {
		return nil, nil, -1, err
	}
	// The same per-command bound LocalRunner applies. Without it the only
	// thing standing between a remote command that never returns and the
	// agent's single job slot is the whole-collection timeout, so ONE wedged
	// `find` on a stale NFS mount costs the entire collection rather than one
	// section — and a bound that exists on one transport and not the other is
	// exactly the local/remote divergence this package is shaped to prevent.
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	r.mu.Lock()
	client := r.client
	r.mu.Unlock()
	if client == nil {
		return nil, nil, -1, errors.New("hostinventory: ssh runner is closed")
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, -1, fmt.Errorf("hostinventory: ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	outBuf := &boundedBuffer{limit: maxOutputBytes}
	errBuf := &boundedBuffer{limit: maxOutputBytes}
	session.Stdout = outBuf
	session.Stderr = errBuf

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-ctx.Done():
		// Ask the far side to stop, then return WITHOUT reading the buffers.
		//
		// session.Run is still on its own goroutine and the ssh package is
		// still copying into outBuf/errBuf from it; reading them here would be
		// a genuine data race, and the partial bytes are worth nothing anyway
		// — a half-read dpkg listing parses perfectly and is silently short,
		// which is the failure ErrTruncated exists to refuse. The deferred
		// Close below tears the channel down so the goroutine finishes.
		_ = session.Signal(ssh.SIGKILL)
		return nil, nil, -1, ctx.Err()
	case runErr := <-done:
		if outBuf.truncated {
			return outBuf.Bytes(), errBuf.Bytes(), -1, ErrTruncated
		}
		if runErr == nil {
			return outBuf.Bytes(), errBuf.Bytes(), 0, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			return outBuf.Bytes(), errBuf.Bytes(), exitErr.ExitStatus(), nil
		}
		return outBuf.Bytes(), errBuf.Bytes(), -1, runErr
	}
}

// ReadFile reads a remote file with `cat`, which every POSIX target has and
// which needs no second subsystem negotiated.
//
// A non-zero exit means the file is missing or unreadable, and that is an
// ERROR here rather than empty bytes: the whole point of the DMI reads is that
// "unreadable without root" must leave the fact absent, and returning empty
// bytes would make it present-and-blank.
func (r *SSHRunner) ReadFile(ctx context.Context, path string) ([]byte, error) {
	out, _, exit, err := r.Run(ctx, []string{"cat", "--", path})
	if err != nil {
		return nil, err
	}
	if exit != 0 {
		return nil, fmt.Errorf("hostinventory: cat %s: exit %d", path, exit)
	}
	return out, nil
}

// Close releases the SSH connection.
func (r *SSHRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client == nil {
		return nil
	}
	err := r.client.Close()
	r.client = nil
	return err
}

// renderArgv turns an argument vector into the single command string an SSH
// exec channel carries, picking the rendering the far-side shell understands.
//
// The choice is made from argv[0] rather than from runner state, so it is a
// property of the command and cannot be got wrong by probing in the wrong
// order: a PowerShell invocation is the only thing this package ever sends to
// Windows, and everything else is POSIX.
func renderArgv(argv []string) (string, error) {
	if isPowerShell(argv[0]) {
		return joinShellSafe(argv)
	}
	return quoteArgv(argv), nil
}

// isPowerShell reports whether argv[0] names a PowerShell host.
func isPowerShell(program string) bool {
	switch strings.ToLower(program) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	}
	return false
}

// quoteArgv renders an argument vector as one POSIX shell word list, single-
// quoting every element. A single quote inside an element is closed, escaped
// and reopened ('\”) — the only form that is safe inside single quotes.
func quoteArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return strings.Join(parts, " ")
}

// joinShellSafe space-joins an argv, refusing any element that is not safe
// unquoted under BOTH cmd.exe and a POSIX shell.
//
// It refuses rather than escapes on purpose. cmd.exe quoting is a different
// language from POSIX quoting and getting it subtly wrong is how an argument
// becomes a second command; the only thing this package needs to send is a
// base64 blob and some bare flags, so anything else is a programming error that
// should surface at the call site rather than be papered over.
func joinShellSafe(argv []string) (string, error) {
	for _, a := range argv {
		if a == "" {
			return "", errors.New("hostinventory: powershell argv contains an empty element")
		}
		if strings.ContainsAny(a, " \t\r\n\"'`$&|<>^%()!;") {
			return "", fmt.Errorf("hostinventory: powershell argv element %q needs quoting; build it as -EncodedCommand instead", a)
		}
	}
	return strings.Join(argv, " "), nil
}

// ---------------------------------------------------------------------------
// boundedBuffer
// ---------------------------------------------------------------------------

// boundedBuffer accumulates at most limit bytes and records whether more were
// offered. Writes always report full acceptance so the producer sees no error —
// closing the pipe mid-command would surface as a command failure and lose the
// rows already read. Same shape as the interrogators' boundedWriter.
type boundedBuffer struct {
	buf       []byte
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - len(b.buf)
	switch {
	case remaining <= 0:
		b.truncated = true
	case len(p) > remaining:
		b.buf = append(b.buf, p[:remaining]...)
		b.truncated = true
	default:
		b.buf = append(b.buf, p...)
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte { return b.buf }
