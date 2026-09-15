package hostinventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner answers a scripted command set.
//
// It exists so the SAME fixture can be driven through two runners that differ
// only in how they would have reached the host — which is what makes the parity
// test mean something. A scripted answer is keyed by the whole argv joined with
// spaces, so a changed flag is a missing key rather than a silently different
// answer.
type fakeRunner struct {
	// label names the transport this fake stands in for, purely so a failure
	// says which side diverged.
	label string

	commands map[string]fakeResult
	files    map[string]fakeResult

	// renderer mimics the transport's own argv handling. The SSH fake runs its
	// argv through renderArgv and back, so a command that the real SSHRunner
	// would refuse to render also fails here.
	renderer func(argv []string) (string, error)

	mu   sync.Mutex
	seen []string
}

type fakeResult struct {
	stdout string
	stderr string
	exit   int
	err    error
}

// newFakeLocal returns a fake standing in for LocalRunner: argv is passed
// through untouched, as exec.Command does.
func newFakeLocal() *fakeRunner {
	return &fakeRunner{
		label:    "local",
		commands: map[string]fakeResult{},
		files:    map[string]fakeResult{},
		renderer: func(argv []string) (string, error) { return strings.Join(argv, " "), nil },
	}
}

// newFakeSSH returns a fake standing in for SSHRunner: argv goes through the
// REAL renderArgv, so a quoting rule that would break on the wire breaks here.
func newFakeSSH() *fakeRunner {
	return &fakeRunner{
		label:    "ssh",
		commands: map[string]fakeResult{},
		files:    map[string]fakeResult{},
		renderer: func(argv []string) (string, error) {
			if _, err := renderArgv(argv); err != nil {
				return "", err
			}
			return strings.Join(argv, " "), nil
		},
	}
}

func (f *fakeRunner) cmd(argv []string, stdout string) *fakeRunner {
	f.commands[strings.Join(argv, " ")] = fakeResult{stdout: stdout}
	return f
}

func (f *fakeRunner) cmdExit(argv []string, exit int, stderr string) *fakeRunner {
	f.commands[strings.Join(argv, " ")] = fakeResult{exit: exit, stderr: stderr}
	return f
}

func (f *fakeRunner) file(path, content string) *fakeRunner {
	f.files[path] = fakeResult{stdout: content}
	return f
}

func (f *fakeRunner) missingFile(path string) *fakeRunner {
	f.files[path] = fakeResult{err: fmt.Errorf("open %s: no such file or directory", path)}
	return f
}

func (f *fakeRunner) Run(_ context.Context, argv []string) ([]byte, []byte, int, error) {
	key, err := f.renderer(argv)
	if err != nil {
		return nil, nil, -1, err
	}
	f.mu.Lock()
	f.seen = append(f.seen, key)
	f.mu.Unlock()

	res, ok := f.commands[key]
	if !ok {
		// An unscripted command behaves like a program that is not installed:
		// the collector's own "try the next package manager" logic then runs
		// for real, rather than being bypassed by a helpful default.
		return nil, []byte("command not found"), 127, nil
	}
	return []byte(res.stdout), []byte(res.stderr), res.exit, res.err
}

func (f *fakeRunner) ReadFile(_ context.Context, path string) ([]byte, error) {
	f.mu.Lock()
	f.seen = append(f.seen, "read "+path)
	f.mu.Unlock()

	res, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("open %s: no such file or directory", path)
	}
	if res.err != nil {
		return nil, res.err
	}
	return []byte(res.stdout), nil
}

// ran reports whether a command was issued, so a test can assert that the
// collector actually ASKED rather than only that it parsed.
func (f *fakeRunner) ran(argv []string) bool {
	key := strings.Join(argv, " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.seen {
		if s == key {
			return true
		}
	}
	return false
}

// fixture reads a testdata file.
func fixture(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("fixture %v: %v", parts, err)
	}
	return string(b)
}

// scriptUbuntu loads a complete, realistic Ubuntu host into a fake runner.
//
// It is a function rather than a literal so the parity test can build TWO
// runners from one source of truth: if local and remote were scripted
// separately, a difference between them would be a difference in the test
// rather than in the code.
func scriptUbuntu(t *testing.T, f *fakeRunner) *fakeRunner {
	t.Helper()

	f.cmd([]string{"uname", "-s"}, "Linux\n")
	f.cmd(linuxCmdKernel, "5.15.0-113-generic\n")
	f.cmd(linuxCmdNodename, "app-01\n")
	f.cmd(linuxCmdFQDN, "app-01.example.net\n")

	f.file(linuxOSReleasePath, fixture(t, "linux", "os-release-ubuntu"))

	f.file(linuxDMIPaths["vendor"], "Dell Inc.\n")
	f.file(linuxDMIPaths["model"], "PowerEdge R650\n")
	f.file(linuxDMIPaths["serial"], "7BQ1EX3\n")
	f.file(linuxDMIPaths["uuid"], "4c4c4544-0042-3110-8052-b7c04f573233\n")
	f.file(linuxDMIPaths["firmware"], "1.12.2\n")

	f.cmd(linuxCmdIPJ, fixture(t, "linux", "ip-j-addr.json"))
	f.cmd(linuxCmdDpkg, fixture(t, "linux", "dpkg-query.txt"))
	f.cmd(linuxCmdSS, fixture(t, "linux", "ss-ltnup.txt"))

	// /etc/ssl/certs holds the one real bundle behind its symlink farm;
	// /etc/pki/tls/certs does not exist on a Debian derivative.
	f.cmd(certFindArgv("/etc/ssl/certs"), "/etc/ssl/certs/ca-certificates.crt\n")
	f.cmdExit(certFindArgv("/etc/pki/tls/certs"), 1, "find: '/etc/pki/tls/certs': No such file or directory")
	f.file("/etc/ssl/certs/ca-certificates.crt", fixture(t, "linux", "ca-certificates.crt"))

	return f
}

// certFindArgv rebuilds the argv listCertFiles issues, so the script and the
// implementation cannot drift.
func certFindArgv(path string) []string {
	argv := []string{"find", path, "-maxdepth", "1", "-type", "f", "("}
	for i, ext := range certStoreFileExtensions {
		if i > 0 {
			argv = append(argv, "-o")
		}
		argv = append(argv, "-name", ext)
	}
	return append(argv, ")")
}

// fixedNow is the collection timestamp every golden test uses, so a Report is
// byte-stable and the parity comparison is about the collection rather than
// about the clock.
func fixedNow() time.Time {
	return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
}
