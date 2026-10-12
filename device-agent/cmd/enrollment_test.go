package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
)

// The real main(), re-executed in a child process: enrollment ends in
// log.Fatal / os.Exit, and what matters is the ORDER of what main does — the
// writability check has to run before the key is sent, not merely exist.
const runMainEnv = "DEVICE_AGENT_TEST_RUN_MAIN"

func TestHelperRunMain(t *testing.T) {
	if os.Getenv(runMainEnv) != "1" {
		t.Skip("helper process for the enrollment tests")
	}
	args := strings.Split(os.Getenv("DEVICE_AGENT_TEST_ARGS"), "\n")
	os.Args = append([]string{"device-agent"}, args...)
	main()
}

func runAgentMain(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// A regression that runs the agent anyway blocks on its signal wait; the
	// deadline turns that into a failure instead of a hung test.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperRunMain$")
	cmd.Env = append(os.Environ(), runMainEnv+"=1", "DEVICE_AGENT_TEST_ARGS="+strings.Join(args, "\n"))
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the agent was still running after 20s — it did not stop on a failed enrollment:\n%s", out)
	}
	return string(out), err
}

// exitStatus is the child's exit status, or -1 if it did not exit on its own.
func exitStatus(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// registrationServer counts registration attempts and answers them the way the
// platform answers a spent key.
func registrationServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/agents/register") {
			hits.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"Registration key has already been used"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func writeAgentConfig(t *testing.T, dir, platformURL, dataPath string) string {
	t.Helper()
	path := filepath.Join(dir, "device-agent.yaml")
	body := "platform_url: " + platformURL + "\nregistration_key: REG-test\npoll_interval: 30s\ndata_path: \"" + dataPath + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere; the unwritable case cannot be built")
	}
}

// TestRegister_UnwritableDataPathSendsNothing is the console's manual steps run
// as an ordinary user: the default data path is root-owned. The key used to be
// spent on an enrollment the agent then could not save. Now nothing is sent.
func TestRegister_UnwritableDataPathSendsNothing(t *testing.T) {
	skipIfRoot(t)
	for _, mode := range []string{"-register", "auto-register"} {
		t.Run(mode, func(t *testing.T) {
			srv, hits := registrationServer(t)
			dir := t.TempDir()
			locked := filepath.Join(dir, "locked")
			if err := os.Mkdir(locked, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
			cfg := writeAgentConfig(t, dir, srv.URL, filepath.Join(locked, "data"))

			args := []string{"-config", cfg, "-interactive=false"}
			if mode == "-register" {
				args = append([]string{"-register"}, args...)
			}
			out, err := runAgentMain(t, args...)
			if err == nil {
				t.Fatalf("agent exited 0 with an unwritable data path:\n%s", out)
			}
			if n := hits.Load(); n != 0 {
				t.Fatalf("%d registration request(s) sent before discovering the data path is unwritable:\n%s", n, out)
			}
			if !strings.Contains(out, "registration key is still unused") {
				t.Fatalf("operator not told the key is still good:\n%s", out)
			}
			if got := exitStatus(err); got != exitNeedsOperator {
				t.Fatalf("exit status %d, want %d (a person has to fix this; the systemd unit must not restart it)", got, exitNeedsOperator)
			}
		})
	}
}

// TestRegister_RejectedKeyIsReportedAsRejected is the other polarity: with a
// writable data path the agent does reach the platform, and a refused key is
// reported in the words the installers stop on — and the agent exits instead
// of running unenrolled.
func TestRegister_RejectedKeyIsReportedAsRejected(t *testing.T) {
	for _, mode := range []string{"-register", "auto-register"} {
		t.Run(mode, func(t *testing.T) {
			srv, hits := registrationServer(t)
			dir := t.TempDir()
			cfg := writeAgentConfig(t, dir, srv.URL, filepath.Join(dir, "data"))

			args := []string{"-config", cfg, "-interactive=false"}
			if mode == "-register" {
				args = append([]string{"-register"}, args...)
			}
			out, err := runAgentMain(t, args...)
			if err == nil {
				t.Fatalf("agent exited 0 after a rejected registration:\n%s", out)
			}
			if n := hits.Load(); n != 1 {
				t.Fatalf("%d registration request(s), want 1 (err %v):\n%s", n, err, out)
			}
			if !strings.Contains(out, "Registration was REJECTED") {
				t.Fatalf("rejected key not reported as REJECTED:\n%s", out)
			}
			if strings.Contains(out, "Device agent started") {
				t.Fatalf("agent started polling with no enrollment:\n%s", out)
			}
			// The installer's unit lists this status in RestartPreventExitStatus;
			// any other status restarts the agent against the endpoint every 10s.
			if got := exitStatus(err); got != exitNeedsOperator {
				t.Fatalf("exit status %d after a rejected key, want %d", got, exitNeedsOperator)
			}
		})
	}
}

func TestCheckEnrollmentWritable(t *testing.T) {
	dir := t.TempDir()
	if err := checkEnrollmentWritable(filepath.Join(dir, "data"), filepath.Join(dir, "conf", "agent.yaml")); err != nil {
		t.Fatalf("writable paths refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "certs")); err != nil {
		t.Fatalf("certs directory not created: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "data", "certs"))
	if len(entries) != 0 {
		t.Fatalf("probe files left behind: %v", entries)
	}

	skipIfRoot(t)
	readOnlyConfig := filepath.Join(dir, "readonly.yaml")
	if err := os.WriteFile(readOnlyConfig, []byte("x: 1\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := checkEnrollmentWritable(filepath.Join(dir, "data"), readOnlyConfig); err == nil {
		t.Fatal("a config file the agent cannot rewrite was accepted")
	}
}

// A config file that cannot be parsed is fixed by a person, not by a restart.
func TestMalformedConfigExitsNeedsOperator(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "device-agent.yaml")
	if err := os.WriteFile(cfg, []byte("platform_url: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runAgentMain(t, "-config", cfg, "-interactive=false")
	if got := exitStatus(err); got != exitNeedsOperator {
		t.Fatalf("exit status %d for a malformed config, want %d:\n%s", got, exitNeedsOperator, out)
	}
}

// Only a REJECTION is permanent: an unreachable platform keeps exit 1 so the
// service manager's restart is the retry.
func TestRegistrationFailureExitCode(t *testing.T) {
	if got := registrationFailureExitCode(&api.RegistrationRejectedError{StatusCode: 400}); got != exitNeedsOperator {
		t.Errorf("rejected key: %d, want %d", got, exitNeedsOperator)
	}
	wrapped := fmt.Errorf("register: %w", &api.RegistrationRejectedError{StatusCode: 403})
	if got := registrationFailureExitCode(wrapped); got != exitNeedsOperator {
		t.Errorf("wrapped rejection: %d, want %d", got, exitNeedsOperator)
	}
	if got := registrationFailureExitCode(errors.New("connection refused")); got != 1 {
		t.Errorf("transient failure: %d, want 1", got)
	}
}
