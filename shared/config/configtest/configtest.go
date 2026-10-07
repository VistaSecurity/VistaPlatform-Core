// Package configtest boots a service's real config loader in a child process.
//
// The production secret guard ends the process (log.Fatalf), so an in-process
// test cannot observe it, and a test of the guard HELPER proves nothing about
// whether a service's loader calls it (the failure shape in CLAUDE.md, "A fix
// can compile, pass its tests, and still do nothing in production"). A service
// wires this in two lines:
//
//	func TestMain(m *testing.M) { configtest.Main(m, func() { Load() }) }
//
//	res := configtest.Run(t, map[string]string{"ENV": "production", ...})
//
// Main dispatches on a marker variable: in the child it runs the loader and
// exits 0 if the loader returned, so a non-zero exit means the loader refused
// to start. The child gets a clean environment containing only what the test
// passes, so nothing leaks in from the developer's shell or CI.
package configtest

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"testing"
)

const childMarker = "VISTA_CONFIGTEST_CHILD"

// Main is the TestMain body of a package that uses Run. In the child process it
// calls load and exits 0; otherwise it runs the package's tests.
func Main(m *testing.M, load func()) {
	if os.Getenv(childMarker) == "1" {
		load()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Result is what the child did.
type Result struct {
	// Started is true when the loader returned (exit 0).
	Started bool
	// ExitCode is the child's exit status.
	ExitCode int
	// Output is the child's combined stdout and stderr (log.Fatal writes stderr).
	Output string
}

// Run executes the loader in a child whose entire environment is env (plus the
// marker). It fails the test only if the child cannot be launched at all.
func Run(t *testing.T, env map[string]string) Result {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = []string{childMarker + "=1"}
	if p := os.Getenv("PATH"); p != "" {
		cmd.Env = append(cmd.Env, "PATH="+p)
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	res := Result{Output: out.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
		res.Started = true
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		t.Fatalf("run child: %v", err)
	}
	return res
}

// Wiring describes a service for CheckSecretWiring.
type Wiring struct {
	// Env is whatever else Load needs to succeed (database URLs and the like).
	// It must not set ENV or any secret; CheckSecretWiring owns those.
	Env map[string]string
	// Required is the service's SecretSpec.Required.
	Required []string
	// VerifiesJWT is the service's SecretSpec.VerifiesJWT.
	VerifiesJWT bool
}

const strong = "0123456789abcdef0123456789abcdef0123456789abcdef" // 48 bytes

// CheckSecretWiring drives the service's real loader (via Main/Run) through the
// production secret contract and fails if any behaviour is missing:
//
//   - production, strong secrets: starts
//   - production, each Required secret missing or short: refuses, naming it
//   - production, JWT_SECRET present but short (verifiers): refuses, naming it
//   - production, JWT_SECRET absent with ES256 keys configured (verifiers): starts
//   - production, JWT_SECRET absent and no ES256 keys (verifiers): refuses
//   - development, short secrets: starts, with a warning naming the variable
func CheckSecretWiring(t *testing.T, w Wiring) {
	t.Helper()

	base := func(extra map[string]string, drop ...string) map[string]string {
		env := map[string]string{"ENV": "production"}
		for k, v := range w.Env {
			env[k] = v
		}
		for _, name := range w.Required {
			env[name] = strong
		}
		if w.VerifiesJWT {
			env["JWT_SECRET"] = strong
		}
		for _, d := range drop {
			delete(env, d)
		}
		for k, v := range extra {
			env[k] = v
		}
		return env
	}
	refuses := func(t *testing.T, env map[string]string, names ...string) {
		t.Helper()
		res := Run(t, env)
		if res.Started {
			t.Fatalf("loader started but must refuse; output:\n%s", res.Output)
		}
		if res.ExitCode == 0 {
			t.Fatalf("loader failed without an exit status; output:\n%s", res.Output)
		}
		for _, n := range names {
			if !bytes.Contains([]byte(res.Output), []byte(n)) {
				t.Fatalf("refusal must name %s; output:\n%s", n, res.Output)
			}
		}
		if bytes.Contains([]byte(res.Output), []byte(strong)) {
			t.Fatalf("output leaks a secret value:\n%s", res.Output)
		}
	}
	starts := func(t *testing.T, env map[string]string) Result {
		t.Helper()
		res := Run(t, env)
		if !res.Started {
			t.Fatalf("loader refused to start (exit %d); output:\n%s", res.ExitCode, res.Output)
		}
		return res
	}

	t.Run("production with strong secrets starts", func(t *testing.T) {
		starts(t, base(nil))
	})
	for _, name := range w.Required {
		name := name
		t.Run("production refuses missing "+name, func(t *testing.T) {
			refuses(t, base(nil, name), name)
		})
		t.Run("production refuses short "+name, func(t *testing.T) {
			refuses(t, base(map[string]string{name: "too-short"}), name)
		})
	}
	if w.VerifiesJWT {
		t.Run("production refuses a present but short JWT_SECRET", func(t *testing.T) {
			refuses(t, base(map[string]string{"JWT_SECRET": "too-short"}), "JWT_SECRET")
		})
		t.Run("production starts without JWT_SECRET when ES256 is configured", func(t *testing.T) {
			starts(t, base(map[string]string{"JWT_JWKS_URL": "http://auth-service:8080/.well-known/jwks.json"}, "JWT_SECRET"))
		})
		t.Run("production refuses without JWT_SECRET and without ES256", func(t *testing.T) {
			refuses(t, base(nil, "JWT_SECRET"), "JWT_SECRET")
		})
	}
	t.Run("development warns about a short secret and starts", func(t *testing.T) {
		if len(w.Required) == 0 {
			t.Skip("service has no required secrets")
		}
		env := base(map[string]string{"ENV": "development", w.Required[0]: "short"})
		res := starts(t, env)
		if !bytes.Contains([]byte(res.Output), []byte(w.Required[0])) || !bytes.Contains([]byte(res.Output), []byte("WARNING")) {
			t.Fatalf("development must warn naming %s; output:\n%s", w.Required[0], res.Output)
		}
	})
}
