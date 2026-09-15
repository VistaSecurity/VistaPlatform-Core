package testdb_test

// One loopback ADDRESS per suite, whenever a test binds a fixed well-known port.
//
// A fixture that has to bind a real well-known port cannot pick a free one: the
// planner under test refuses to invent a port, so the listener has to be on 502 /
// 47808 / 44818 or the dispatch is never exercised. Two suites both binding
// 127.0.0.1 on the same port is then a flake by construction — `make
// test-parallel`, `make test-race` and `make test-coverage` all run those
// packages at once — and worse than a flake: one suite's probes reach the other's
// listener and its assertions are answered by the wrong socket.
//
// The whole 127.0.0.0/8 range is loopback, so the fix is free: each suite binds
// its own address (sensor/internal/discovery uses 127.0.0.2,
// cluster-sensor-service/internal/services uses 127.0.0.3) and gets its own
// socket and its own datagrams.
//
// The rule is only checkable if something checks it — the comment on the first
// suite to move said exactly this and the second suite stayed on 127.0.0.1
// anyway. Mutation-proven: point either suite's fixture host back at 127.0.0.1
// and this test names the file.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// wellKnownPorts are the ports a fixture in this repo binds LITERALLY because the
// protocol dispatch keys on them. Extend when a new protocol fixture appears.
// 502 / 4840 / 44818 / 47808 are the four the product itself keys dispatch on
// (`cryptoPortProtocols` in shared/discovery/sweep.go), so a fixture for any of
// them has no choice about the port; the rest are protocols a prober may grow.
var wellKnownPorts = []string{"102", "161", "502", "623", "2404", "4840", "20000", "44818", "47808"}

var bindsSocket = regexp.MustCompile(`net\.(Listen|ListenPacket|ListenTCP|ListenUDP)\(`)

// bindsFixedPort reports whether src binds a socket on a port it NAMES. An
// ephemeral bind (`"127.0.0.1:0"`) is exempt: the kernel hands out a free port, so
// two suites doing it never collide, and such files legitimately mention
// well-known port numbers as probe arguments (shared/discovery/probe_ot_test.go
// calls probeModbus(..., 502) against an ephemeral listener).
func bindsFixedPort(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		if bindsSocket.MatchString(line) && !strings.Contains(line, `:0"`) {
			return true
		}
	}
	return false
}

func TestTestFixturesBindTheirOwnLoopbackAddress(t *testing.T) {
	root := repoRoot(t)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable trees are not this guard's business
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		src := string(b)
		if !bindsFixedPort(src) {
			// Either it binds nothing, or every bind asks the kernel for a free
			// port (`:0`) — which cannot collide with anything.
			return nil
		}
		port, ok := mentionsWellKnownPort(src)
		if !ok {
			return nil // a fixed port of the test's own choosing, not a shared well-known one
		}
		if !strings.Contains(src, `"127.0.0.1"`) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		t.Errorf("%s binds a socket, uses the well-known port %s, and names 127.0.0.1: "+
			"give this suite its own loopback address (127.0.0.N) instead. Two suites on one "+
			"127.0.0.1:%s collide under `make test-parallel` — and the loser's probes are answered "+
			"by the other suite's listener, which is worse than a bind failure.", rel, port, port)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// mentionsWellKnownPort reports the first well-known port that appears in src as a
// bare decimal token (so 47808 matches and 447808 or "x47808" do not).
func mentionsWellKnownPort(src string) (string, bool) {
	for _, p := range wellKnownPorts {
		if regexp.MustCompile(`\b` + p + `\b`).MatchString(src) {
			return p, true
		}
	}
	return "", false
}
