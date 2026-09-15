package riskbands_test

// One ladder, and a scanner that says so.
//
// The band boundaries were hand-copied into eight SQL queries plus a Go
// function once before, and they drifted: the summary and facet counters banded
// High at >= 70 while every badge banded it at >= 60, so an asset scoring 60–69
// rendered "High", was counted "Medium", and was dropped by the "High" filter.
// The table was built to end that — and then three counters in
// device-interrogation-service wrote `risk_score >= 70` by hand anyway, because
// the table lived in another module's `internal` package and they could not
// reach it.
//
// So the guard is not "the table exists". It is "nobody has written the numbers
// out again".

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A comparison of `risk_score` against a band BOUNDARY.
//
// Two deliberate narrowings, because a guard that is too strict is the same bug
// pointed the other way:
//
//   - only `risk_score`, not every `score`. A CVSS score in the NVD feed, a
//     tenant HEALTH score and an RBAC risk score are different 0–100 metrics
//     with their own published ladders; making them use the asset band table
//     would be a wrong answer, not a consistent one.
//   - not `… 0`. `risk_score > 0` is the "has anything scored this at all?"
//     test — the NOT ASSESSED distinction — and is not a band boundary. Zero
//     is the one number that means something other than a threshold.
var handWrittenLadder = regexp.MustCompile(`\brisk_score\s*(?:>=|>|<=|<)\s*(?:[1-9]\d*)`)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("go.work not found above the working directory; not a full checkout")
	return ""
}

func TestNobodyWritesTheRiskLadderOutByHand(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	scanned := 0

	for _, sub := range []string{"services", "shared"} {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Generated registries and vendored trees are not hand-written.
				if d.Name() == "node_modules" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			// riskbands itself is where the numbers legitimately live.
			if strings.HasPrefix(rel, filepath.Join("shared", "riskbands")) {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			scanned++
			for i, line := range strings.Split(string(body), "\n") {
				trimmed := strings.TrimSpace(line)
				// A comment explaining the rule is not a violation of it.
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "--") {
					continue
				}
				if handWrittenLadder.MatchString(line) {
					offenders = append(offenders, rel+":"+itoa(i+1)+"  "+trimmed)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	if scanned == 0 {
		t.Fatal("scanned no Go files; the walker has stopped walking, which is the one way " +
			"this guard passes over nothing")
	}
	for _, o := range offenders {
		t.Errorf("a risk threshold is written out by hand:\n  %s\n"+
			"Use riskbands.MustRiskAtLeastSQL / MustRiskBandSQL. Two copies of a boundary is how "+
			"an asset came to render High and be counted Medium.", o)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
