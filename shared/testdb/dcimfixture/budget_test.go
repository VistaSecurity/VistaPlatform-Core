package dcimfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeTB records Fatalf instead of ending the goroutine.
type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Logf(string, ...any)   {}
func (f *fakeTB) Fatalf(string, ...any) { f.failed = true }

func TestAssertUnder_EnforcesOnlyUnderEnforceSwitch(t *testing.T) {
	cases := []struct {
		env        string
		d          time.Duration
		wantFailed bool
	}{
		{"", 300 * time.Millisecond, false},        // informative: over budget, not enforced
		{"warn", 300 * time.Millisecond, false},    // anything but "enforce" is informative
		{"enforce", 300 * time.Millisecond, true},  // enforced + over
		{"enforce", 100 * time.Millisecond, false}, // enforced + under
	}
	for _, c := range cases {
		t.Setenv(BudgetsEnv, c.env)
		t.Setenv(ArtifactsEnv, "")
		f := &fakeTB{}
		AssertUnder(f, "x", c.d, 200*time.Millisecond)
		if f.failed != c.wantFailed {
			t.Errorf("DCIM_BUDGETS=%q d=%v: failed=%v, want %v", c.env, c.d, f.failed, c.wantFailed)
		}
	}
}

func TestAssertUnder_WritesReport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(ArtifactsEnv, dir)
	t.Setenv(BudgetsEnv, "")
	AssertUnder(&fakeTB{}, "a", 10*time.Millisecond, 200*time.Millisecond)
	AssertUnder(&fakeTB{}, "b", 300*time.Millisecond, 200*time.Millisecond)
	b, err := os.ReadFile(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	var recs []BudgetRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Name != "a" || recs[0].Over || recs[1].Name != "b" || !recs[1].Over || recs[1].DurationMS != 300 {
		t.Fatalf("report = %+v", recs)
	}
}

func TestScale1IsDataModelSection12(t *testing.T) {
	s := Scale1()
	got := [6]int{s.Sites, s.Racks(), s.Assets(), s.Interfaces(), s.IPs(), s.Cables()}
	want := [6]int{500, 5000, 50000, 500000, 200000, 100000}
	if got != want || s.Prefixes() != 20000 {
		t.Fatalf("Scale1 = %v prefixes=%d, want %v / 20000", got, s.Prefixes(), want)
	}
	if AssetName(42, 7, 0) != "sw-0042-07-01" || RackName(42, 7) != "rack-0042-07" || InterfaceName(23) != "Gi1/0/24" {
		t.Fatal("stable names changed")
	}
}
