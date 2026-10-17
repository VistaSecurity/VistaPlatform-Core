package dcimfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Environment variables the budget helper reads.
const (
	// BudgetsEnv set to "enforce" makes AssertUnder fail the test on a breach.
	// Unset (PR gate, local runs) a breach is only logged.
	BudgetsEnv = "DCIM_BUDGETS"
	// ArtifactsEnv names the directory the JSON report is written into.
	ArtifactsEnv = "TEST_ARTIFACTS_DIR"
	// ReportFile is the report's file name inside ArtifactsEnv.
	ReportFile = "dcim-budgets.json"
)

// BudgetRecord is one measurement in the report.
type BudgetRecord struct {
	Name       string  `json:"name"`
	DurationMS float64 `json:"duration_ms"`
	BudgetMS   float64 `json:"budget_ms"`
	Over       bool    `json:"over"`
}

var reportMu sync.Mutex

// AssertUnder records name, d against budget and fails the test when d exceeds
// budget AND DCIM_BUDGETS=enforce. Budgets are informative on PRs (a loaded
// shared runner must not make the gate flaky) and enforced in the nightly job.
// With TEST_ARTIFACTS_DIR set, the measurement is appended to dcim-budgets.json
// there so CI can collect it.
func AssertUnder(t testing.TB, name string, d, budget time.Duration) {
	t.Helper()
	over := d > budget
	rec := BudgetRecord{Name: name, DurationMS: ms(d), BudgetMS: ms(budget), Over: over}
	if dir := os.Getenv(ArtifactsEnv); dir != "" {
		if err := appendReport(dir, rec); err != nil {
			t.Logf("dcimfixture: write budget report: %v", err)
		}
	}
	if !over {
		t.Logf("budget %s: %v (budget %v)", name, d, budget)
		return
	}
	if os.Getenv(BudgetsEnv) == "enforce" {
		t.Fatalf("budget %s exceeded: %v > %v", name, d, budget)
		return
	}
	t.Logf("budget %s exceeded (informative; set %s=enforce to fail): %v > %v", name, BudgetsEnv, d, budget)
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func appendReport(dir string, rec BudgetRecord) error {
	reportMu.Lock()
	defer reportMu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, ReportFile)
	var all []BudgetRecord
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &all) // a corrupt report is replaced, not fatal
	}
	all = append(all, rec)
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
