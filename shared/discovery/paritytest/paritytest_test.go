package paritytest

import (
	"context"
	"testing"
	"time"
)

// TestParity_EngineAgainstGolden runs the shared engine against the fixture
// network and holds it to the ground truth. (The legacy executors it was once
// also compared with were deleted in WP5.)
func TestParity_EngineAgainstGolden(t *testing.T) {
	n := Start(t, EngineSuiteAddr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rows, elapsed, err := RunEngine(ctx, n.Addr, n.Ports(), nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Logf("engine scanned %d ports in %s", len(n.Ports()), elapsed)
	got := Collect(t, n, rows)
	LogResult(t, "engine", n, got)

	diffs := CompareGolden("engine", n, got)
	Report(t, diffs)
	CheckGaps(t, n, []string{"golden/engine"}, diffs)
}

// TestParity_EngineTiming measures the engine against a host of closed and
// silent ports. The engine takes no per-probe timeout from its caller, so this
// is its production timing.
func TestParity_EngineTiming(t *testing.T) {
	ports := TimingNetwork(t, EngineSuiteAddr, TimingClosedPorts, TimingSilentPorts)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rows, elapsed, err := RunEngine(ctx, EngineSuiteAddr, ports, nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Logf("TIMING engine (production settings): %d closed + %d silent ports in %s, %d row(s)",
		TimingClosedPorts, TimingSilentPorts, elapsed.Round(time.Millisecond), len(rows))
}
