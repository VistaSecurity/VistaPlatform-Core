package discovery

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func planFor(t *testing.T, depth ScanDepth, pace Pace, targets ...PlanTargetInput) ScanPlan {
	t.Helper()
	spec, err := ResolveJobRequest(JobRequestFields{ScanDepth: string(depth), Pace: string(pace)})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildScanPlan(spec.Spec, nil, targets)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

var privateSlash24 = PlanTargetInput{Target: "10.20.30.0/24", Class: ClassPrivate}

// The formulas in EstimateScan's godoc, worked by hand for a Thorough /24
// (256 addresses × 65,535 TCP ports; the engine's recorded rate is 33.6 k a
// second at polite and normal, 82 k at fast):
//
//	normal: best  ceil(16,776,960 / 33,600)            = 500
//	        worst 256 hosts × ceil(65535/128)=512 batches × 1.5 s, 4 hosts at once
//	              = 196,608 s ÷ 4                       = 49,152
//	fast:   best  ceil(16,776,960 / 82,000)            = 205
//	        worst 256 × 128 batches × 1 s ÷ (2048/512=4) = 8,192
//	polite: best  the 100 ms pause bounds it, not the engine:
//	              256 × 4096 batches × 0.1 s ÷ 8 hosts  = 13,107.2 → 13,108
//	        worst 256 × 4096 × 2.1 s ÷ 8                = 275,251.2 → 275,252
func TestEstimateScan_ThoroughSlash24AtEachPace(t *testing.T) {
	for _, tc := range []struct {
		pace                Pace
		best, worst         uint64
		wantHostsAtOnceText string
	}{
		{PaceNormal, 500, 49_152, "4 host(s) at a time"},
		{PaceFast, 205, 8_192, "4 host(s) at a time"},
		{PacePolite, 13_108, 275_252, "8 host(s) at a time"},
	} {
		t.Run(string(tc.pace), func(t *testing.T) {
			plan := planFor(t, DepthThorough, tc.pace, privateSlash24)
			est, err := EstimateScan(plan)
			if err != nil {
				t.Fatal(err)
			}
			if est.SecondsBest != tc.best || est.SecondsWorst != tc.worst {
				t.Fatalf("seconds = %d..%d, want %d..%d", est.SecondsBest, est.SecondsWorst, tc.best, tc.worst)
			}
			if est.Addresses != 256 || est.Probes != 256*(65535+11) || est.Probes != plan.EstimatedProbes {
				t.Fatalf("addresses/probes = %d/%d, want 256 and the plan's %d", est.Addresses, est.Probes, plan.EstimatedProbes)
			}
			if !strings.Contains(est.Basis, tc.wantHostsAtOnceText) || !strings.Contains(est.Basis, string(tc.pace)+" pace") {
				t.Fatalf("basis does not name the pace's concurrency: %q", est.Basis)
			}
		})
	}
}

// One address at Quick (41 TCP ports): a connect scan is a moment at every
// pace, and the worst case is one batch waiting out the timeout.
func TestEstimateScan_SingleHostQuick(t *testing.T) {
	host := PlanTargetInput{Target: "10.20.30.40", Class: ClassPrivate}
	for _, tc := range []struct {
		pace        Pace
		best, worst uint64
	}{
		{PacePolite, 1, 7}, // 3 batches × (2 s + 100 ms) = 6.3 s → 7
		{PaceNormal, 1, 2}, // 1 batch × 1.5 s → 2
		{PaceFast, 1, 1},   // 1 batch × 1 s
	} {
		est, err := EstimateScan(planFor(t, DepthQuick, tc.pace, host))
		if err != nil {
			t.Fatal(err)
		}
		if est.SecondsBest != tc.best || est.SecondsWorst != tc.worst || est.Addresses != 1 || est.Probes != 41 {
			t.Errorf("%s: %+v, want %d..%d seconds, 1 address, 41 probes", tc.pace, est, tc.best, tc.worst)
		}
	}
}

// The slowest single host bounds the worst case even when the pooled estimate
// is lower: one Thorough host cannot finish faster than its own batches, however
// many hosts the budget could run beside it.
func TestEstimateScan_SlowestHostBoundsWorstCase(t *testing.T) {
	plan := planFor(t, DepthThorough, PaceNormal, PlanTargetInput{Target: "10.0.0.1", Class: ClassPrivate})
	est, err := EstimateScan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// 512 batches × 1.5 s = 768 s, not 768 ÷ 4.
	if est.SecondsWorst != 768 {
		t.Fatalf("worst = %d, want 768 (one host's own batches)", est.SecondsWorst)
	}
}

// Targets with different depths pool: an external host capped to Standard and
// a private /30 at Thorough.
func TestEstimateScan_MixedDepthsPool(t *testing.T) {
	plan := planFor(t, DepthThorough, PaceNormal,
		PlanTargetInput{Target: "10.0.0.0/30", Class: ClassPrivate},
		PlanTargetInput{Target: "93.184.216.34", Class: ClassExternal})
	est, err := EstimateScan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Private: 4 hosts × 512 batches × 1.5 s = 3072 s. External at Standard
	// (1,364 ports): 1 host × ceil(1364/128)=11 batches × 1.5 s = 16.5 s. Pooled
	// over 4 hosts at once: (3072 + 16.5) / 4 = 772.1 s, above the slowest
	// single host (768 s) → 773.
	if est.SecondsWorst != 773 {
		t.Fatalf("worst = %d, want 773", est.SecondsWorst)
	}
	if est.Addresses != 5 {
		t.Fatalf("addresses = %d, want 5", est.Addresses)
	}
}

// Nothing overflows on the largest numbers the types can hold, and the range
// stays ordered.
func TestEstimateScan_SaturatesOnHugeInputs(t *testing.T) {
	huge := ScanPlan{
		Pace:            PaceFast,
		EstimatedProbes: math.MaxUint64,
		Targets: []PlanTarget{
			{Target: "::/0", Addresses: math.MaxUint64, TCPPortCount: 65535},
			{Target: "10.0.0.0/8", Addresses: math.MaxUint64, TCPPortCount: 65535},
		},
	}
	for _, pace := range []Pace{PacePolite, PaceNormal, PaceFast} {
		huge.Pace = pace
		est, err := EstimateScan(huge)
		if err != nil {
			t.Fatal(err)
		}
		if est.Addresses != math.MaxUint64 || est.Probes != math.MaxUint64 {
			t.Errorf("%s: addresses/probes = %d/%d, want saturated", pace, est.Addresses, est.Probes)
		}
		// 2^64-1 probes at the pace's recorded rate: a wrapped product would
		// fall far below this.
		if floor := ceilDiv(math.MaxUint64, measuredPortsPerSecond[pace]); est.SecondsBest < floor || est.SecondsWorst < est.SecondsBest {
			t.Errorf("%s: seconds %d..%d, want best >= %d and an ordered range (wrapped?)", pace, est.SecondsBest, est.SecondsWorst, floor)
		}
	}
}

// The worst case is never below the best, over a spread of shapes.
func TestEstimateScan_RangeIsOrdered(t *testing.T) {
	for _, depth := range []ScanDepth{DepthQuick, DepthStandard, DepthThorough} {
		for _, pace := range []Pace{PacePolite, PaceNormal, PaceFast} {
			for _, target := range []string{"10.0.0.1", "10.0.0.0/28", "10.0.0.0/20"} {
				est, err := EstimateScan(planFor(t, depth, pace, PlanTargetInput{Target: target, Class: ClassPrivate}))
				if err != nil {
					t.Fatal(err)
				}
				if est.SecondsBest == 0 || est.SecondsWorst < est.SecondsBest {
					t.Errorf("%s %s %s: %d..%d", depth, pace, target, est.SecondsBest, est.SecondsWorst)
				}
			}
		}
	}
}

// A UDP-only custom scan has no TCP connect scan to time: it reports its probe
// count, no invented duration, and says why.
func TestEstimateScan_UDPOnlyHasNoTime(t *testing.T) {
	spec, err := ResolveJobRequest(JobRequestFields{ScanDepth: "custom", UDPPorts: "500,4500"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildScanPlan(spec.Spec, nil, []PlanTargetInput{{Target: "10.0.0.0/29", Class: ClassPrivate}})
	if err != nil {
		t.Fatal(err)
	}
	est, err := EstimateScan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if est.Probes != 16 || est.SecondsBest != 0 || est.SecondsWorst != 0 || !strings.Contains(est.Basis, "only UDP probes") {
		t.Fatalf("estimate = %+v", est)
	}
}

// The basis states what the range assumes — the three caveats the person must
// not miss.
func TestEstimateScan_BasisSaysWhatItAssumes(t *testing.T) {
	est, err := EstimateScan(planFor(t, DepthStandard, PaceNormal, privateSlash24))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"not a promise", "liveness checks usually remove many addresses", "UDP is paced separately", "1.5s connect timeout", "33,600"} {
		if !strings.Contains(est.Basis, want) {
			t.Errorf("basis lacks %q: %s", want, est.Basis)
		}
	}
	if strings.Count(est.Basis, ". ") != 0 || !strings.HasSuffix(est.Basis, ".") {
		t.Errorf("basis is not one sentence: %s", est.Basis)
	}
}

func TestEstimateScan_UnknownPaceIsAnError(t *testing.T) {
	_, err := EstimateScan(ScanPlan{Pace: "warp"})
	if err == nil {
		t.Fatal("an unknown pace was estimated")
	}
}

// A preview's lists are always arrays, never null, so a client can iterate
// them without a guard.
func TestNewScanPreview_ListsAreArrays(t *testing.T) {
	preview, err := NewScanPreview(planFor(t, DepthQuick, PaceNormal, privateSlash24), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(preview)
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["external_targets"]) != "[]" || string(got["confirmation_required"]) != "false" {
		t.Fatalf("preview = %s", raw)
	}
	for _, key := range []string{"plan", "estimate", "confirmation_required", "external_targets"} {
		if _, ok := got[key]; !ok {
			t.Errorf("preview has no %q: %s", key, raw)
		}
	}
	if _, err := NewScanPreview(ScanPlan{Pace: "warp"}, false, nil); err == nil {
		t.Error("a plan with an unknown pace was previewed")
	}
}

// dry_run has nothing to preview on the legacy shape: it is refused, naming
// why, in the one function both services call.
func TestResolveJobRequest_DryRunNeedsAScanPlan(t *testing.T) {
	for _, f := range []JobRequestFields{
		{Protocols: []string{"TLS"}, Ports: []int{443}, DryRun: true},
		{OTProbeProtocols: []string{"Modbus"}, DryRun: true},
	} {
		_, err := ResolveJobRequest(f)
		var reqErr *ScanRequestError
		if !errors.As(err, &reqErr) || !strings.Contains(err.Error(), "dry_run previews a scan-depth request") {
			t.Errorf("%+v: err = %v, want a dry_run refusal", f, err)
		}
	}
	// And the same requests without dry_run, and a scan-plan one with it, pass.
	if _, err := ResolveJobRequest(JobRequestFields{Protocols: []string{"TLS"}, Ports: []int{443}}); err != nil {
		t.Errorf("legacy without dry_run refused: %v", err)
	}
	if shape, err := ResolveJobRequest(JobRequestFields{ScanDepth: "quick", DryRun: true}); err != nil || !shape.Plan {
		t.Errorf("scan-plan dry run = %+v, %v", shape, err)
	}
	if shape, err := ResolveJobRequest(JobRequestFields{DryRun: true}); err != nil || !shape.Plan {
		t.Errorf("bare dry run (defaults to standard) = %+v, %v", shape, err)
	}
}
