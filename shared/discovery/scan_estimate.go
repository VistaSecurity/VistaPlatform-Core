package discovery

// The preview of a scan-plan job ( WP3b): POST /discovery/jobs with
// `dry_run: true` runs the whole creation path — validation, target
// authorization, the per-target external cap, Auto routing, the budget — and
// stops before anything is written. What it returns is a ScanPreview: the plan
// the real create would store, a time estimate, and whether the person still
// has to confirm external targets. The type lives here, beside ScanPlan, so
// cluster-sensor-service (which builds it), inventory-service (which relays
// it) and the OpenAPI contract cannot disagree about the shape.

import "fmt"

// ScanPreview is the answer to a dry run.
type ScanPreview struct {
	// Plan is the plan a real create of the same request would store.
	Plan ScanPlan `json:"plan"`
	// Estimate is how big and how long, roughly. See EstimateScan.
	Estimate ScanEstimate `json:"estimate"`
	// ConfirmationRequired is true when the request names targets outside the
	// tenant's registered networks and does not carry
	// external_targets_confirmed: a real create would answer 422
	// external_targets_unconfirmed. The plan already shows the downgrades that
	// apply once confirmed.
	ConfirmationRequired bool `json:"confirmation_required"`
	// ExternalTargets lists those targets (always an array, empty when none).
	ExternalTargets []PreviewExternalTarget `json:"external_targets"`
}

// PreviewExternalTarget is a target outside the registered networks and the
// addresses it names (a hostname's resolved, and pinned, addresses; a
// literal's own value).
type PreviewExternalTarget struct {
	Target    string   `json:"target"`
	Addresses []string `json:"addresses"`
}

// ScanEstimate is a rough size and duration for a plan. The seconds are an
// honest RANGE, not a prediction: the plan does not know how many addresses
// are up or how the network answers, and the estimate says so in Basis.
type ScanEstimate struct {
	// Probes is the plan's estimated probe count (Σ addresses × (TCP + UDP
	// ports)), the number the budget is checked against.
	Probes uint64 `json:"probes"`
	// Addresses is how many addresses the plan's targets name together.
	Addresses uint64 `json:"addresses"`
	// SecondsBest and SecondsWorst bound the TCP connect scan, in whole
	// seconds rounded up; see EstimateScan for the formulas. Both are 0 for a
	// plan with no TCP ports (a UDP-only custom scan), whose UDP probing is
	// paced separately and not estimated.
	SecondsBest  uint64 `json:"seconds_best"`
	SecondsWorst uint64 `json:"seconds_worst"`
	// Basis says in one plain sentence what the range assumes.
	Basis string `json:"basis"`
}

// measuredPortsPerSecond is the engine's recorded connect-scan throughput per
// pace when every probe is answered at once (open or refused), on loopback,
// from BenchmarkScanLoopback (shared/discovery/scan_bench_test.go;: ≈
// 33.6 k a second at the normal pace, ≈ 82 k at fast). Loopback has no latency
// and no loss, and a faster machine measured more, so these are conservative
// ceilings, not network measurements.
//
// Polite has no figure of its own: its pause between batches (BatchDelay)
// bounds it long before the engine does, so it takes the normal figure as the
// ceiling and EstimateScan applies the pause. (BenchmarkScanLoopback at polite
// measures ≈ 160 ports/s — one host's 16 ports per 100 ms — which is that pause,
// not the engine.)
var measuredPortsPerSecond = map[Pace]uint64{
	PacePolite: 33_600,
	PaceNormal: 33_600,
	PaceFast:   82_000,
}

// EstimateScan sizes a plan. Both bounds cover the TCP connect scan only;
// UDP is paced separately (a datagram per host at a fixed rate, each probe
// waiting for its answer) and is counted in Probes but not in the seconds.
//
// Let, for the plan's pace profile (PaceProfile), G = GlobalConcurrency,
// P = PerHostConcurrency, T = ConnectTimeout and D = BatchDelay; H = floor(G/P)
// hosts that can be scanned at once; and for each target t, A = its addresses
// and N = its planned TCP ports. A host's ports go in ceil(N/P) batches.
//
//   - Best case: every address is up and every probe is answered at once, so
//     the scan is limited by the engine's throughput R
//     (measuredPortsPerSecond) and, at a pace with a pause between batches
//     (polite), by that pause:
//
//     seconds_best = ceil( max( Σ A·N / R,
//     Σ A·ceil(N/P) · D / min(H, Σ A) ) )
//
//   - Worst case: every address is up but silently drops every probe, so
//     every batch waits out the connect timeout and the pause. One host takes
//     ceil(N/P) · (T+D); H hosts run at once. This is the formula in
//     PaceProfile's documentation, spread over those hosts:
//
//     seconds_worst = ceil( max( Σ A · ceil(N/P) · (T+D) / H,
//     the slowest single host ) )
//
//     which is never below seconds_best: the slowest rate a pace allows
//     (TestEstimateScan_RangeIsOrdered) is far under the engine's.
//
// Neither bound models the liveness pass, which usually REMOVES most addresses
// of an empty range before any port is probed (so a sparse range finishes well
// under both), nor the process-wide connection budget a small host may impose,
// nor round-trip time on a distant network. Everything saturates rather than
// overflows, and the seconds are whole seconds rounded up.
func EstimateScan(plan ScanPlan) (ScanEstimate, error) {
	prof, err := plan.Pace.Profile()
	if err != nil {
		return ScanEstimate{}, err
	}
	rate := measuredPortsPerSecond[plan.Pace]

	est := ScanEstimate{Probes: plan.EstimatedProbes}
	perHost := uint64(prof.PerHostConcurrency)
	unitMillis := uint64((prof.ConnectTimeout + prof.BatchDelay).Milliseconds())
	delayMillis := uint64(prof.BatchDelay.Milliseconds())
	var tcpProbes, batches, worstHostMillis, slowestHostMillis uint64
	for _, t := range plan.Targets {
		est.Addresses = saturatingAdd(est.Addresses, t.Addresses)
		n := uint64(t.TCPPortCount)
		tcpProbes = saturatingAdd(tcpProbes, saturatingMul(t.Addresses, n))
		hostBatches := ceilDiv(n, perHost)
		batches = saturatingAdd(batches, saturatingMul(t.Addresses, hostBatches))
		oneHost := saturatingMul(hostBatches, unitMillis)
		if t.Addresses > 0 && oneHost > slowestHostMillis {
			slowestHostMillis = oneHost
		}
		worstHostMillis = saturatingAdd(worstHostMillis, saturatingMul(t.Addresses, oneHost))
	}

	hostsAtOnce := uint64(prof.GlobalConcurrency / prof.PerHostConcurrency)
	if hostsAtOnce < 1 {
		hostsAtOnce = 1
	}
	best := ceilDiv(tcpProbes, rate)
	if delayMillis > 0 {
		active := hostsAtOnce
		if est.Addresses < active {
			active = est.Addresses
		}
		if paused := ceilDiv(ceilDiv(saturatingMul(batches, delayMillis), active), 1000); paused > best {
			best = paused
		}
	}
	worstMillis := ceilDiv(worstHostMillis, hostsAtOnce)
	if slowestHostMillis > worstMillis {
		worstMillis = slowestHostMillis
	}
	est.SecondsBest, est.SecondsWorst = best, ceilDiv(worstMillis, 1000)
	est.Basis = estimateBasis(plan.Pace, prof, rate, tcpProbes > 0, hostsAtOnce)
	return est, nil
}

func estimateBasis(pace Pace, prof PaceProfile, rate uint64, hasTCP bool, hostsAtOnce uint64) string {
	if !hasTCP {
		return "This scan sends only UDP probes, which are paced separately and not timed here; treat the probe count as the size of the job, and any time as unknown."
	}
	return fmt.Sprintf("An estimate for the %s pace, not a promise: the fastest figure assumes every address answers at once (the engine's recorded rate is about %s connection attempts a second on loopback), the slowest assumes every address is up but drops every probe so each batch waits out the %s connect timeout, %d host(s) at a time; liveness checks usually remove many addresses before any port is probed, and UDP is paced separately and not counted.",
		pace, groupDigits(rate), prof.ConnectTimeout, hostsAtOnce)
}

func ceilDiv(a, b uint64) uint64 {
	if b == 0 {
		return 0
	}
	q := a / b
	if a%b != 0 {
		q++
	}
	return q
}

// NewScanPreview assembles a dry run's answer from a plan the creation path
// has already authorized, classified and budget-checked.
func NewScanPreview(plan ScanPlan, confirmationRequired bool, external []PreviewExternalTarget) (ScanPreview, error) {
	est, err := EstimateScan(plan)
	if err != nil {
		return ScanPreview{}, err
	}
	if external == nil {
		external = []PreviewExternalTarget{}
	}
	return ScanPreview{Plan: plan, Estimate: est, ConfirmationRequired: confirmationRequired, ExternalTargets: external}, nil
}
