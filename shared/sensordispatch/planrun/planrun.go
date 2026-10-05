// Package planrun runs a planned discovery job on a tenant sensor (
// WP2b; holes H10, H16, H31): the sensor's counterpart of cluster-sensor's
// work-unit executor, on the same per-host pipeline
// (discovery.UnitEngine), reporting each host to the platform as it finishes.
//
// One run of one job:
//
//  1. Every target is expanded to the addresses this attempt scans — a range
//     through the same expansion the platform created its units with, a
//     hostname to the addresses it was authorized on (never resolved again),
//     minus the addresses the platform already has an answer for.
//  2. Each address passes the SENSOR's own rules (Config.Allow) before any
//     packet — the liveness probe included — and again immediately before
//     its port scan; every dial the engine makes goes through a dialer that
//     asks the same rules (the backstop for a rule that changes mid-host). An
//     address the rules refuse is reported failed, with the reason, unscanned.
//  3. Liveness, for range targets only, in chunks; an address that gave no
//     answer is reported done there and then.
//  4. The rest, UnitWorkers(pace) at a time: the shared engine (TCP scan with
//     the plan's ports and pace, OT serialization and the tarpit guard,
//     Identify with the plan's OT opt-in, ScanUDP), and the host's result is
//     reported before the worker takes the next host. Nothing is held past the
//     host that produced it: memory is bounded by the workers in flight, not
//     by the job.
//
// While it works it pings (an empty report) every PingInterval, so a host that
// takes hours still renews the job's progress lease. Any answer that says the
// job was cancelled or ended stops the run at once: the hosts in flight are
// abandoned and nothing more is reported.
//
// CGO-free and free of platform coupling: the standalone sensor imports it,
// and the platform's tests drive it against their fake networks.
package planrun

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// ErrJobStopped is what a Reporter returns (wrapped) when the platform answered
// that the job is cancelled or has ended, and what Run returns then.
var ErrJobStopped = errors.New("the platform stopped this discovery job")

// Reporter sends one progress report. An empty units is a ping. It returns an
// error wrapping ErrJobStopped when the answer says to stop.
type Reporter interface {
	Report(ctx context.Context, units []sensordispatch.UnitResult) error
}

// Config is what a run needs besides the plan.
type Config struct {
	// Allow is the sensor's own judgement of an address: nil error to scan
	// it. Required — a run without the sensor's rules does not start.
	Allow func(netip.Addr) error
	// Reporter delivers results and pings. Required.
	Reporter Reporter
	// Dialer is the network the engine dials (default: the system's). Every
	// dial passes Allow first, whatever Dialer is.
	Dialer discovery.Dialer
	// PingInterval is how often an empty report renews the lease (default
	// sensordispatch.PlanProgressInterval).
	PingInterval time.Duration
	// ReportAttempts and ReportBackoff bound how hard a host's result is
	// retried before it is given up as unreported (default 5, 2s doubling).
	// An unreported host is failed by the platform when the job completes,
	// and a Retry scans it again.
	ReportAttempts int
	ReportBackoff  time.Duration
	// Logf logs (default log.Printf).
	Logf func(format string, args ...interface{})
}

// Summary is what a run did, for the completion report.
type Summary struct {
	// Units is every address this attempt was to answer for.
	Units int
	// Done were scanned and reported; Failed were refused by this sensor's
	// rules or could not be scanned, and reported as such.
	Done   int
	Failed int
	// Unreported could not be delivered after every retry.
	Unreported int
}

// livenessChunk is how many addresses one liveness sweep call covers, as on
// the platform: enough to keep the pace's budget busy, small enough that
// results — and progress — move every few seconds.
const livenessChunk = 256

type work struct {
	target   *sensordispatch.PlanTargetWork
	addr     netip.Addr
	raw      string
	tcp      discovery.PortSet
	udp      []int
	liveness *discovery.LivenessResult
}

type runner struct {
	plan    sensordispatch.PlanPayload
	cfg     Config
	engine  *discovery.UnitEngine
	live    *discovery.Scanner
	stop    context.CancelCauseFunc
	summary struct {
		done, failed, unreported atomic.Int64
	}
}

// Run executes plan for jobID. It returns the summary and nil when every
// address was answered for; ErrJobStopped (wrapped) when the platform stopped
// the job; ctx's error when the caller cancelled; any other error when the
// plan could not be run at all (nothing was scanned).
func Run(ctx context.Context, plan sensordispatch.PlanPayload, cfg Config) (Summary, error) {
	if cfg.Allow == nil || cfg.Reporter == nil {
		return Summary{}, errors.New("a planned scan needs the sensor's address rules and a reporter")
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{}
	}
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = sensordispatch.PlanProgressInterval
	}
	if cfg.ReportAttempts <= 0 {
		cfg.ReportAttempts = 5
	}
	if cfg.ReportBackoff <= 0 {
		cfg.ReportBackoff = 2 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	var inputs []string
	for _, t := range plan.Targets {
		if t.Hostname() == "" {
			inputs = append(inputs, t.Target)
		}
	}
	// ExpandTargets truncates past its cap without a word: refuse a plan the
	// sensor could not expand completely rather than scan its front.
	if err := discovery.CheckTargetSizes(inputs); err != nil {
		return Summary{}, err
	}
	dialer := GuardedDialer(cfg.Dialer, cfg.Allow)
	engine, err := discovery.NewUnitEngine(plan.Pace, plan.OTProbeProtocols, nil, discovery.WithDialer(dialer))
	if err != nil {
		return Summary{}, fmt.Errorf("scan engine: %w", err)
	}
	live, err := discovery.NewLivenessScanner(plan.Pace, discovery.WithDialer(dialer))
	if err != nil {
		return Summary{}, fmt.Errorf("scan engine: %w", err)
	}

	rctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	r := &runner{plan: plan, cfg: cfg, engine: engine, live: live, stop: stop}

	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		r.ping(rctx)
	}()
	defer func() { stop(nil); <-pingDone }()

	sum := Summary{}
	var sweep, direct []work
	for i := range plan.Targets {
		t := &plan.Targets[i]
		tcp, _ := t.TCPPortSet() // validated by ParsePayload
		udpSet, _ := t.UDPPortSet()
		udp := udpSet.Ports()
		addrs := t.Addresses()
		if t.Hostname() != "" && len(t.PinnedAddresses) == 0 && len(addrs) == 0 && !contains(t.SkipAddresses, t.Target) {
			// A name with no addresses it was authorized on: the platform's
			// unit for it is the name itself. Never resolved here.
			addrs = []string{t.Target}
		}
		sum.Units += len(addrs)
		for _, raw := range addrs {
			a, err := netip.ParseAddr(raw)
			if err != nil {
				r.fail(rctx, t, raw, "not scanned: "+raw+" is not an address, and a planned scan never resolves names")
				continue
			}
			w := work{target: t, addr: a.Unmap(), raw: raw, tcp: tcp, udp: udp}
			if discovery.IsNetworkRange(t.Target) && tcp.Len() > 0 {
				sweep = append(sweep, w)
			} else {
				direct = append(direct, w)
			}
		}
	}

	err = r.livenessPhase(rctx, sweep, &direct)
	if err == nil {
		err = r.portPhase(rctx, direct)
	}
	sum.Done, sum.Failed, sum.Unreported = int(r.summary.done.Load()), int(r.summary.failed.Load()), int(r.summary.unreported.Load())
	if cause := context.Cause(rctx); err == nil && cause != nil && !errors.Is(cause, context.Canceled) {
		err = cause
	}
	if err == nil {
		err = ctx.Err()
	}
	return sum, err
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ping renews the lease until the run ends.
func (r *runner) ping(ctx context.Context) {
	t := time.NewTicker(r.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.cfg.Reporter.Report(ctx, nil); errors.Is(err, ErrJobStopped) {
				r.stop(err)
				return
			} else if err != nil && ctx.Err() == nil {
				r.cfg.Logf("discovery job progress ping failed (the job keeps running; the next ping retries): %v", err)
			}
		}
	}
}

// report delivers results, retrying a transient failure. It stops the run on
// a stop answer; a result it cannot deliver is counted unreported.
func (r *runner) report(ctx context.Context, units []sensordispatch.UnitResult) {
	backoff := r.cfg.ReportBackoff
	for attempt := 1; ; attempt++ {
		err := r.cfg.Reporter.Report(ctx, units)
		if err == nil {
			for _, u := range units {
				if u.Failed {
					r.summary.failed.Add(1)
				} else {
					r.summary.done.Add(1)
				}
			}
			return
		}
		if errors.Is(err, ErrJobStopped) {
			r.stop(err)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if attempt >= r.cfg.ReportAttempts {
			r.cfg.Logf("discovery job: %d host result(s) could not be reported after %d attempts and are given up: %v", len(units), attempt, err)
			r.summary.unreported.Add(int64(len(units)))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (r *runner) fail(ctx context.Context, t *sensordispatch.PlanTargetWork, raw, reason string) {
	r.report(ctx, []sensordispatch.UnitResult{{TargetID: t.TargetID, Address: raw, Attempt: r.plan.Attempt, Failed: true, Error: reason}})
}

// refusal is the sentence an address the sensor's rules refuse carries.
func refusal(err error) string {
	return "not scanned: refused by this sensor's own rules: " + err.Error()
}

// livenessPhase sweeps the range addresses; the ones that answered join the
// port phase with their verdict, the rest are reported done here.
func (r *runner) livenessPhase(ctx context.Context, sweep []work, next *[]work) error {
	for lo := 0; lo < len(sweep); lo += livenessChunk {
		if ctx.Err() != nil {
			return nil
		}
		chunk := sweep[lo:min(lo+livenessChunk, len(sweep))]
		var cleared []work
		var addrs []netip.Addr
		for _, w := range chunk {
			if err := r.cfg.Allow(w.addr); err != nil {
				r.fail(ctx, w.target, w.raw, refusal(err))
				continue
			}
			cleared = append(cleared, w)
			addrs = append(addrs, w.addr)
		}
		if len(addrs) == 0 {
			continue
		}
		results, err := r.live.Liveness(ctx, addrs)
		if err != nil {
			return fmt.Errorf("liveness: %w", err)
		}
		if ctx.Err() != nil {
			// Verdicts cut short by a stop are not verdicts.
			return nil
		}
		byAddr := make(map[netip.Addr]discovery.LivenessResult, len(results))
		for _, lv := range results {
			byAddr[lv.Addr] = lv
		}
		var quiet []sensordispatch.UnitResult
		for _, w := range cleared {
			lv, ok := byAddr[w.addr]
			if !ok {
				continue
			}
			if lv.State == discovery.LivenessUp {
				w.liveness = &lv
				*next = append(*next, w)
				continue
			}
			// No answer (or no verdict): finished here, its ports counted not
			// probed — the same unit the platform's own sweep records.
			n := w.tcp.Len()
			quiet = append(quiet, sensordispatch.NewUnitResult(w.target.TargetID, w.raw, r.plan.Attempt, discovery.UnitOutput{
				Host: discovery.HostScan{Addr: w.addr, Liveness: lv.State, LivenessEvidence: lv.Evidence, PortsRequested: n, NotProbed: n},
			}))
		}
		for lo := 0; lo < len(quiet); lo += sensordispatch.MaxUnitsPerBatch {
			r.report(ctx, quiet[lo:min(lo+sensordispatch.MaxUnitsPerBatch, len(quiet))])
		}
	}
	return nil
}

// portPhase runs every remaining address through the engine, UnitWorkers(pace)
// at a time, reporting each as it finishes.
func (r *runner) portPhase(ctx context.Context, units []work) error {
	if len(units) == 0 {
		return nil
	}
	feed := make(chan work)
	var wg sync.WaitGroup
	for range min(discovery.UnitWorkers(r.engine.Pace()), len(units)) {
		wg.Go(func() {
			for w := range feed {
				r.runUnit(ctx, w)
			}
		})
	}
feed:
	for _, w := range units {
		select {
		case feed <- w:
		case <-ctx.Done():
			break feed
		}
	}
	close(feed)
	wg.Wait()
	return nil
}

func (r *runner) runUnit(ctx context.Context, w work) {
	if ctx.Err() != nil {
		return
	}
	// The rules are asked again immediately before the host's first packet:
	// what the platform delivered may have changed since the sweep.
	if err := r.cfg.Allow(w.addr); err != nil {
		r.fail(ctx, w.target, w.raw, refusal(err))
		return
	}
	out, err := r.engine.Run(ctx, discovery.UnitInput{Addr: w.addr, Hostname: w.target.Hostname(), SNICandidates: w.target.SNICandidates, TCP: w.tcp, UDP: w.udp, Liveness: w.liveness})
	if ctx.Err() != nil {
		// Stopped under it: what it learned is discarded, never reported as
		// a finished host.
		return
	}
	if err != nil {
		r.fail(ctx, w.target, w.raw, "scan failed: "+err.Error())
		return
	}
	r.report(ctx, []sensordispatch.UnitResult{sensordispatch.NewUnitResult(w.target.TargetID, w.raw, r.plan.Attempt, out)})
}
