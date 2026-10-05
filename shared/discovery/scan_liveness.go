package discovery

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"
)

// LivenessState is the engine's verdict on whether an address is worth
// port-scanning.
type LivenessState uint8

const (
	// LivenessUndetermined: no verdict — cancelled before an answer, or
	// every probe failed locally.
	LivenessUndetermined LivenessState = iota
	// LivenessUp: a probe was accepted or refused (both mean a host is
	// there), or a LivenessOracle vouched for it.
	LivenessUp
	// LivenessNoAnswer: every probe timed out or was unreachable. This is
	// NOT "down" — a firewall that drops everything is indistinguishable
	// from an empty address — and coverage must report it as no answer.
	LivenessNoAnswer
	// LivenessAssumedUp: liveness was skipped (AssumeUp, or ScanTCP); the
	// host goes straight to the port scan.
	LivenessAssumedUp
)

func (s LivenessState) String() string {
	switch s {
	case LivenessUp:
		return "up"
	case LivenessNoAnswer:
		return "no_answer"
	case LivenessAssumedUp:
		return "assumed_up"
	default:
		return "undetermined"
	}
}

// LivenessResult is the liveness verdict for one address.
type LivenessResult struct {
	Addr  netip.Addr
	State LivenessState
	// Evidence says what decided it: "tcp-open:443", "tcp-refused:22",
	// "oracle", "assumed", or "" when nothing answered.
	Evidence string
	// Probes is how many liveness connects got a verdict for this address.
	Probes int
}

// LivenessOracle is the seam for liveness evidence the engine cannot gather
// unprivileged and CGO-free: ARP on the sensor's own layer-2 segment, ICMP
// where raw sockets are allowed, or addresses inventory and passive capture
// already know are live. KnownUp is asked only about addresses the caller
// passed in (it can vouch for an address, never add one); returning false
// falls through to the TCP probes. It must honour ctx.
type LivenessOracle interface {
	KnownUp(ctx context.Context, addr netip.Addr) bool
}

// defaultLivenessPorts are the ports the TCP liveness probe tries: the
// services most likely to be listening on, or actively refused by, a host of
// any kind — SSH, DNS, HTTP, MS-RPC, NetBIOS session, HTTPS, SMB, RDP and the
// two common alternate web ports. A Windows host with its firewall on often
// still answers 135/445; a Linux server 22; an appliance 80/443. A refusal on
// any of them counts as much as an accept.
const defaultLivenessPorts = "22,53,80,135,139,443,445,3389,8080,8443"

// DefaultLivenessPorts returns the ports the TCP liveness probe tries.
func DefaultLivenessPorts() PortSet { return mustPorts(defaultLivenessPorts) }

// WithLivenessPorts replaces the liveness probe ports. OT ports in the set are
// ignored: a reachability check must never be what wakes a controller.
func WithLivenessPorts(p PortSet) Option {
	return func(s *Scanner) error {
		if p.Without(OTPorts()).Len() == 0 {
			return errors.New("liveness needs at least one non-OT port")
		}
		s.livenessPorts = p
		return nil
	}
}

// WithAssumeUp skips liveness: every address proceeds to the port scan
// (the Thorough "assume all hosts are up" choice — for networks that drop
// probes to closed ports, at the cost of scanning empty addresses in full).
func WithAssumeUp() Option {
	return func(s *Scanner) error {
		s.assumeUp = true
		return nil
	}
}

// WithLivenessOracle adds a source of liveness evidence (see LivenessOracle).
func WithLivenessOracle(o LivenessOracle) Option {
	return func(s *Scanner) error {
		s.oracle = o
		return nil
	}
}

// Liveness decides, for each address, whether anything answers at TCP level
// on the liveness ports (accepted OR refused both mean up; nothing at all
// means NoAnswer). Results are in input order, one per distinct address. The
// same authorization rule as Scan applies: only the given addresses are
// contacted. AssumeUp does not apply here — Liveness always probes.
func (s *Scanner) Liveness(ctx context.Context, addrs []netip.Addr) ([]LivenessResult, error) {
	targets, err := normalizeTargets(addrs)
	if err != nil {
		return nil, err
	}
	r := s.newRun(ctx, len(targets))
	stop := r.startProgress()
	out := r.probeLiveness(ctx, targets)
	stop()
	return out, nil
}

// liveness is Scan's liveness phase: probes, or AssumedUp for every address.
func (r *run) liveness(ctx context.Context, targets []netip.Addr) []LivenessResult {
	if r.s.assumeUp {
		out := make([]LivenessResult, len(targets))
		for i, a := range targets {
			out[i] = LivenessResult{Addr: a, State: LivenessAssumedUp, Evidence: "assumed"}
		}
		return out
	}
	return r.probeLiveness(ctx, targets)
}

func (r *run) probeLiveness(ctx context.Context, targets []netip.Addr) []LivenessResult {
	ports := r.s.livenessPorts.Without(OTPorts())
	out := make([]LivenessResult, len(targets))
	eff := min(r.s.pace.GlobalConcurrency, r.s.gate.capacity())
	parallel := max(1, min(len(targets), eff/max(1, min(ports.Len(), r.s.pace.PerHostConcurrency))))

	next := make(chan int)
	var wg sync.WaitGroup
	for range parallel {
		wg.Go(func() {
			for i := range next {
				out[i] = r.livenessHost(ctx, targets[i], ports)
			}
		})
	}
feed:
	for i := range targets {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	for i := range out {
		if !out[i].Addr.IsValid() { // never reached: cancelled
			out[i] = LivenessResult{Addr: targets[i], State: LivenessUndetermined}
		}
	}
	return out
}

// livenessHost probes one address's liveness ports concurrently (within the
// per-host limit) and stops at the first answer.
func (r *run) livenessHost(ctx context.Context, addr netip.Addr, ports PortSet) LivenessResult {
	res := LivenessResult{Addr: addr}
	if r.s.oracle != nil && r.s.oracle.KnownUp(ctx, addr) {
		res.State, res.Evidence = LivenessUp, "oracle"
		return res
	}
	hctx, stop := context.WithCancel(ctx)
	defer stop()
	hostSlot := make(chan struct{}, r.s.pace.PerHostConcurrency)

	var mu sync.Mutex
	filtered := 0
	var wg sync.WaitGroup
	for _, p := range ports.ports {
		wg.Go(func() {
			o := r.probe(hctx, hostSlot, netip.AddrPortFrom(addr, p))
			mu.Lock()
			defer mu.Unlock()
			switch o {
			case outcomeOpen, outcomeClosed:
				res.Probes++
				if res.State != LivenessUp {
					res.State = LivenessUp
					verb := "tcp-open:"
					if o == outcomeClosed {
						verb = "tcp-refused:"
					}
					res.Evidence = verb + strconv.Itoa(int(p))
					stop()
				}
			case outcomeFiltered:
				res.Probes++
				filtered++
			}
		})
	}
	wg.Wait()
	if res.State != LivenessUp && filtered > 0 && ctx.Err() == nil {
		res.State = LivenessNoAnswer
	}
	return res
}
