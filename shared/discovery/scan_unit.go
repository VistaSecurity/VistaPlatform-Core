package discovery

// The per-unit pipeline ( WP2): what one host of a scan-plan job goes
// through. It lives here, not in either runtime, because the Platform Sensor
// (cluster-sensor-service's work units) and a tenant's standalone sensor
// (WP2b) must run a planned host the same way — the repo's source-sharing rule
// for active probing:
//
//	TCP port scan of the target's PLANNED ports (pace, OT serialization and
//	the tarpit guard are the engine's) → Identify on the open ports (OT probes
//	only for the protocols the job opted in to) → ScanUDP on the planned UDP
//	ports.
//
// Liveness for ranges runs before this, as a sweep over many units at once
// (NewLivenessScanner); a unit arrives here already known to be up, or assumed
// up because its target named one host.
//
// The engine contacts only the address it is handed. Every unit's address was
// authorized by the caller before it got here; this file must never derive
// another.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// MaxUnitDeadline caps how long one host may take. A Thorough host at the
// polite pace, every port filtered, is about 2.4 hours of connect timeouts;
// this leaves room for that and identification, and no more.
const MaxUnitDeadline = 6 * time.Hour

// unitIdentifyAllowance is what identification of one host is budgeted: the
// most open ports a host reports before the tarpit guard calls it a tarpit
// (512), worked PerHostConcurrency at a time, each a banner wait plus one
// probe — and, should the port be TLS, the follow-up handshakes after it: the
// key-exchange support handshakes (at most two, sharing ONE probe timeout that
// bounds their connects too — MeasureTLSKeyExchange's single deadline), then
// the version enumeration: one connect and one handshake per version the first
// handshake did not prove.
const (
	unitMaxIdentified    = 512
	unitIdentifyPerPort  = 7 * time.Second
	unitTLSKexSupport    = defaultIdentifyProbeTimeout
	unitTLSEnumHandshake = defaultIdentifyProbeTimeout
	unitUDPPerPortBudget = 16 * time.Second // two probers × two attempts × the 4s probe timeout
)

// unitTLSEnumHandshakes is how many forced-version handshakes enumeration adds
// to a TLS port at most: every version but the negotiated one.
var unitTLSEnumHandshakes = len(tlsVersionsNewestFirst) - 1

// UnitEngine runs units on the shared engine with one job's settings.
type UnitEngine struct {
	// scanner always assumes up: liveness is decided before a unit runs.
	scanner *Scanner
	pace    PaceProfile
	// otProbes is the job's OT opt-in (discovery_jobs.ot_probe_protocols).
	otProbes []string
	// guard is applied to fetches a scanned server's data asks for (OCSP).
	// A platform runtime sets it; the standalone sensor leaves it nil (see
	// IdentifyOptions.OutboundGuard).
	guard AddressGuard
}

// NewUnitEngine builds a job's engine. extra lets a caller inject a dialer (a
// test's fake network, a sensor's guarded one); without one the engine dials
// the network itself. An OT opt-in naming a protocol identification cannot
// probe is refused here, before any packet.
func NewUnitEngine(pace Pace, otProbes []string, guard AddressGuard, extra ...Option) (*UnitEngine, error) {
	prof, err := pace.Profile()
	if err != nil {
		return nil, err
	}
	if err := ValidateOTProbeNames(otProbes); err != nil {
		return nil, err
	}
	opts := append([]Option{WithPace(pace), WithOTPolicy(OTPolicySerialize), WithAssumeUp()}, extra...)
	scanner, err := NewScanner(opts...)
	if err != nil {
		return nil, err
	}
	return &UnitEngine{scanner: scanner, pace: prof, otProbes: otProbes, guard: guard}, nil
}

// NewLivenessScanner is a scanner for the liveness sweep, with the same pace
// and dialer as the units.
func NewLivenessScanner(pace Pace, extra ...Option) (*Scanner, error) {
	opts := append([]Option{WithPace(pace), WithOTPolicy(OTPolicySerialize)}, extra...)
	return NewScanner(opts...)
}

// ValidateOTProbeNames refuses an OT opt-in naming a protocol identification
// cannot actively probe. Empty is valid (no opt-in).
func ValidateOTProbeNames(names []string) error {
	_, err := validateOTProbes(names)
	return err
}

// Pace is the profile the engine runs at.
func (e *UnitEngine) Pace() PaceProfile { return e.pace }

// UnitWorkers is how many units of one job run at once: as many hosts as the
// pace's per-scan budget holds at its per-host limit, so a job never has more
// connections in flight than its pace allows (polite 8 × 16, normal 4 × 128,
// fast 4 × 512). Every connection also passes the engine's process-wide
// descriptor gate.
func UnitWorkers(p PaceProfile) int {
	return max(1, p.GlobalConcurrency/p.PerHostConcurrency)
}

// UnitInput is one unit as the engine runs it.
type UnitInput struct {
	Addr     netip.Addr
	Hostname string
	// SNICandidates are names the target is known by, offered to a TLS port
	// that refuses the nameless attempt (IdentifyOptions.SNICandidates).
	SNICandidates []string
	TCP           PortSet
	UDP           []int
	// Liveness is the sweep's verdict for a range address; nil when the
	// target named the host (assumed up).
	Liveness *LivenessResult
}

// UnitOutput is what one unit learned.
type UnitOutput struct {
	Host HostScan
	TCP  []Observation
	UDP  []Observation
	// DeadlineHit: the unit ran out of its own time (not the job's); what it
	// learned is kept and the ports it did not reach are counted not probed.
	DeadlineHit bool
	Deadline    time.Duration
}

// Deadline is the unit's time budget, derived from its ports: the TCP scan's
// worst case (every port waits out the connect timeout, PerHostConcurrency at
// a time, plus the OT ports one at a time), identification's (every open port
// budgeted as if it were TLS, with its key-exchange support handshakes and its
// version enumeration), and UDP's, with half again as
// slack and a minute's floor; never above MaxUnitDeadline.
func (e *UnitEngine) Deadline(in UnitInput) time.Duration {
	per := e.pace.PerHostConcurrency
	tcpPorts := in.TCP.Len()
	ot := in.TCP.Len() - in.TCP.Without(OTPorts()).Len()
	batches := (tcpPorts + per - 1) / per
	tcp := time.Duration(batches)*(e.pace.ConnectTimeout+e.pace.BatchDelay) + time.Duration(ot)*(e.pace.ConnectTimeout+time.Second)
	identifyPerPort := unitIdentifyPerPort + unitTLSKexSupport + time.Duration(unitTLSEnumHandshakes)*(e.pace.ConnectTimeout+unitTLSEnumHandshake)
	identify := time.Duration((min(tcpPorts, unitMaxIdentified)+per-1)/per) * identifyPerPort
	udp := time.Duration(len(in.UDP)) * unitUDPPerPortBudget
	d := (tcp+identify+udp)*3/2 + time.Minute
	if d > MaxUnitDeadline {
		return MaxUnitDeadline
	}
	return d
}

// Run executes one unit. It returns early, with what it had, when ctx (the
// job) ends; the caller decides from ctx whether the result counts.
func (e *UnitEngine) Run(ctx context.Context, in UnitInput) (UnitOutput, error) {
	out := UnitOutput{Deadline: e.Deadline(in)}
	uctx, cancel := context.WithTimeout(ctx, out.Deadline)
	defer cancel()

	if in.TCP.Len() > 0 {
		hs, err := e.scanner.ScanTCP(uctx, in.Addr, in.TCP)
		if err != nil {
			return out, fmt.Errorf("port scan: %w", err)
		}
		out.Host = hs
	} else {
		// A UDP-only custom scan: no TCP port was asked for, so none is sent.
		out.Host = HostScan{Addr: in.Addr, Liveness: LivenessAssumedUp, LivenessEvidence: "assumed"}
	}
	if in.Liveness != nil {
		out.Host.Liveness, out.Host.LivenessEvidence = in.Liveness.State, in.Liveness.Evidence
	}

	idOpts := IdentifyOptions{Hostname: in.Hostname, SNICandidates: in.SNICandidates, OTProbes: e.otProbes, OutboundGuard: e.guard}
	// A tarpit's "open" ports are not listeners: identifying them would be
	// the speculative traffic the guard exists to avoid.
	if !out.Host.RespondsOnAllPorts && len(out.Host.Open) > 0 && uctx.Err() == nil {
		obs, err := e.scanner.Identify(uctx, out.Host, idOpts)
		if err != nil {
			return out, fmt.Errorf("identify: %w", err)
		}
		out.TCP = obs
	}
	if len(in.UDP) > 0 && uctx.Err() == nil {
		obs, err := e.scanner.ScanUDP(uctx, in.Addr, in.UDP, idOpts)
		if err != nil {
			return out, fmt.Errorf("udp: %w", err)
		}
		out.UDP = obs
	}
	out.DeadlineHit = ctx.Err() == nil && uctx.Err() != nil
	return out, nil
}

// PlanTargetHostname is the name a plan target presents as SNI: the input when
// it is a hostname, "" for an address or a range.
func PlanTargetHostname(input string) string {
	if net.ParseIP(input) != nil || IsNetworkRange(input) {
		return ""
	}
	return input
}
