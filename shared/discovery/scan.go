package discovery

// The connect-scan engine.
//
// This file and its scan_*.go siblings are the one TCP port-discovery engine
// shared by the Platform Sensor (cluster-sensor-service) and the standalone
// Sensor. It answers "which addresses are up, and which TCP ports on them
// accept a connection" — the cheap, broad pass that comes before any
// protocol identification.
//
// It is a CONNECT scan: a full TCP handshake via the operating system's
// ordinary socket API. A raw SYN scan needs CAP_NET_RAW, which restricted-
// PodSecurity clusters forbid, and cannot ride in a CGO-free binary that
// cross-compiles to Linux, Windows and macOS. Speed comes from concurrency
// instead, bounded three ways: per host, per scan (the pace profile), and per
// process (the file-descriptor budget, scan_pace.go).
//
// Guarantees:
//
//   - Authorization envelope. The engine connects ONLY to the addresses it is
//     handed, as netip.Addr values. It performs no DNS resolution and never
//     derives, expands or follows another address (no CIDR expansion, no
//     redirects, no "neighbours"). IPv4-mapped IPv6 input is dialled as the
//     IPv4 address it denotes; a zone identifier is kept. Callers MUST pass
//     only addresses already cleared by shared/identity/dispatchguard —
//     liveness probes included, since a liveness probe is a packet too.
//   - No payload. The engine never writes a byte. An accepted connection is
//     closed immediately.
//   - OT safety. Ports in OTPorts() are touched only under the scanner's
//     OTPolicy: by default one connection at a time per host, with a pause
//     after any connection the device accepted; or not at all.
//   - Bounded output. A host that accepts connections on a large share of the
//     ports probed (a tarpit, or a firewall that answers for everything)
//     stops being scanned early and is reported RespondsOnAllPorts with a
//     small sample, never tens of thousands of "open" ports.
//   - Honest counts. Every requested port ends up open, closed, filtered,
//     a local error, or not probed — and each is counted. "No answer" is
//     never reported as "down", and a local resource failure (out of file
//     descriptors) is never reported as "filtered".
//   - Cancellation. Cancelling the context stops new connects, aborts the
//     ones in flight, and returns once every goroutine the call started has
//     exited.
//
// Non-goals (later work packages): service identification (banner read, TLS
// ClientHello), UDP probes, ARP/ICMP liveness (they need raw sockets — see
// LivenessOracle for the seam), and expanding targets.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Dialer is the engine's only way onto the network. *net.Dialer satisfies it.
// The address is always a literal "ip:port" / "[ip%zone]:port", so a standard
// dialer never resolves a name. Tests inject a recording dialer to prove which
// addresses were contacted.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// OTPolicy controls how the engine touches OT/ICS ports (OTPorts()).
type OTPolicy uint8

const (
	// OTPolicySerialize (the default): OT ports are connect-only and strictly
	// serialized per host — at most one connection to any OT port of a host
	// at a time, closed immediately, and OTSpacing after any connect that was
	// ACCEPTED (a session was opened) before the next. Many PLCs tolerate only
	// one to three sessions.
	OTPolicySerialize OTPolicy = iota
	// OTPolicySkip: never connect to an OT port. Skipped ports are counted
	// in HostScan.SkippedOT, not silently dropped.
	OTPolicySkip
)

// defaultOTSpacing is the pause after an OT port of a host ACCEPTED a
// connection, before the next connect to an OT port of that host. Long enough
// that a controller has torn down the session we just closed before the next
// one arrives. A port that refused or never answered held no session, so there
// is nothing to wait out and the next connect follows at once — still strictly
// one at a time. (The pause used to follow every OT connect, which made 19 OT
// ports cost ~4.5 s per host even when none of them listened.)
const defaultOTSpacing = 250 * time.Millisecond

// defaultOTSuspectConcurrency is the per-host regular-port concurrency a host
// drops to once it is found OT-suspect (an OT port answered open). A fragile
// PLC can fault on the TOTAL number of simultaneous connections, not only on
// connections to its OT port, so once we know a host speaks an OT protocol we
// stop blasting its other ports in parallel. Two, not one, because the point
// is to stop flooding, not to serialize the whole host to a crawl.
const defaultOTSuspectConcurrency = 2

// maxOTSuspectConcurrency bounds the option: an "OT-suspect throttle" that
// allowed hundreds of connections would not be a throttle. The value is also
// clamped to the pace's per-host limit at use, so it can only ever lower
// concurrency, never raise it.
const maxOTSuspectConcurrency = 256

// TarpitGuard stops scanning a host that accepts connections on too many of
// the ports probed. A tarpit, a SYN proxy or a firewall that completes every
// handshake makes a connect scan report every port open; scanning all 65 535
// of them proves nothing and buries the real results.
//
// The guard triggers when the open count reaches
//
//	min(MaxOpen, ceil(MaxOpenFraction × ports-to-probe))
//
// and is inactive for scans of fewer than MinPorts ports, where the output is
// already small and a busy server (a domain controller has a dozen of the
// Quick ports open) must not be mistaken for a tarpit.
type TarpitGuard struct {
	Disabled        bool
	MinPorts        int
	MaxOpen         int
	MaxOpenFraction float64
	// SampleSize is how many open ports (the lowest-numbered seen) a
	// tarpit host reports.
	SampleSize int
}

// DefaultTarpitGuard: trigger at 512 open ports or a quarter of the ports
// probed, whichever is smaller, for scans of 256 ports or more; report 32.
// Standard (1 364 ports) therefore triggers at 341 open, Thorough at 512 —
// far above any real server, far below 65 535.
func DefaultTarpitGuard() TarpitGuard {
	return TarpitGuard{MinPorts: 256, MaxOpen: 512, MaxOpenFraction: 0.25, SampleSize: 32}
}

func (g TarpitGuard) validate() error {
	if g.Disabled {
		return nil
	}
	switch {
	case g.MinPorts < 0:
		return fmt.Errorf("tarpit MinPorts %d must not be negative", g.MinPorts)
	case g.MaxOpen < 1:
		return fmt.Errorf("tarpit MaxOpen %d must be at least 1", g.MaxOpen)
	case !(g.MaxOpenFraction > 0 && g.MaxOpenFraction <= 1):
		return fmt.Errorf("tarpit MaxOpenFraction %v must be in (0, 1]", g.MaxOpenFraction)
	case g.SampleSize < 1:
		return fmt.Errorf("tarpit SampleSize %d must be at least 1", g.SampleSize)
	}
	return nil
}

// threshold is the open count that trips the guard for a scan of n ports;
// 0 means the guard is inactive.
func (g TarpitGuard) threshold(n int) int {
	if g.Disabled || n < g.MinPorts || n == 0 {
		return 0
	}
	t := int(math.Ceil(g.MaxOpenFraction * float64(n)))
	return max(1, min(g.MaxOpen, t))
}

// HostScan is the result for one address. For every host:
//
//	PortsRequested == OpenCount + Closed + Filtered + LocalErrors + NotProbed
type HostScan struct {
	Addr netip.Addr
	// Liveness is how the host came to be port-scanned (or why it was not).
	Liveness         LivenessState
	LivenessEvidence string

	PortsRequested int
	// Open lists open ports in ascending order. When RespondsOnAllPorts it
	// is only a sample (TarpitGuard.SampleSize); OpenCount is the number
	// actually seen open before the scan of this host stopped.
	Open      []int
	OpenCount int
	// Closed ports refused the connection (RST): the host is up, nothing
	// listens there.
	Closed int
	// Filtered ports gave no answer before the timeout, or the network said
	// unreachable: a firewall, or nothing at that address.
	Filtered int
	// LocalErrors are probes that failed on THIS side (out of descriptors or
	// ephemeral ports). They say nothing about the target.
	LocalErrors int
	// NotProbed counts requested ports that got no verdict: skipped OT ports,
	// ports left when the tarpit guard tripped, or ports left at
	// cancellation.
	NotProbed int
	SkippedOT int

	RespondsOnAllPorts bool
	// Cancelled: the context ended before every port got a verdict.
	Cancelled bool
	Duration  time.Duration

	// OTSuspect is set once an OT/ICS port (OTPorts()) answered open on this
	// host. From that moment the host's remaining regular-port concurrency was
	// throttled (see WithOTSuspectConcurrency): a device that speaks an OT
	// protocol is treated as fragile for the rest of its scan.
	OTSuspect bool
	// OTSuspectPort is the OT port whose open answer first made the host
	// OT-suspect (0 when OTSuspect is false).
	OTSuspectPort int
}

// Responded reports whether the host answered at TCP level at all — an open
// port or a refusal. A refusal (RST) proves the host is up as surely as an
// open port does.
func (h HostScan) Responded() bool {
	return h.OpenCount > 0 || h.Closed > 0 ||
		(h.Liveness == LivenessUp && strings.HasPrefix(h.LivenessEvidence, "tcp-"))
}

// ScanResult is the result of Scan, with the totals a coverage summary needs
// ("254 addresses, 31 responded, 223 no answer; 4 ports closed, 9 filtered").
type ScanResult struct {
	// Hosts is one entry per distinct input address, in input order.
	Hosts []HostScan

	HostsTotal int
	// HostsResponded answered at TCP level (see HostScan.Responded).
	HostsResponded int
	// HostsNoAnswer were probed and nothing answered. NOT "down": a firewall
	// that drops everything looks exactly like an empty address.
	HostsNoAnswer int
	// HostsUndetermined got no verdict (cancelled, or only local errors).
	HostsUndetermined int
	// HostsPortScanned went on to the port scan (up, or AssumeUp).
	HostsPortScanned int
	TarpitHosts      int

	PortsProbed int
	Open        int
	Closed      int
	Filtered    int
	LocalErrors int
	NotProbed   int

	Cancelled bool
	Duration  time.Duration
}

// ScanPhase names what a scan is doing, for progress reports.
type ScanPhase string

const (
	PhaseLiveness ScanPhase = "liveness"
	PhasePorts    ScanPhase = "ports"
	PhaseDone     ScanPhase = "done"
)

// Progress is a snapshot of a running scan. Port counters cover the port
// scan only (liveness probes are not "ports probed").
type Progress struct {
	Phase          ScanPhase
	HostsTotal     int
	HostsDone      int
	HostsResponded int
	PortsProbed    int64
	Open           int64
	Closed         int64
	Filtered       int64
}

const (
	defaultProgressInterval = time.Second
	minProgressInterval     = 100 * time.Millisecond
)

// Scanner is a configured scan engine. Its configuration is immutable; one
// Scanner may run several scans concurrently. Each scan call has its own pace
// budget; every scan in the process shares one connection budget (Limits).
//
// A Scanner contacts only the addresses passed to it and performs no name
// resolution: callers must pass addresses already cleared by
// shared/identity/dispatchguard, and that includes the liveness pass.
type Scanner struct {
	dialer           Dialer
	pace             PaceProfile
	otPolicy         OTPolicy
	otSpacing        time.Duration
	otSuspectConc    int
	udpRate          int
	tarpit           TarpitGuard
	livenessPorts    PortSet
	assumeUp         bool
	oracle           LivenessOracle
	progress         func(Progress)
	progressInterval time.Duration
	gate             *connGate
}

// Option configures a Scanner.
type Option func(*Scanner) error

// WithDialer replaces the network dialer (default: a zero net.Dialer; the
// engine applies its own timeout through the context).
func WithDialer(d Dialer) Option {
	return func(s *Scanner) error {
		if d == nil {
			return errors.New("dialer must not be nil")
		}
		s.dialer = d
		return nil
	}
}

// WithPace selects a named pace profile (default PaceNormal).
func WithPace(p Pace) Option {
	return func(s *Scanner) error {
		prof, err := p.Profile()
		if err != nil {
			return err
		}
		s.pace = prof
		return nil
	}
}

// WithPaceProfile sets explicit concurrency and timing (Advanced/custom).
func WithPaceProfile(p PaceProfile) Option {
	return func(s *Scanner) error {
		if err := p.validate(); err != nil {
			return err
		}
		s.pace = p
		return nil
	}
}

// WithOTPolicy sets how OT/ICS ports are touched (default OTPolicySerialize).
func WithOTPolicy(p OTPolicy) Option {
	return func(s *Scanner) error {
		if p != OTPolicySerialize && p != OTPolicySkip {
			return fmt.Errorf("unknown OT policy %d", p)
		}
		s.otPolicy = p
		return nil
	}
}

// WithOTSpacing sets the pause after an accepted OT-port connection, before
// the next connect to an OT port of the same host, under OTPolicySerialize
// (default 250ms).
func WithOTSpacing(d time.Duration) Option {
	return func(s *Scanner) error {
		if d < 0 || d > 10*time.Second {
			return fmt.Errorf("OT spacing %s must be in [0, 10s]", d)
		}
		s.otSpacing = d
		return nil
	}
}

// WithOTSuspectConcurrency sets the per-host regular-port concurrency a host
// drops to once an OT port answers open (default defaultOTSuspectConcurrency).
// It is clamped to the pace's per-host concurrency at use, so it can only lower
// the number of connections in flight to an OT-suspect host, never raise it.
func WithOTSuspectConcurrency(n int) Option {
	return func(s *Scanner) error {
		if n < 1 || n > maxOTSuspectConcurrency {
			return fmt.Errorf("OT-suspect concurrency %d must be in [1, %d]", n, maxOTSuspectConcurrency)
		}
		s.otSuspectConc = n
		return nil
	}
}

// WithTarpitGuard replaces the tarpit guard (default DefaultTarpitGuard()).
func WithTarpitGuard(g TarpitGuard) Option {
	return func(s *Scanner) error {
		if err := g.validate(); err != nil {
			return err
		}
		s.tarpit = g
		return nil
	}
}

// WithProgress registers a progress callback, called at most once per
// interval (minimum 100ms; 0 means 1s) and once more with PhaseDone when the
// scan finishes. Calls are serialized and never happen after Scan returns.
// The callback must not block for long: it delays the next report, not the
// scan.
func WithProgress(fn func(Progress), interval time.Duration) Option {
	return func(s *Scanner) error {
		if interval == 0 {
			interval = defaultProgressInterval
		}
		s.progress = fn
		s.progressInterval = max(interval, minProgressInterval)
		return nil
	}
}

// NewScanner builds a Scanner. Defaults: PaceNormal, OTPolicySerialize,
// DefaultTarpitGuard, DefaultLivenessPorts, liveness on.
func NewScanner(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		dialer:        &net.Dialer{},
		pace:          paceProfiles[PaceNormal],
		otPolicy:      OTPolicySerialize,
		otSpacing:     defaultOTSpacing,
		otSuspectConc: defaultOTSuspectConcurrency,
		tarpit:        DefaultTarpitGuard(),
		livenessPorts: DefaultLivenessPorts(),
		gate:          processConnGate(),
	}
	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}
	if s.livenessPorts.Without(OTPorts()).Len() == 0 {
		return nil, errors.New("liveness needs at least one non-OT port")
	}
	return s, nil
}

// Limits reports the bounds this Scanner runs with.
func (s *Scanner) Limits() Limits {
	slots := s.gate.capacity()
	return Limits{
		PaceProfile:          s.pace,
		ConnectionSlots:      slots,
		EffectiveConcurrency: min(s.pace.GlobalConcurrency, slots),
	}
}

// ParseScanAddrs parses IP address literals for the engine. It never
// resolves: a hostname, a CIDR block or an "ip:port" is an error naming the
// entry, because the engine may only contact addresses the caller has
// already authorized (dispatchguard pins a hostname to the addresses it
// resolved to; that resolution belongs there, not here).
func ParseScanAddrs(in []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address (the scan engine never resolves names or expands ranges)", raw)
		}
		out = append(out, a)
	}
	return out, nil
}

// normalizeTarget returns the address the engine will dial for a, or an error
// for an address that must never be dialled.
func normalizeTarget(a netip.Addr) (netip.Addr, error) {
	if !a.IsValid() {
		return netip.Addr{}, errors.New("invalid (zero) address")
	}
	if a.Is4In6() {
		// ::ffff:10.0.0.1 IS 10.0.0.1 on the wire; dial it as such so the
		// address that reaches the socket is the one the guard judged.
		a = a.Unmap()
	}
	if a.IsUnspecified() {
		// Connecting to 0.0.0.0 / :: reaches THIS host, not a target.
		return netip.Addr{}, fmt.Errorf("%s is the unspecified address", a)
	}
	if a.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("%s is a multicast address", a)
	}
	return a, nil
}

// normalizeTargets validates every address before anything is dialled (an
// invalid entry fails the whole call with no packet sent) and folds
// duplicates, keeping input order.
func normalizeTargets(addrs []netip.Addr) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]bool, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		n, err := normalizeTarget(a)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

// outcome is one probe's result.
type outcome uint8

const (
	outcomeAborted outcome = iota // our context ended; no verdict
	outcomeOpen
	outcomeClosed
	outcomeFiltered
	outcomeLocalError
)

// Winsock error numbers. Windows' net package returns these rather than the
// syscall.E* constants, so errors.Is against ECONNREFUSED misses them.
const (
	wsaEMFILE        = 10024
	wsaEADDRNOTAVAIL = 10049
	wsaENOBUFS       = 10055
	wsaECONNRESET    = 10054
	wsaECONNREFUSED  = 10061
)

func hasWinsockErrno(err error, codes ...uintptr) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return slices.Contains(codes, uintptr(errno))
}

// classifyDialError maps a failed connect to a port state. A refusal or reset
// is "closed" (and proves the host is up); running out of descriptors or
// ephemeral ports is a LOCAL error, never "filtered"; everything else —
// timeout, no route, host/network unreachable, administratively prohibited —
// is "filtered".
func classifyDialError(err error) outcome {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET),
		hasWinsockErrno(err, wsaECONNREFUSED, wsaECONNRESET):
		return outcomeClosed
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE),
		errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.ENOBUFS),
		hasWinsockErrno(err, wsaEMFILE, wsaEADDRNOTAVAIL, wsaENOBUFS):
		return outcomeLocalError
	default:
		return outcomeFiltered
	}
}

// run is the state of one Scan/ScanTCP/Liveness call.
type run struct {
	s *Scanner
	// root is the caller's context. Cancelling it cancels every per-host
	// context too, but one sibling at a time; acquire checks root as well so
	// no host can start a connect while the cancellation is still
	// propagating to it.
	root     context.Context
	paceSlot chan struct{}

	hostsTotal     int
	phase          atomic.Value // ScanPhase
	hostsDone      atomic.Int64
	hostsResponded atomic.Int64
	probed         atomic.Int64
	open           atomic.Int64
	closed         atomic.Int64
	filtered       atomic.Int64
}

func (s *Scanner) newRun(ctx context.Context, hosts int) *run {
	r := &run{s: s, root: ctx, paceSlot: make(chan struct{}, s.pace.GlobalConcurrency), hostsTotal: hosts}
	r.phase.Store(PhaseLiveness)
	return r
}

// acquire takes a per-host slot, a per-scan pace slot and a process-wide
// connection slot, always in that order (so two callers can never hold them
// crosswise), giving up if ctx ends first.
func (r *run) acquire(ctx context.Context, hostSlot chan struct{}) bool {
	select {
	case hostSlot <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	select {
	case r.paceSlot <- struct{}{}:
	case <-ctx.Done():
		<-hostSlot
		return false
	}
	select {
	case r.s.gate.slots <- struct{}{}:
	case <-ctx.Done():
		<-r.paceSlot
		<-hostSlot
		return false
	}
	// select picks randomly among ready cases: a slot can win against an
	// already-cancelled context. Re-check so no connect starts after cancel.
	if ctx.Err() != nil || r.root.Err() != nil {
		r.release(hostSlot)
		return false
	}
	return true
}

func (r *run) release(hostSlot chan struct{}) {
	<-r.s.gate.slots
	<-r.paceSlot
	<-hostSlot
}

// probe makes one TCP connect to ap and classifies it. It writes nothing and
// closes an accepted connection before returning.
func (r *run) probe(ctx context.Context, hostSlot chan struct{}, ap netip.AddrPort) outcome {
	if !r.acquire(ctx, hostSlot) {
		return outcomeAborted
	}
	defer r.release(hostSlot)
	dctx, cancel := context.WithTimeout(ctx, r.s.pace.ConnectTimeout)
	defer cancel()
	conn, err := r.s.dialer.DialContext(dctx, "tcp", ap.String())
	if err == nil {
		_ = conn.Close()
		return outcomeOpen
	}
	if ctx.Err() != nil {
		// Our own cancellation (scan cancelled, or the tarpit guard stopped
		// this host) — not something the target said.
		return outcomeAborted
	}
	return classifyDialError(err)
}

// dialGated acquires the same per-host, per-scan and process slots probe() uses
// and opens a connection the caller keeps (for a banner read or a prober)
// until it calls the returned release, which closes the connection and frees
// the slots. It reports false (releasing nothing) when a slot could not be had
// before ctx ended or the dial failed. The connection holds a slot for its
// whole lifetime, so identification cannot exceed the scan's connection budget.
func (r *run) dialGated(ctx context.Context, hostSlot chan struct{}, network string, ap netip.AddrPort) (net.Conn, func(), bool) {
	if !r.acquire(ctx, hostSlot) {
		return nil, nil, false
	}
	dctx, cancel := context.WithTimeout(ctx, r.s.pace.ConnectTimeout)
	defer cancel()
	conn, err := r.s.dialer.DialContext(dctx, network, ap.String())
	if err != nil || conn == nil {
		r.release(hostSlot)
		return nil, nil, false
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_ = conn.Close()
			r.release(hostSlot)
		})
	}
	return conn, release, true
}

// sleepCtx waits d or until ctx ends; it reports whether the full wait
// elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// scanHost probes ports on one address.
func (r *run) scanHost(ctx context.Context, addr netip.Addr, ports PortSet, lv LivenessResult) HostScan {
	start := time.Now()
	hs := HostScan{
		Addr:             addr,
		Liveness:         lv.State,
		LivenessEvidence: lv.Evidence,
		PortsRequested:   ports.Len(),
	}
	ot := OTPorts()
	var regular, otPorts []uint16
	for _, p := range ports.ports {
		switch {
		case !ot.contains16(p):
			regular = append(regular, p)
		case r.s.otPolicy == OTPolicySkip:
			hs.SkippedOT++
		default:
			otPorts = append(otPorts, p)
		}
	}
	threshold := r.s.tarpit.threshold(len(regular) + len(otPorts))

	hctx, stopHost := context.WithCancel(ctx)
	defer stopHost()
	hostSlot := make(chan struct{}, r.s.pace.PerHostConcurrency)

	// OT-suspect throttle. Once an OT port answers open, suspect flips and the
	// regular-port workers route each remaining connect through suspectSlots,
	// capping in-flight regular connects to this host at suspectConc (clamped
	// to the per-host limit so it can only ever lower concurrency). Connects
	// already in flight finish; this never adds one, nor speeds anything up.
	var suspect atomic.Bool
	suspectConc := min(r.s.otSuspectConc, r.s.pace.PerHostConcurrency)
	suspectSlots := make(chan struct{}, suspectConc)
	suspectSpacing := r.s.otSpacing

	var mu sync.Mutex
	record := func(port uint16, o outcome) {
		mu.Lock()
		defer mu.Unlock()
		switch o {
		case outcomeOpen:
			hs.OpenCount++
			hs.Open = append(hs.Open, int(port))
			r.open.Add(1)
			r.probed.Add(1)
			if ot.contains16(port) && !hs.OTSuspect {
				hs.OTSuspect = true
				hs.OTSuspectPort = int(port)
				suspect.Store(true)
			}
			if threshold > 0 && hs.OpenCount >= threshold && !hs.RespondsOnAllPorts {
				hs.RespondsOnAllPorts = true
				stopHost()
			}
		case outcomeClosed:
			hs.Closed++
			r.closed.Add(1)
			r.probed.Add(1)
		case outcomeFiltered:
			hs.Filtered++
			r.filtered.Add(1)
			r.probed.Add(1)
		case outcomeLocalError:
			hs.LocalErrors++
		}
	}

	var wg sync.WaitGroup
	if len(regular) > 0 {
		feed := make(chan uint16)
		wg.Go(func() {
			defer close(feed)
			perHost, delay := r.s.pace.PerHostConcurrency, r.s.pace.BatchDelay
			for i, p := range regular {
				if i > 0 && delay > 0 && i%perHost == 0 && !sleepCtx(hctx, delay) {
					return
				}
				select {
				case feed <- p:
				case <-hctx.Done():
					return
				}
			}
		})
		for range min(r.s.pace.PerHostConcurrency, len(regular)) {
			wg.Go(func() {
				for p := range feed {
					if !suspect.Load() {
						record(p, r.probe(hctx, hostSlot, netip.AddrPortFrom(addr, p)))
						continue
					}
					// Throttled: an OT port on this host answered open.
					select {
					case suspectSlots <- struct{}{}:
					case <-hctx.Done():
						return
					}
					if !sleepCtx(hctx, suspectSpacing) {
						<-suspectSlots
						return
					}
					record(p, r.probe(hctx, hostSlot, netip.AddrPortFrom(addr, p)))
					<-suspectSlots
				}
			})
		}
	}
	if len(otPorts) > 0 {
		// One goroutine, one connect at a time: probe() returns only after
		// the connection is closed, so two OT connects to this host can
		// never overlap. The pause follows only a connect that was accepted
		// — a session the device had to set up and tear down; a refusal or
		// silence held none (see defaultOTSpacing).
		wg.Go(func() {
			sessionHeld := false
			for _, p := range otPorts {
				if sessionHeld && !sleepCtx(hctx, r.s.otSpacing) {
					return
				}
				o := r.probe(hctx, hostSlot, netip.AddrPortFrom(addr, p))
				record(p, o)
				sessionHeld = o == outcomeOpen
			}
		})
	}
	wg.Wait()

	slices.Sort(hs.Open)
	if hs.RespondsOnAllPorts && len(hs.Open) > r.s.tarpit.SampleSize {
		hs.Open = slices.Clip(hs.Open[:r.s.tarpit.SampleSize])
	}
	hs.NotProbed = hs.PortsRequested - hs.OpenCount - hs.Closed - hs.Filtered - hs.LocalErrors
	hs.Cancelled = ctx.Err() != nil && hs.NotProbed > hs.SkippedOT && !hs.RespondsOnAllPorts
	hs.Duration = time.Since(start)
	return hs
}

// startProgress launches the reporter; the returned func stops it and makes
// the final PhaseDone report. Reports are serialized by construction: one
// goroutine makes them, and the final one happens after it has exited.
func (r *run) startProgress() (stop func()) {
	fn := r.s.progress
	if fn == nil {
		return func() {}
	}
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		t := time.NewTicker(r.s.progressInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				fn(r.snapshot())
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		<-exited
		r.phase.Store(PhaseDone)
		fn(r.snapshot())
	}
}

func (r *run) snapshot() Progress {
	return Progress{
		Phase:          r.phase.Load().(ScanPhase),
		HostsTotal:     r.hostsTotal,
		HostsDone:      int(r.hostsDone.Load()),
		HostsResponded: int(r.hostsResponded.Load()),
		PortsProbed:    r.probed.Load(),
		Open:           r.open.Load(),
		Closed:         r.closed.Load(),
		Filtered:       r.filtered.Load(),
	}
}

// hostParallelism is how many hosts the port phase works on at once: enough
// that per-host limits do not leave the global budget idle, doubled so a
// host finishing does not drain the pipeline.
func (r *run) hostParallelism(hosts int) int {
	eff := min(r.s.pace.GlobalConcurrency, r.s.gate.capacity())
	per := r.s.pace.PerHostConcurrency
	return max(1, min(hosts, 2*((eff+per-1)/per)))
}

// Scan checks liveness (unless AssumeUp), then port-scans every host that is
// up. addrs must already be authorized by the caller (see the package
// guarantees); an invalid, unspecified or multicast address fails the whole
// call before anything is dialled. Cancelling ctx returns promptly with what
// was learned so far and Cancelled set.
func (s *Scanner) Scan(ctx context.Context, addrs []netip.Addr, ports PortSet) (ScanResult, error) {
	targets, err := normalizeTargets(addrs)
	if err != nil {
		return ScanResult{}, err
	}
	if ports.Len() == 0 {
		return ScanResult{}, errors.New("no ports to scan")
	}
	start := time.Now()
	r := s.newRun(ctx, len(targets))
	stopProgress := r.startProgress()

	live := r.liveness(ctx, targets)

	r.phase.Store(PhasePorts)
	hosts := make([]HostScan, len(targets))
	var toScan []int
	for i, lv := range live {
		if lv.State == LivenessUp || lv.State == LivenessAssumedUp {
			toScan = append(toScan, i)
			continue
		}
		hosts[i] = HostScan{
			Addr: targets[i], Liveness: lv.State, LivenessEvidence: lv.Evidence,
			PortsRequested: ports.Len(), NotProbed: ports.Len(),
			Cancelled: lv.State == LivenessUndetermined && ctx.Err() != nil,
		}
		r.hostsDone.Add(1)
	}

	next := make(chan int)
	var wg sync.WaitGroup
	for range r.hostParallelism(len(toScan)) {
		wg.Go(func() {
			for i := range next {
				hosts[i] = r.scanHost(ctx, targets[i], ports, live[i])
				if hosts[i].Responded() {
					r.hostsResponded.Add(1)
				}
				r.hostsDone.Add(1)
			}
		})
	}
feed:
	for _, i := range toScan {
		select {
		case next <- i:
		case <-ctx.Done():
			// Hosts never handed out are recorded as cancelled below.
			break feed
		}
	}
	close(next)
	wg.Wait()
	stopProgress()

	res := ScanResult{Hosts: hosts, HostsTotal: len(targets), Cancelled: ctx.Err() != nil}
	for i := range hosts {
		h := &hosts[i]
		if !h.Addr.IsValid() {
			// Up, but the scan was cancelled before this host was reached.
			*h = HostScan{
				Addr: targets[i], Liveness: live[i].State, LivenessEvidence: live[i].Evidence,
				PortsRequested: ports.Len(), NotProbed: ports.Len(), Cancelled: true,
			}
		}
		switch {
		case h.Responded():
			res.HostsResponded++
		case h.Filtered > 0 || h.Liveness == LivenessNoAnswer:
			res.HostsNoAnswer++
		default:
			res.HostsUndetermined++
		}
		if h.Liveness == LivenessUp || h.Liveness == LivenessAssumedUp {
			res.HostsPortScanned++
		}
		if h.RespondsOnAllPorts {
			res.TarpitHosts++
		}
		res.Open += h.OpenCount
		res.Closed += h.Closed
		res.Filtered += h.Filtered
		res.LocalErrors += h.LocalErrors
		res.NotProbed += h.NotProbed
	}
	res.PortsProbed = res.Open + res.Closed + res.Filtered
	res.Duration = time.Since(start)
	return res, nil
}

// ScanTCP port-scans one address without a liveness check (the host is
// reported LivenessAssumedUp). The same guarantees as Scan apply.
func (s *Scanner) ScanTCP(ctx context.Context, addr netip.Addr, ports PortSet) (HostScan, error) {
	target, err := normalizeTarget(addr)
	if err != nil {
		return HostScan{}, err
	}
	if ports.Len() == 0 {
		return HostScan{}, errors.New("no ports to scan")
	}
	r := s.newRun(ctx, 1)
	r.phase.Store(PhasePorts)
	stopProgress := r.startProgress()
	hs := r.scanHost(ctx, target, ports, LivenessResult{Addr: target, State: LivenessAssumedUp, Evidence: "assumed"})
	if hs.Responded() {
		r.hostsResponded.Add(1)
	}
	r.hostsDone.Add(1)
	stopProgress()
	return hs, nil
}
