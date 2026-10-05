package discovery

// ScanUDP — honest per-service UDP discovery for one address.
//
// For each requested UDP port it runs the curated protocol probe(s) for that
// port (probe_udp_services.go) and returns one Observation per port, using the
// honest UDP vocabulary: a parsed reply is "open" (identified); an ICMP
// port-unreachable is "closed" (refused); silence is "open_or_filtered", which
// must NEVER become a finding or an asset. A custom port with no payload prober
// gets a single minimal datagram only to elicit a port-unreachable — otherwise
// it stays open_or_filtered (hole H18).
//
// UDP is rate-limited per host (WithUDPPacketRate; default scales with pace):
// many stacks rate-limit the ICMP unreachables that make a refusal detectable,
// so firing datagrams faster than that would turn refusals into false silence.
// The scan therefore paces its datagrams — one per interval per host, however
// many ports are in flight — and honours context cancellation. The spacing is
// enforced where the datagram is written (udpPacer), not where a probe is
// scheduled, so a goroutine that is late to its turn delays the datagrams
// behind it rather than landing next to them.
//
// What it does overlap is the WAITING. A UDP probe spends almost all its time
// waiting for a reply that, on a silent port, never comes (the probe timeout,
// per attempt). Up to udpPortConcurrency ports of one host wait at once, each
// datagram still taking the next slot of the host's packet rate, so a large
// custom UDP range costs about ports × interval rather than ports × timeout.
// OT/ICS UDP ports are never overlapped: they are probed one at a time.
//
// OT/ICS UDP ports (OTUDPPorts) are probed only under the OT opt-in
// (IdentifyOptions.OTProbes), using the existing BACnet / EtherNet-IP probers.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// udpPortConcurrency is how many UDP ports of one host may be awaiting a
// reply at once. It overlaps reply waits only: every datagram still waits for
// its own slot of the per-host packet rate.
const udpPortConcurrency = 8

// defaultUDPPacketRate is the per-host datagram rate (packets/second) a UDP
// scan uses at the normal pace. ICMP unreachable is itself rate-limited by many
// stacks, so this is intentionally modest.
const defaultUDPPacketRate = 100

// udpPacketRateForPace scales the default rate with the pace profile.
func udpPacketRateForPace(p PaceProfile) int {
	normal := paceProfiles[PaceNormal]
	r := defaultUDPPacketRate * p.GlobalConcurrency / normal.GlobalConcurrency
	return max(5, r)
}

// WithUDPPacketRate sets the per-host UDP datagram rate (packets/second). Zero
// restores the pace-derived default. It can only slow the scan; there is no
// corresponding way to make UDP faster than the pace allows.
func WithUDPPacketRate(pps int) Option {
	return func(s *Scanner) error {
		if pps < 0 || pps > 100000 {
			return fmt.Errorf("UDP packet rate %d must be in [0, 100000]", pps)
		}
		s.udpRate = pps
		return nil
	}
}

// udpRate returns the effective per-host UDP packet rate.
func (s *Scanner) effectiveUDPRate() int {
	if s.udpRate > 0 {
		return s.udpRate
	}
	return udpPacketRateForPace(s.pace)
}

// ScanUDP probes the given UDP ports on addr and returns one Observation per
// port, in the order given (deduplicated). It contacts only addr, resolves no
// name, paces its datagrams, and honours ctx cancellation.
func (s *Scanner) ScanUDP(ctx context.Context, addr netip.Addr, ports []int, opts IdentifyOptions) ([]Observation, error) {
	target, err := normalizeTarget(addr)
	if err != nil {
		return nil, err
	}
	otOptIn, err := validateOTProbes(opts.OTProbes)
	if err != nil {
		return nil, err
	}
	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultIdentifyProbeTimeout
	}

	// One datagram no more often than every interval, per host, whichever
	// port it is for.
	pace := &udpPacer{interval: time.Second / time.Duration(s.effectiveUDPRate())}

	seen := make(map[int]bool, len(ports))
	var order, regular, ot []int
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		order = append(order, port)
		if _, isOT := otUDPPortProtocols[port]; isOT {
			ot = append(ot, port)
		} else {
			regular = append(regular, port)
		}
	}
	results := make(map[int]Observation, len(order))
	var resMu sync.Mutex
	probe := func(port int) {
		if ctx.Err() != nil {
			return
		}
		o := s.scanUDPPort(ctx, target, port, timeout, otOptIn, pace)
		resMu.Lock()
		results[port] = o
		resMu.Unlock()
	}

	var wg sync.WaitGroup
	if len(regular) > 0 {
		feed := make(chan int)
		for range min(udpPortConcurrency, len(regular)) {
			wg.Go(func() {
				for port := range feed {
					probe(port)
				}
			})
		}
		wg.Go(func() {
			defer close(feed)
			for _, port := range regular {
				select {
				case feed <- port:
				case <-ctx.Done():
					return
				}
			}
		})
	}
	if len(ot) > 0 {
		// One at a time: an OT device is never sent overlapping probes.
		wg.Go(func() {
			for _, port := range ot {
				probe(port)
			}
		})
	}
	wg.Wait()

	// In the order given; a port the scan never reached (cancelled) is left
	// out, as before.
	out := make([]Observation, 0, len(results))
	for _, port := range order {
		if o, ok := results[port]; ok {
			out = append(out, o)
		}
	}
	return out, nil
}

// scanUDPPort probes one UDP port.
func (s *Scanner) scanUDPPort(ctx context.Context, addr netip.Addr, port int, timeout time.Duration, otOptIn map[string]bool, pace *udpPacer) Observation {
	obs := Observation{Addr: addr, Port: port, Transport: "udp", State: "open_or_filtered"}

	// OT UDP ports: only under opt-in, with the existing probers.
	if protos, ok := otUDPPortProtocols[port]; ok {
		proto := protos[0]
		if !otOptIn[CanonicalProtocolName(proto)] {
			obs.ServiceHint = toLowerASCII(proto)
			obs.Metadata = map[string]any{"ot_connect_only": true}
			obs.Notes = "ot-opt-in-not-given"
			return obs
		}
		return s.runOTUDPProbe(ctx, addr, port, proto, timeout, pace)
	}

	probers := udpServiceProbersForPort(port)
	if len(probers) == 0 {
		// A custom/advanced UDP port with no payload prober: one minimal
		// datagram, read only to catch a port-unreachable. No reply leaves it
		// open_or_filtered — never a finding, never an asset.
		return s.probeUnknownUDP(ctx, addr, port, timeout, pace)
	}

	for _, np := range probers {
		if ctx.Err() != nil {
			obs.Notes = "cancelled"
			return obs
		}
		att := s.runUDPService(ctx, addr, port, np, timeout, pace)
		switch att.Outcome {
		case ProbeAnswered:
			obs.State = "open"
			obs.Protocol = att.Result.Protocol
			obs.Identified = true
			obs.Result = att.Result
			obs.ServiceHint = toLowerASCII(att.Result.Protocol)
			return obs
		case ProbeRefused:
			obs.State = "closed"
			obs.Notes = "icmp-port-unreachable"
			return obs // the host said nothing is bound; no point trying more
		}
		// no-answer / error: try the next protocol for this port, if any.
	}
	return obs // open_or_filtered — honest, and not a finding
}

// runUDPService dials a connected UDP socket through the injected dialer and
// runs one service prober with the shared retry/classify loop.
func (s *Scanner) runUDPService(ctx context.Context, addr netip.Addr, port int, np udpNamedProbe, timeout time.Duration, pace *udpPacer) ProbeAttempt {
	att := ProbeAttempt{Protocol: np.protocol, Port: port, Transport: "udp", Outcome: ProbeError}
	for i := 0; i < udpProbeAttempts; i++ {
		if !pace.acquire(ctx) {
			att.Outcome = ProbeNoAnswer
			att.Detail = "cancelled"
			return att
		}
		att.Attempts = i + 1
		conn, err := s.dialPacedUDP(ctx, addr, port, timeout, pace)
		if err != nil {
			att.Outcome, att.Detail = classifyUDPProbeError(err), err.Error()
			if att.Outcome == ProbeRefused {
				return att
			}
			continue
		}
		res, perr := np.probe(conn, timeout)
		_ = conn.Close()
		if perr == nil && res != nil {
			att.Outcome, att.Result, att.Detail = ProbeAnswered, res, ""
			return att
		}
		if perr == nil {
			att.Outcome, att.Detail = ProbeNoAnswer, "prober returned no result"
			continue
		}
		att.Outcome, att.Detail = classifyUDPProbeError(perr), perr.Error()
		if att.Outcome == ProbeRefused {
			return att
		}
	}
	return att
}

// runOTUDPProbe dispatches the existing OT UDP prober (BACnet / EtherNet-IP)
// through the gate, one at a time, under the OT opt-in.
func (s *Scanner) runOTUDPProbe(ctx context.Context, addr netip.Addr, port int, proto string, timeout time.Duration, pace *udpPacer) Observation {
	obs := Observation{Addr: addr, Port: port, Transport: "udp", State: "open_or_filtered", ServiceHint: toLowerASCII(proto)}
	probe, ok := udpProberRegistry[CanonicalProtocolName(proto)]
	if !ok {
		obs.Notes = "no-ot-udp-prober"
		return obs
	}
	if !pace.acquire(ctx) {
		obs.Notes = "cancelled"
		return obs
	}
	// The OT UDP probers dial themselves (ip:port); prober timeout applies.
	// Their write cannot be seen from here, so the slot is held for the whole
	// probe and the interval counted from its return: while an OT probe is in
	// flight the host is sent nothing else.
	res, err := probe(NewProber(timeout), "", addr.String(), port)
	pace.release(true)
	if err != nil || res == nil {
		att := classifyUDPProbeError(err)
		if att == ProbeRefused {
			obs.State, obs.Notes = "closed", "icmp-port-unreachable"
		}
		return obs
	}
	obs.State, obs.Protocol, obs.Identified, obs.Result = "open", res.Protocol, true, res
	return obs
}

// probeUnknownUDP sends one minimal datagram to a port with no payload prober,
// only to catch an ICMP port-unreachable. A reply (unlikely) or silence leaves
// the port open_or_filtered — never a finding.
func (s *Scanner) probeUnknownUDP(ctx context.Context, addr netip.Addr, port int, timeout time.Duration, pace *udpPacer) Observation {
	obs := Observation{Addr: addr, Port: port, Transport: "udp", State: "open_or_filtered", Notes: "no-payload-prober"}
	if !pace.acquire(ctx) {
		obs.Notes = "cancelled"
		return obs
	}
	conn, err := s.dialPacedUDP(ctx, addr, port, timeout, pace)
	if err != nil {
		if classifyUDPProbeError(err) == ProbeRefused {
			obs.State, obs.Notes = "closed", "icmp-port-unreachable"
		}
		return obs
	}
	defer func() { _ = conn.Close() }()
	if _, err := udpExchange(conn, []byte{0x00}, timeout, 512); err != nil {
		if classifyUDPProbeError(err) == ProbeRefused {
			obs.State, obs.Notes = "closed", "icmp-port-unreachable"
		}
	}
	return obs
}

// dialUDP opens a connected UDP socket to addr:port through the injected
// dialer, so a connected socket surfaces ICMP port-unreachable as a read error.
func (s *Scanner) dialUDP(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := s.dialer.DialContext(dctx, "udp", netip.AddrPortFrom(addr, uint16(port)).String())
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("nil udp connection")
	}
	return conn, nil
}

// toLowerASCII lowercases an ASCII protocol label for a service hint.
func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// udpPacer spaces one host's datagrams at least interval apart, measured
// between the writes themselves. A sender takes the slot (acquire), which
// waits out the interval since the previous datagram, and keeps it until its
// own datagram has been written; only then does the interval for the next
// sender start. Reserving a time and sleeping until it is not enough: a
// goroutine that wakes late for its slot would send just ahead of the one
// that woke on time for the next, and after a stall several would send at once.
type udpPacer struct {
	interval time.Duration
	mu       sync.Mutex // held from acquire to release: the send slot
	last     time.Time  // when the previous datagram was written
}

// acquire waits for the host's next send slot and returns holding it; the
// caller must release it. It returns false, holding nothing, if ctx ends first.
func (p *udpPacer) acquire(ctx context.Context) bool {
	p.mu.Lock()
	if !sleepCtx(ctx, time.Until(p.last.Add(p.interval))) {
		p.mu.Unlock()
		return false
	}
	return true
}

// release gives the slot up. sent says whether a datagram was written while it
// was held; if not, the next sender owes no wait for it.
func (p *udpPacer) release(sent bool) {
	if sent {
		p.last = time.Now()
	}
	p.mu.Unlock()
}

// dialPacedUDP is dialUDP for a caller holding the pacer's slot: the slot is
// handed to the returned connection, which gives it up once its datagram is
// written (or on Close, if it never writes one). A failed dial releases it.
func (s *Scanner) dialPacedUDP(ctx context.Context, addr netip.Addr, port int, timeout time.Duration, pace *udpPacer) (net.Conn, error) {
	conn, err := s.dialUDP(ctx, addr, port, timeout)
	if err != nil {
		pace.release(false)
		return nil, err
	}
	return &pacedUDPConn{Conn: conn, ctx: ctx, pace: pace, held: true}, nil
}

// pacedUDPConn is a UDP socket whose every Write is one slot of its host's
// packet rate. It is used by one goroutine at a time, like the probers' conn.
type pacedUDPConn struct {
	net.Conn
	ctx  context.Context
	pace *udpPacer
	held bool // the slot was acquired and not yet spent
}

func (c *pacedUDPConn) Write(b []byte) (int, error) {
	if !c.held && !c.pace.acquire(c.ctx) {
		return 0, c.ctx.Err()
	}
	c.held = false
	n, err := c.Conn.Write(b)
	c.pace.release(true)
	return n, err
}

func (c *pacedUDPConn) Close() error {
	if c.held {
		c.held = false
		c.pace.release(false)
	}
	return c.Conn.Close()
}
