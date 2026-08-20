package discovery

// UDP probe dispatch and outcome classification, shared by the standalone
// sensor and the in-cluster Platform Sensor.
//
// WHY THIS FILE EXISTS
//
// A TCP port scan cannot tell you anything about a UDP-only service. Dispatching
// a UDP prober only for ports a TCP scan reported open means a BACnet/IP
// controller — which listens on UDP 47808 and nothing else — is never asked a
// question, while the job reports `completed` with zero findings and zero
// errors. That reads to the operator as "there are no BACnet devices on this
// segment": a false clean bill of health on a building-automation network.
//
// So UDP-registered probers are dispatched per requested (protocol, port) pair,
// independent of any TCP result. What that pair set may contain is deliberately
// narrow — see PlanUDPProbes.
//
// UDP HAS NO HANDSHAKE
//
// A TCP connect either completes or fails, and either answer is information.
// A UDP datagram that draws no reply is ambiguous three ways: nothing is
// listening, something is listening but chose not to answer, or a datagram was
// dropped in either direction. Absence of a reply is therefore NOT evidence of
// absence, and must never be recorded as one. ProbeOutcome keeps the three
// distinguishable cases apart so callers can be honest about which one they got.

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// ProbeOutcome is what a probe actually established, as opposed to what it
// found. The distinction that matters most is NoAnswer (we learned nothing)
// versus Refused (we learned there is no listener).
type ProbeOutcome string

const (
	// ProbeAnswered — the device replied and the reply parsed as the protocol.
	// This is the only outcome that is evidence a device exists.
	ProbeAnswered ProbeOutcome = "answered"

	// ProbeNoAnswer — the datagram(s) went out and nothing came back before the
	// deadline. INCONCLUSIVE: it means "no device", "device declined to answer"
	// or "packet dropped", and there is no way to tell which. Never record this
	// as a negative finding.
	ProbeNoAnswer ProbeOutcome = "no_answer"

	// ProbeRefused — the host actively rejected the datagram (ICMP port
	// unreachable, surfaced as ECONNREFUSED on the connected socket). This is
	// the one genuinely negative UDP result: the host is up and nothing is
	// bound to that port. Distinct from ProbeNoAnswer on purpose.
	ProbeRefused ProbeOutcome = "refused"

	// ProbeError — the probe could not be completed or the reply did not parse
	// as the protocol. Something may well be listening; we just cannot say what.
	ProbeError ProbeOutcome = "error"
)

// Inconclusive reports whether an outcome leaves the question unanswered — i.e.
// whether presenting it as "nothing is there" would be a lie.
func (o ProbeOutcome) Inconclusive() bool {
	return o == ProbeNoAnswer || o == ProbeError
}

// udpProbeAttempts is how many datagrams a UDP probe sends before giving up.
//
// One unanswered datagram is weak evidence: UDP has no retransmission, so a
// single drop in either direction is indistinguishable from an absent device.
// Two attempts roughly square the loss probability needed to hide a live device
// while bounding the worst case at 2×timeout plus one short delay — which
// matters because an OT job fans out over every target in a segment. We do not
// go higher: past two, the marginal confidence per extra second of scan time
// falls off, and a device that ignored two Who-Is requests is more likely
// declining to answer than dropping packets.
//
// A definitive outcome (Answered or Refused) stops the loop immediately — there
// is nothing a retry could add.
const udpProbeAttempts = 2

// udpProbeRetryDelay spaces the retry so it is not sent into the same transient
// congestion or rate-limit window that may have eaten the first datagram.
const udpProbeRetryDelay = 250 * time.Millisecond

// ProbeAttempt records a dispatched probe: what was asked, of whom, and what
// came back. It exists so a caller can distinguish "probed and got no answer"
// from "probed and confirmed absent" from "never probed" — the last being a
// pair that PlanUDPProbes never returned, and so never appears here at all.
type ProbeAttempt struct {
	Protocol  string
	Port      int
	Transport string // "udp"
	Outcome   ProbeOutcome
	Attempts  int    // datagrams actually sent
	Detail    string // wire/transport error text, when there was one
	Result    *ProbeResult
}

// Answered reports whether this attempt is evidence a device is there.
func (a ProbeAttempt) Answered() bool { return a.Outcome == ProbeAnswered && a.Result != nil }

// IsUDPProtocol reports whether the protocol's registered active prober speaks
// UDP. Dispatch decisions derive from this rather than from a hand-kept list,
// so moving a prober between transports moves its dispatch with it.
func IsUDPProtocol(protocol string) bool {
	_, ok := udpProberRegistry[CanonicalProtocolName(protocol)]
	return ok
}

// ProtocolPort is one dispatchable (protocol, port) pair.
type ProtocolPort struct {
	Protocol string
	Port     int
}

// PlanUDPProbes returns the (protocol, port) pairs that must be dispatched over
// UDP for a request, independent of any TCP port-scan result.
//
// SCOPE: this widens WHICH PROBERS RUN against an already-authorised target. It
// must never widen the target set or invent a port. A pair is returned only when
// BOTH halves were explicitly requested by the caller:
//
//   - the protocol appears in protocols and has a UDP-registered prober; and
//   - the port appears in ports and is a well-known port for that protocol
//     (PortSpeaks) — so asking for BACnet alongside an IT port list does not
//     spray Who-Is datagrams across 443 and 8443.
//
// A UDP protocol that matches none of the requested ports yields no pair. It is
// returned in `undispatched` instead so the caller can say so out loud rather
// than silently doing nothing — which is the failure this whole file exists to
// end.
func PlanUDPProbes(protocols []string, ports []int) (pairs []ProtocolPort, undispatched []string) {
	seen := make(map[ProtocolPort]bool)
	for _, protocol := range protocols {
		if !IsUDPProtocol(protocol) {
			continue
		}
		matched := false
		for _, port := range ports {
			if !PortSpeaks(port, protocol) {
				continue
			}
			pair := ProtocolPort{Protocol: protocol, Port: port}
			if seen[pair] {
				matched = true
				continue
			}
			seen[pair] = true
			pairs = append(pairs, pair)
			matched = true
		}
		if !matched {
			undispatched = append(undispatched, protocol)
		}
	}
	return pairs, undispatched
}

// ProbeUDP dispatches the UDP prober for protocol against ip:port, retrying per
// udpProbeAttempts, and classifies what came back. It never returns an error:
// the outcome IS the result, and "no answer" is a legitimate thing to have
// learned (namely, nothing).
//
// hostname is carried for identity/logging; the datagram goes to ip.
func (p *Prober) ProbeUDP(hostname, ip, protocol string, port int) ProbeAttempt {
	attempt := ProbeAttempt{
		Protocol:  protocol,
		Port:      port,
		Transport: "udp",
		Outcome:   ProbeError,
	}

	probe, ok := udpProberRegistry[CanonicalProtocolName(protocol)]
	if !ok {
		attempt.Detail = fmt.Sprintf("no UDP prober registered for protocol %q", protocol)
		return attempt
	}

	for i := 0; i < udpProbeAttempts; i++ {
		if i > 0 {
			time.Sleep(udpProbeRetryDelay)
		}
		attempt.Attempts = i + 1

		res, err := probe(p, hostname, ip, port)
		if err == nil && res != nil {
			attempt.Outcome = ProbeAnswered
			attempt.Result = res
			attempt.Detail = ""
			return attempt
		}
		if err == nil {
			// A prober that returns (nil, nil) has told us nothing.
			attempt.Outcome = ProbeNoAnswer
			attempt.Detail = "prober returned no result"
			continue
		}

		attempt.Outcome = classifyUDPProbeError(err)
		attempt.Detail = err.Error()
		if attempt.Outcome == ProbeRefused {
			// ICMP port unreachable is definitive; retrying cannot change it.
			return attempt
		}
	}

	return attempt
}

// classifyUDPProbeError maps a failed UDP probe onto the outcome it actually
// justifies. The important line is between a timeout (we learned nothing) and
// ECONNREFUSED (the host told us nothing is bound there).
func classifyUDPProbeError(err error) ProbeOutcome {
	if err == nil {
		return ProbeAnswered
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ProbeRefused
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ProbeNoAnswer
	}
	// Anything else — a malformed reply, a wrong protocol marker, a local
	// socket failure — means something happened that we cannot interpret.
	// Deliberately NOT folded into ProbeNoAnswer: a reply that failed to parse
	// is not the same as silence.
	return ProbeError
}
