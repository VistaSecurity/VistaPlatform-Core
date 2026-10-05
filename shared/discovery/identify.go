package discovery

// Service identification.
//
// ScanOpenPorts / Scan answer "which TCP ports accept a connection". Identify
// answers the next question — "what is speaking there" — for the open ports of
// a host, and it answers HONESTLY: a port it cannot name stays a first-class
// observation (an open, unidentified endpoint), never a dropped result and
// never a guess (hole H13; decision D5).
//
// The envelope is the scanner's: Identify contacts only the address handed to
// it (from a HostScan the caller already produced for a dispatchguard-cleared
// target), resolves no name, and reuses the run's per-host / pace / process
// connection budget. It honours context cancellation.
//
// Two rules keep identification from being the aggressive application-layer
// probing the port scan deliberately is not (hole H15):
//
//   - At most ONE speculative payload per port: a single TLS ClientHello into a
//     silent port. The banner wait writes nothing (it reads what a
//     server-speaks-first service sends unprompted). Everything else — the SSH,
//     SMB and OT handshakes — runs only once a prior read or the port number
//     has already identified the service, so it is not speculative. So do the
//     follow-up handshakes a TLS port gets, made only after its identifying
//     handshake SUCCEEDED, one at a time, each through the same gate: the
//     key-exchange support handshakes (at most one per question that handshake
//     left open — classical-only, hybrid-only — so at most two, in practice
//     one, as a TLS 1.3 handshake always answers one of them; both share one
//     probe timeout), then TLS version enumeration (decision D4 of the
//     one-scan-path spec: one forced-version handshake per version the first
//     did not prove, so at most three). A TLS port therefore receives at most
//     six ClientHellos: 1 identifying + 2 support + 3 enumeration.
//   - A TLS port that answers the nameless ClientHello with a TLS ALERT may be
//     offered the target's known names (IdentifyOptions.SNICandidates, at most
//     MaxSNICandidates = 3), one more ClientHello per name, stopping at the
//     first that negotiates. That is 3 extra connections at most, to a port
//     that has just proved it speaks TLS; none on an OT-suspect host, none when
//     the first attempt succeeded or failed for any other reason. The follow-up
//     handshakes of a port that then negotiates use that name, so the maximum
//     per port becomes 1 + 3 + 2 + 3 = nine, and only for a port that refused.
//   - OT/ICS ports (OTPorts()) are connect-only during identification: no
//     banner read, no TLS hello, no probe at all, UNLESS the caller opted in to
//     that protocol (IdentifyOptions.OTProbes) and the port is its standard
//     port. On a host already found OT-suspect, even regular ports get no
//     speculative payload beyond the well-known pairings (TLS only where
//     PortSpeaks(port,"TLS"); SMB only on 445/139; SSH recognised read-only;
//     no key-exchange support handshake and no TLS version enumeration — the
//     one handshake is all such a host gets).
//
// Raw banner bytes are NEVER retained. A banner we recognise yields a service
// hint; a banner we do not recognise yields only its length. Keeping the bytes
// of an unknown service's greeting would be collecting data we cannot read and
// have no use for (CLAUDE.md "Collect posture, never key material").

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Observation is what Identify learned about one open port. It is neutral — no
// models import — so both runtimes can map it onto their finding shape (WP2):
// the Platform Sensor onto discovery_findings, the standalone Sensor onto its
// models.DiscoveryFinding.
//
// An unidentified open port is a first-class Observation (Identified=false,
// State "open"): decision D5 makes it an endpoint that can become inventory
// through the normal approval flow, so it is recorded, not dropped.
type Observation struct {
	Addr      netip.Addr `json:"addr"`
	Port      int        `json:"port"`
	Transport string     `json:"transport"` // "tcp" or "udp"
	// State is the port's state in the identification vocabulary: "open",
	// "closed", "filtered", or "open_or_filtered" (a UDP port that neither
	// answered nor was refused).
	State string `json:"state"`
	// Protocol is the canonical protocol name when identified (e.g. "TLS",
	// "SSH", "SMB", "Modbus"), or "" when the port could not be named.
	Protocol string `json:"protocol,omitempty"`
	// ServiceHint is a weak label from the banner signature table ("ftp",
	// "smtp", "mysql", …) when the service was recognised but no dedicated
	// prober produced a Result. It may be set even when Identified is false.
	ServiceHint string `json:"service_hint,omitempty"`
	// Identified is true only when the service was positively determined — a
	// recognised banner, a completed TLS/SSH/SMB/OT probe. An open port with a
	// mere ServiceHint and no Result is NOT identified.
	Identified bool `json:"identified"`
	// Result is the full canonical prober output when a prober ran (TLS
	// certificates and cipher/version, SSH algorithms, SMB dialect, OT
	// identity). It reuses ProbeResult — the single certificate shape — so
	// nothing here forks x509 extraction. Nil when no prober ran.
	Result *ProbeResult `json:"result,omitempty"`
	// Metadata carries lightweight identification detail that is not a full
	// prober Result: "banner_len" (bytes read, never the bytes themselves),
	// and flags like "ot_connect_only".
	Metadata map[string]any `json:"metadata,omitempty"`
	// Notes records what happened during identification when it is worth
	// saying out loud: "closed-during-identify", "reset-during-identify",
	// "timeout-during-identify", "ot-opt-in-not-given".
	Notes string `json:"notes,omitempty"`
}

// IdentifyOptions configures one Identify call.
type IdentifyOptions struct {
	// Hostname is the SNI to present on the TLS attempt (and identity for the
	// probers). The datagram/handshake still goes to the HostScan's IP; this
	// never triggers a name resolution. Empty means no SNI (probe the IP).
	Hostname string
	// SNICandidates are names the target is known by, offered one at a time
	// ONLY if the first TLS attempt of a port is answered with a TLS alert (the
	// server wants a name an address scan did not give it). Sanitized
	// (SanitizeSNICandidates: DNS names, at most MaxSNICandidates, no IP
	// literals) inside the engine, so a caller cannot widen the bound. Never
	// resolved and never used to choose where to connect: the address is fixed.
	// Ignored on an OT-suspect host and when Hostname already names the target.
	SNICandidates []string
	// OTProbes lists the OT/ICS protocols (canonical names, e.g. "Modbus",
	// "OPC_UA") the caller has explicitly opted in to actively probing during
	// identification. Anything not in this list — or on a non-standard port —
	// leaves OT ports connect-only. Validated against the OT prober registry.
	OTProbes []string
	// BannerWait overrides the server-speaks-first banner read window. Zero
	// means the pace-derived default (defaultBannerWait scaled by pace).
	BannerWait time.Duration
	// ProbeTimeout overrides the per-probe timeout handed to the TLS/SSH/SMB/OT
	// probers. Zero means defaultIdentifyProbeTimeout.
	ProbeTimeout time.Duration
	// OutboundGuard, when set, is applied to every fetch a scanned server's own
	// data asks for during identification — the OCSP responder named in the
	// certificate the TLS attempt receives (see outbound.go). A platform
	// runtime MUST set it: without it that fetch uses the default client, and a
	// scanned host could point the platform at cloud metadata, loopback or an
	// in-cluster Service. The standalone sensor leaves it nil.
	OutboundGuard AddressGuard
}

const (
	// defaultBannerWait is the server-speaks-first read window at the normal
	// pace. Long enough for a loaded SSH/SMTP server to send its greeting,
	// short enough that a silent port (the common case) does not stall the
	// scan. Scaled by pace in bannerWaitFor.
	defaultBannerWait = 750 * time.Millisecond
	// defaultIdentifyProbeTimeout bounds each delegated prober (a TLS or SSH
	// handshake needs more than a bare connect).
	defaultIdentifyProbeTimeout = 4 * time.Second
	// maxBannerRead caps the banner read. We only ever look at a greeting's
	// first bytes to classify it, and never store them.
	maxBannerRead = 512
)

// sniCandidatesFor is the names a port that refuses the nameless attempt may be
// offered: the sanitized, bounded list, minus the name already presented.
func sniCandidatesFor(opts IdentifyOptions) []string {
	var out []string
	for _, n := range SanitizeSNICandidates(opts.SNICandidates) {
		if n != strings.ToLower(opts.Hostname) {
			out = append(out, n)
		}
	}
	return out
}

// bannerWaitFor derives the banner read window from the pace: it scales
// defaultBannerWait by the pace's connect timeout relative to the normal pace,
// so a polite scan waits longer and a fast scan less. opts.BannerWait overrides.
func (s *Scanner) bannerWaitFor(opts IdentifyOptions) time.Duration {
	if opts.BannerWait > 0 {
		return opts.BannerWait
	}
	normal := paceProfiles[PaceNormal].ConnectTimeout
	w := time.Duration(float64(defaultBannerWait) * float64(s.pace.ConnectTimeout) / float64(normal))
	return max(250*time.Millisecond, min(w, 2*time.Second))
}

// Identify determines what is listening on each open port of h and returns one
// Observation per open port, in ascending port order. It never contacts an
// address other than h.Addr and never resolves a name. When h.OTSuspect is set
// (an OT port answered open during the scan), regular ports are restricted to
// the well-known pairings only — no speculative TLS into an unknown silent port.
func (s *Scanner) Identify(ctx context.Context, h HostScan, opts IdentifyOptions) ([]Observation, error) {
	addr, err := normalizeTarget(h.Addr)
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
	// One ClientHello per probe: the prober's own key-exchange support
	// handshakes would redial around the gate. The identifier makes them
	// itself after a confirmed TLS handshake (measureTLSKeyExchangeSupport),
	// as it does version enumeration, gated like every other connection.
	prober := NewProber(timeout).WithoutSupportHandshakes()
	if opts.OutboundGuard != nil {
		prober = prober.WithOutboundAddressGuard(opts.OutboundGuard)
	}
	bannerWait := s.bannerWaitFor(opts)

	r := s.newRun(ctx, 1)
	r.phase.Store(PhasePorts)

	ports := append([]int(nil), h.Open...)
	var regular, otPorts []int
	for _, p := range ports {
		if OTPorts().Contains(p) {
			otPorts = append(otPorts, p)
		} else {
			regular = append(regular, p)
		}
	}

	out := make([]Observation, len(ports))
	index := make(map[int]int, len(ports))
	for i, p := range ports {
		index[p] = i
	}

	hctx, stop := context.WithCancel(ctx)
	defer stop()
	hostSlot := make(chan struct{}, s.pace.PerHostConcurrency)

	ident := identifier{
		run:        r,
		prober:     prober,
		addr:       addr,
		hostname:   opts.Hostname,
		candidates: sniCandidatesFor(opts),
		bannerWait: bannerWait,
		suspect:    h.OTSuspect,
		otOptIn:    otOptIn,
		hostSlot:   hostSlot,
	}

	// Regular ports in parallel (capped to the OT-suspect ceiling on a suspect
	// host, so identification does not undo the scan's own throttle); OT ports
	// strictly one connection at a time.
	parallel := s.pace.PerHostConcurrency
	if h.OTSuspect {
		parallel = min(parallel, s.otSuspectConc)
	}
	var wg sync.WaitGroup
	if len(regular) > 0 {
		feed := make(chan int)
		wg.Go(func() {
			defer close(feed)
			for _, p := range regular {
				select {
				case feed <- p:
				case <-hctx.Done():
					return
				}
			}
		})
		for range min(parallel, len(regular)) {
			wg.Go(func() {
				for p := range feed {
					out[index[p]] = ident.identifyRegular(hctx, p)
				}
			})
		}
	}
	if len(otPorts) > 0 {
		wg.Go(func() {
			for _, p := range otPorts {
				out[index[p]] = ident.identifyOT(hctx, p)
			}
		})
	}
	wg.Wait()

	return out, nil
}

// identifier carries the per-call identification state.
type identifier struct {
	run        *run
	prober     *Prober
	addr       netip.Addr
	hostname   string
	candidates []string // sanitized SNI names to try after a TLS alert
	bannerWait time.Duration
	suspect    bool
	otOptIn    map[string]bool // folded canonical name -> opted in
	hostSlot   chan struct{}
}

// bannerState is what the banner read established.
type bannerState uint8

const (
	bannerGotData bannerState = iota // the server sent bytes unprompted
	bannerSilent                     // nothing within the window; port alive
	bannerClosed                     // EOF/refusal before any byte
	bannerReset                      // connection reset during the read
	bannerAborted                    // our context ended
)

// identifyRegular identifies one open non-OT port.
func (id *identifier) identifyRegular(ctx context.Context, port int) Observation {
	obs := Observation{Addr: id.addr, Port: port, Transport: "tcp", State: "open"}
	ap := netip.AddrPortFrom(id.addr, uint16(port))

	conn, release, ok := id.run.dialGated(ctx, id.hostSlot, "tcp", ap)
	if !ok {
		// Could not reconnect now (slot/ctx) — say so rather than invent a
		// verdict. The scan already found it open.
		obs.Notes = "unreachable-during-identify"
		return obs
	}
	// The banner read reuses conn; a path that hands conn to a prober calls
	// release itself, so release here only covers the paths that do not.
	banner, st := readBanner(conn, id.bannerWait)
	n := len(banner)
	// banner is discarded below — never stored.
	switch st {
	case bannerAborted:
		release()
		obs.Notes = "timeout-during-identify"
		return obs
	case bannerClosed:
		release()
		obs.State, obs.Notes = "open", "closed-during-identify"
		return obs
	case bannerReset:
		release()
		obs.State, obs.Notes = "open", "reset-during-identify"
		return obs
	}

	if st == bannerGotData {
		sig := matchBanner(banner)
		if sig != nil {
			obs.ServiceHint = sig.hint
			if sig.protocol == "SSH" {
				release() // the banner stream is consumed; the prober re-dials
				return id.identifySSH(ctx, port, obs)
			}
			// Recognised a server-speaks-first service we have no crypto
			// prober for (FTP/SMTP/POP3/IMAP/MySQL). The recognition itself is
			// the identification; we keep the hint, not the bytes.
			release()
			obs.Protocol = sig.protocol
			obs.Identified = true
			obs.Metadata = map[string]any{"banner_len": n}
			return obs
		}
		// Bytes we do not recognise. Keep the length only — not the bytes.
		release()
		obs.Metadata = map[string]any{"banner_len": n}
		obs.Notes = "unidentified-banner"
		return obs
	}

	// Silent port (client-speaks-first). One speculative payload is allowed.
	// 445/139 are SMB, not TLS: go straight to SMB so we send exactly one
	// payload, never a wasted ClientHello then an SMB negotiate.
	switch {
	case port == 445 || port == 139:
		if id.suspect && !PortSpeaks(port, "SMB") {
			release()
			return id.unidentifiedSilent(obs, n)
		}
		return id.probeThenObserve(ctx, conn, release, port, "SMB", obs, n)
	case id.suspect && !PortSpeaks(port, "TLS"):
		// Suspect host: no speculative TLS into a port not known to speak it.
		release()
		obs.Notes = "ot-suspect-no-speculative-payload"
		return id.unidentifiedSilent(obs, n)
	default:
		return id.probeThenObserve(ctx, conn, release, port, "TLS", obs, n)
	}
}

// unidentifiedSilent fills an open-but-unidentified observation for a silent
// port, recording the banner length (0) without a hint.
func (id *identifier) unidentifiedSilent(obs Observation, bannerLen int) Observation {
	obs.Metadata = map[string]any{"banner_len": bannerLen}
	return obs
}

// probeThenObserve hands the already-open conn to the named prober (reusing the
// one connection and, for TLS, spending the one allowed ClientHello) and maps
// the result onto obs. It owns releasing conn.
func (id *identifier) probeThenObserve(ctx context.Context, conn net.Conn, release func(), port int, protocol string, obs Observation, bannerLen int) Observation {
	var (
		res *ProbeResult
		kex *tlsKexFollowUp
		err error
	)
	if isTLSProtocol(protocol) {
		// The TLS prober's own handshake, kept apart from its support
		// handshakes so those can be made below, through the gate.
		res, kex, err = handshakeTLSConn(context.Background(), id.prober, conn, id.hostname, port)
	} else {
		res, err = runTCPProberOnConn(id.prober, conn, protocol, id.hostname, port)
	}
	// Released before the follow-up handshakes dial again: a worker holding
	// this slot while it waits for another could exhaust the per-host slots.
	release()
	sni := id.hostname
	var refused *TLSHandshakeRefusedError
	if isTLSProtocol(protocol) && errors.As(err, &refused) && !id.suspect {
		// The server answered the nameless ClientHello with an alert. Offer the
		// names the target is known by, one connection each, through the same
		// gate, until one negotiates (sniCandidates).
		if r2, k2, name := id.retryTLSWithNames(ctx, port); r2 != nil {
			res, kex, err, sni = r2, k2, nil, name
			res.Metadata["sni_used"] = name
		}
	}
	if err != nil || res == nil {
		obs.Metadata = map[string]any{"banner_len": bannerLen}
		if errors.As(err, &refused) {
			// The server answered our ClientHello with a TLS alert: the port
			// speaks TLS, it just would not negotiate with us (typically it
			// requires a server name, and an address target has none). Named,
			// like an SSH banner whose handshake failed — not filed as an
			// unidentified port.
			obs.Protocol = "TLS"
			obs.Identified = true
			obs.ServiceHint = "tls"
			obs.Metadata["tls_handshake_alert"] = refused.Alert
			obs.Notes = "tls-handshake-refused"
			return obs
		}
		obs.Notes = strings.ToLower(protocol) + "-attempt-failed"
		return obs
	}
	if kex != nil && !id.suspect {
		id.measureTLSKeyExchangeSupport(ctx, port, res, kex)
		id.enumerateTLSVersions(ctx, port, res, sni)
	}
	obs.Protocol = res.Protocol
	obs.Identified = true
	obs.Result = res
	return obs
}

// retryTLSWithNames makes the TLS attempt again for each candidate name, in
// order, each over its own gated connection to the SAME address, and returns the
// first that negotiates with the name it negotiated under. A connection the gate
// refuses ends the retries (the port may not be reachable now); any other failure
// moves on to the next name. At most len(id.candidates) <= MaxSNICandidates
// connections.
func (id *identifier) retryTLSWithNames(ctx context.Context, port int) (*ProbeResult, *tlsKexFollowUp, string) {
	ap := netip.AddrPortFrom(id.addr, uint16(port))
	for _, name := range id.candidates {
		if ctx.Err() != nil {
			return nil, nil, ""
		}
		conn, release, ok := id.run.dialGated(ctx, id.hostSlot, "tcp", ap)
		if !ok {
			return nil, nil, ""
		}
		res, kex, err := handshakeTLSConn(context.Background(), id.prober, conn, name, port)
		release()
		if err == nil && res != nil {
			return res, kex, name
		}
	}
	return nil, nil, ""
}

// isTLSProtocol reports whether protocol names the registry's TLS prober.
func isTLSProtocol(protocol string) bool {
	fold := CanonicalProtocolName(protocol)
	return fold == CanonicalProtocolName("TLS") || fold == CanonicalProtocolName("HTTPS")
}

// errEnumerationDial is what an enumeration dial reports when the gate (slot,
// pace, descriptor budget or context) refused the connection.
var errEnumerationDial = errors.New("discovery: no connection for TLS version enumeration")

// errKexSupportDial is what a key-exchange support dial reports when the gate
// (slot, pace, descriptor budget or context) refused the connection.
var errKexSupportDial = errors.New("discovery: no connection for a TLS key-exchange support handshake")

// measureTLSKeyExchangeSupport asks a confirmed TLS listener the key-exchange
// questions its identifying handshake left open — does it also accept a
// classical-only offer, a hybrid-post-quantum-only one — with at most one
// handshake per question (MeasureTLSKeyExchange), all within one probe
// timeout. Every connection goes through the run's gate and the scanner's
// dialer, one at a time, and the unit's context bounds the dial and closes a
// connection mid-handshake when it ends. A question whose handshake could not
// be made stays unanswered (absent), never false.
func (id *identifier) measureTLSKeyExchangeSupport(ctx context.Context, port int, res *ProbeResult, kex *tlsKexFollowUp) {
	ap := netip.AddrPortFrom(id.addr, uint16(port))
	dial := func(timeout time.Duration) (net.Conn, error) {
		if ctx.Err() != nil {
			return nil, errKexSupportDial
		}
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, release, ok := id.run.dialGated(dctx, id.hostSlot, "tcp", ap)
		if !ok {
			return nil, errKexSupportDial
		}
		// The support handshake has a deadline but no context: tie the
		// connection to the unit's so cancellation ends it at once.
		stop := context.AfterFunc(ctx, release)
		return &releasingConn{Conn: conn, release: func() { stop(); release() }}, nil
	}
	kex.measureSupport(res, dial, id.prober.timeout)
}

// enumerateTLSVersions adds to res the other TLS versions a confirmed TLS
// listener accepts. Every connection goes through the run's gate and the
// scanner's dialer, one at a time, and honours ctx; the negotiated version is
// already proven and stays first.
func (id *identifier) enumerateTLSVersions(ctx context.Context, port int, res *ProbeResult, sni string) {
	ap := netip.AddrPortFrom(id.addr, uint16(port))
	dial := func(ctx context.Context) (net.Conn, error) {
		conn, release, ok := id.run.dialGated(ctx, id.hostSlot, "tcp", ap)
		if !ok {
			return nil, errEnumerationDial
		}
		return &releasingConn{Conn: conn, release: release}, nil
	}
	applyTLSVersions(res, enumerateTLSVersions(ctx, dial, sni, id.prober.timeout, negotiatedTLSVersion(res)))
}

// releasingConn hands a gated connection to code that only knows net.Conn:
// Close returns the gate's slots along with the socket.
type releasingConn struct {
	net.Conn
	release func()
}

func (c *releasingConn) Close() error {
	c.release()
	return nil
}

// identifySSH runs the SSH prober on a fresh gated connection (the banner read
// consumed the identification line on the first connection). It is not a
// speculative write: the banner already said this is SSH.
func (id *identifier) identifySSH(ctx context.Context, port int, obs Observation) Observation {
	ap := netip.AddrPortFrom(id.addr, uint16(port))
	if id.suspect {
		// On an OT-suspect host, SSH is recognised read-only: the banner is
		// enough to name it, and the full handshake prober (which writes) is
		// withheld.
		obs.Protocol = "SSH"
		obs.Identified = true
		obs.ServiceHint = "ssh"
		obs.Notes = "ot-suspect-ssh-banner-only"
		return obs
	}
	conn, release, ok := id.run.dialGated(ctx, id.hostSlot, "tcp", ap)
	if !ok {
		obs.Protocol = "SSH"
		obs.Identified = true
		obs.ServiceHint = "ssh"
		obs.Notes = "ssh-handshake-unreachable"
		return obs
	}
	defer release()
	res, err := probeSSH(id.prober, conn, id.hostname, port)
	if err != nil || res == nil {
		obs.Protocol = "SSH"
		obs.Identified = true
		obs.ServiceHint = "ssh"
		obs.Notes = "ssh-handshake-failed"
		return obs
	}
	obs.Protocol = "SSH"
	obs.Identified = true
	obs.Result = res
	return obs
}

// identifyOT identifies one open OT/ICS port. Connect-only by default: the port
// is recorded with its well-known service hint but Identified stays false. A
// prober runs only when the caller opted in to that protocol AND the port is
// the protocol's standard TCP port.
func (id *identifier) identifyOT(ctx context.Context, port int) Observation {
	obs := Observation{Addr: id.addr, Port: port, Transport: "tcp", State: "open"}
	protos, _ := WellKnownProtocolsForPort(port)
	if len(protos) > 0 {
		obs.ServiceHint = strings.ToLower(protos[0])
	}

	proto, run := id.otProbeForPort(port)
	if !run {
		obs.Metadata = map[string]any{"ot_connect_only": true}
		if len(id.otOptIn) == 0 {
			obs.Notes = "ot-opt-in-not-given"
		} else {
			obs.Notes = "ot-connect-only"
		}
		return obs
	}

	ap := netip.AddrPortFrom(id.addr, uint16(port))
	conn, release, ok := id.run.dialGated(ctx, id.hostSlot, "tcp", ap)
	if !ok {
		obs.Metadata = map[string]any{"ot_connect_only": true}
		obs.Notes = "ot-probe-unreachable"
		return obs
	}
	defer release()
	res, err := runTCPProberOnConn(id.prober, conn, proto, id.hostname, port)
	if err != nil || res == nil {
		obs.Notes = "ot-probe-failed"
		return obs
	}
	obs.Protocol = res.Protocol
	obs.Identified = true
	obs.Result = res
	return obs
}

// otProbeForPort returns the OT protocol to probe on port and whether to probe
// it: only when the caller opted in to that protocol AND port is its standard
// TCP port AND a TCP prober is registered for it. Returns ("", false) otherwise.
func (id *identifier) otProbeForPort(port int) (string, bool) {
	protos, ok := WellKnownProtocolsForPort(port)
	if !ok {
		return "", false
	}
	for _, p := range protos {
		fold := CanonicalProtocolName(p)
		if !id.otOptIn[fold] {
			continue
		}
		if _, isTCP := tcpProberRegistry[fold]; !isTCP {
			continue // e.g. EtherNet_IP/BACnet probers are UDP — see ScanUDP
		}
		return p, true
	}
	return "", false
}

// readBanner reads up to maxBannerRead bytes from a server that is expected to
// speak first, within wait. It WRITES NOTHING. The bytes are returned only so
// the caller can classify them; the caller must not store them.
func readBanner(conn net.Conn, wait time.Duration) ([]byte, bannerState) {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, maxBannerRead)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], bannerGotData
	}
	switch {
	case err == nil:
		return nil, bannerSilent
	case isTimeout(err):
		return nil, bannerSilent // alive, just quiet — try the one TLS payload
	case errors.Is(err, net.ErrClosed):
		return nil, bannerAborted
	default:
		if isReset(err) {
			return nil, bannerReset
		}
		return nil, bannerClosed
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isReset(err error) bool {
	s := err.Error()
	return strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed")
}

// runTCPProberOnConn dispatches a registered TCP prober on an already-open
// connection — the one the identifier dialled through the gate — so the
// identification spends exactly one connection (and, for TLS, one ClientHello).
func runTCPProberOnConn(p *Prober, conn net.Conn, protocol, hostname string, port int) (*ProbeResult, error) {
	fold := CanonicalProtocolName(protocol)
	probe, ok := tcpProberRegistry[fold]
	if !ok {
		return nil, errors.New("no TCP prober for " + protocol)
	}
	return probe(p, conn, hostname, port)
}

// validateOTProbes folds and validates the caller's OT opt-in against the OT
// prober registry (re-derived here so this package does not import
// cluster-sensor's allowlist). An unknown protocol is an error, not a silent
// drop: an opt-in the caller believes they gave but that does nothing is worse
// than a refusal.
func validateOTProbes(names []string) (map[string]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	allowed := otIdentifiableProtocols()
	out := make(map[string]bool, len(names))
	for _, n := range names {
		fold := CanonicalProtocolName(n)
		if !allowed[fold] {
			return nil, errors.New("unknown or non-identifiable OT probe protocol: " + n)
		}
		out[fold] = true
	}
	return out, nil
}

// otIdentifiableProtocols is the set of OT/ICS protocols (folded canonical
// names) that identification can actively probe: a protocol whose standard port
// is an OT port AND that has a registered prober. Derived from the port map and
// the prober registries, so it tracks probe_ot.go's registrations with no hand-
// kept copy.
func otIdentifiableProtocols() map[string]bool {
	out := map[string]bool{}
	for port, protos := range cryptoPortProtocols {
		if !OTPorts().Contains(port) {
			continue
		}
		for _, p := range protos {
			if HasProber(p) {
				out[CanonicalProtocolName(p)] = true
			}
		}
	}
	return out
}
