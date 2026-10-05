package discovery

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// udpResponder binds a loopback UDP socket and replies to each datagram with
// reply(req); a nil return sends nothing (a black hole). It records every
// request it received. Loopback only.
type udpResponder struct {
	addr string
	mu   sync.Mutex
	reqs [][]byte
	pc   net.PacketConn
}

func startUDPResponder(t testing.TB, reply func(req []byte) []byte) *udpResponder {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen udp on loopback: %v", err)
	}
	r := &udpResponder{addr: pc.LocalAddr().String(), pc: pc}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			r.mu.Lock()
			r.reqs = append(r.reqs, req)
			r.mu.Unlock()
			if rep := reply(req); rep != nil {
				_, _ = pc.WriteTo(rep, from)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return r
}

func (r *udpResponder) requests() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.reqs...)
}

// remapUDPDialer dials every requested address to a single real loopback
// responder (or a closed port), recording which ports it was asked for.
type remapUDPDialer struct {
	target string // "ip:port" of the responder (or a closed port)
	mu     sync.Mutex
	ports  []int
}

func (d *remapUDPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.ports = append(d.ports, int(ap.Port()))
	d.mu.Unlock()
	var dl net.Dialer
	return dl.DialContext(ctx, network, d.target)
}

func udpScanner(t testing.TB, d Dialer) *Scanner {
	t.Helper()
	s, err := NewScanner(WithDialer(d), WithPaceProfile(testPace), WithUDPPacketRate(10000))
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

func onlyObs(t *testing.T, obs []Observation) Observation {
	t.Helper()
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1", len(obs))
	}
	return obs[0]
}

// ---- each service prober, against a minimal valid reply --------------------

func TestScanUDP_IdentifiesEachService(t *testing.T) {
	cases := []struct {
		name  string
		port  int
		proto string
		reply func(req []byte) []byte
	}{
		{"dns", 53, "DNS", func(req []byte) []byte {
			r := make([]byte, 12)
			if len(req) >= 2 {
				r[0], r[1] = req[0], req[1]
			}
			r[2] = 0x80 // QR
			return r
		}},
		{"ntp", 123, "NTP", func(req []byte) []byte {
			r := make([]byte, 48)
			r[0] = 0x24 // VN=4, mode=4 (server)
			r[1] = 0x02 // stratum
			return r
		}},
		{"snmp", 161, "SNMP", func(req []byte) []byte {
			return []byte{0x30, 0x05, 0x02, 0x01, 0x03, 0x04, 0x00}
		}},
		{"ike", 500, "IKE", func(req []byte) []byte {
			r := make([]byte, 28)
			copy(r[0:8], req[0:min(8, len(req))]) // echo initiator SPI
			r[17] = 0x20                          // IKEv2
			r[18] = 34                            // SA_INIT
			return r
		}},
		{"openvpn", 1194, "OpenVPN", func(req []byte) []byte {
			return []byte{byte(openvpnHardResetServerV2) << 3, 1, 2, 3, 4, 5, 6, 7, 8}
		}},
		{"dtls", 4433, "DTLS", func(req []byte) []byte {
			r := make([]byte, 13)
			r[0] = 22
			r[1] = 0xFE
			r[2] = 0xFD
			return r
		}},
		{"mdns", 5353, "mDNS", func(req []byte) []byte {
			r := make([]byte, 12)
			r[2] = 0x80 // QR
			return r
		}},
		{"ssdp", 1900, "SSDP", func(req []byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := startUDPResponder(t, tc.reply)
			d := &remapUDPDialer{target: resp.addr}
			s := udpScanner(t, d)
			obs, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{tc.port}, IdentifyOptions{ProbeTimeout: 500 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			o := onlyObs(t, obs)
			if !o.Identified || o.Protocol != tc.proto || o.State != "open" {
				t.Fatalf("%s: identified=%v protocol=%q state=%q notes=%q", tc.name, o.Identified, o.Protocol, o.State, o.Notes)
			}
		})
	}
}

// TestScanUDP_QUICVersionNegotiation covers the QUIC prober separately: the
// reply must be a long header with version 0.
func TestScanUDP_QUICVersionNegotiation(t *testing.T) {
	resp := startUDPResponder(t, func(req []byte) []byte {
		return []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x08, 0xde} // long header, version 0
	})
	d := &remapUDPDialer{target: resp.addr}
	s := udpScanner(t, d)
	obs, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{443}, IdentifyOptions{ProbeTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	// Port 443 maps to {QUIC, DTLS}; QUIC is first and must answer.
	o := onlyObs(t, obs)
	if !o.Identified || o.Protocol != "QUIC" {
		t.Fatalf("443: identified=%v protocol=%q", o.Identified, o.Protocol)
	}
}

func TestScanUDP_SharedPortContinuesAfterUnrecognisedReply(t *testing.T) {
	// UDP/443 can be QUIC or DTLS. A datagram that proves "not QUIC" is still
	// evidence that something answered, so the scanner must try the next curated
	// prober for the same port instead of giving up as open_or_filtered.
	resp := startUDPResponder(t, func(req []byte) []byte {
		r := make([]byte, 13)
		r[0] = 22
		r[1] = 0xFE
		r[2] = 0xFD
		return r
	})
	d := &remapUDPDialer{target: resp.addr}
	s := udpScanner(t, d)
	obs, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{443}, IdentifyOptions{ProbeTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	o := onlyObs(t, obs)
	if !o.Identified || o.Protocol != "DTLS" || o.State != "open" {
		t.Fatalf("443 fallback: identified=%v protocol=%q state=%q notes=%q", o.Identified, o.Protocol, o.State, o.Notes)
	}
	if got := len(resp.requests()); got < 2 {
		t.Fatalf("shared UDP port got %d request(s), want at least 2 so a later prober ran", got)
	}
}

// ---- honesty: no answer is not closed --------------------------------------

func TestScanUDP_NoAnswerIsOpenOrFiltered_NotClosed(t *testing.T) {
	resp := startUDPResponder(t, func([]byte) []byte { return nil }) // black hole
	d := &remapUDPDialer{target: resp.addr}
	s := udpScanner(t, d)
	obs, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{53}, IdentifyOptions{ProbeTimeout: 60 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	o := onlyObs(t, obs)
	if o.Identified {
		t.Error("black hole wrongly identified")
	}
	if o.State != "open_or_filtered" {
		t.Errorf("state=%q, want open_or_filtered (no answer must NOT be closed)", o.State)
	}
}

func TestScanUDP_RefusedPortIsClosed(t *testing.T) {
	// A closed UDP port: bind then release, so a connected socket's read gets
	// an ICMP port-unreachable (ECONNREFUSED) on platforms that report it.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen udp: %v", err)
	}
	closedAddr := pc.LocalAddr().String()
	_ = pc.Close()

	// Confirm the platform actually reports port-unreachable on a connected
	// UDP socket; skip where it does not (e.g. Windows disables it).
	probe, _ := net.Dial("udp", closedAddr)
	_ = probe.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = probe.Write([]byte{0})
	_, rerr := probe.Read(make([]byte, 1))
	_ = probe.Close()
	if classifyUDPProbeError(rerr) != ProbeRefused {
		t.Skipf("platform does not report UDP port-unreachable (got %v); refusal is undetectable here", rerr)
	}

	d := &remapUDPDialer{target: closedAddr}
	s := udpScanner(t, d)
	obs, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{53}, IdentifyOptions{ProbeTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	o := onlyObs(t, obs)
	if o.State != "closed" {
		t.Errorf("state=%q, want closed (ICMP port-unreachable)", o.State)
	}
}

// ---- scope: no payload sprayed across unrelated ports ----------------------

func TestScanUDP_UnknownPortSendsOnlyAMinimalDatagram(t *testing.T) {
	resp := startUDPResponder(t, func([]byte) []byte { return nil })
	d := &remapUDPDialer{target: resp.addr}
	s := udpScanner(t, d)
	const unknown = 33333 // not in the curated map
	if _, ok := curatedUDPPortProtocols[unknown]; ok {
		t.Fatal("pick a port not in the curated map")
	}
	obs, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{unknown}, IdentifyOptions{ProbeTimeout: 60 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	o := onlyObs(t, obs)
	if o.Identified || o.State != "open_or_filtered" {
		t.Errorf("unknown port: identified=%v state=%q, want unidentified open_or_filtered", o.Identified, o.State)
	}
	// A protocol payload (DNS query, NTP packet, …) must NOT have been sprayed:
	// only the single minimal byte.
	for _, req := range resp.requests() {
		if len(req) > 1 {
			t.Errorf("unknown port got a %d-byte payload; want a single minimal datagram", len(req))
		}
	}
}

// ---- no SNMP v1/v2c community guess ----------------------------------------

func TestScanUDP_SNMPProbeIsV3DiscoveryNotACommunityGuess(t *testing.T) {
	resp := startUDPResponder(t, func([]byte) []byte { return nil })
	d := &remapUDPDialer{target: resp.addr}
	s := udpScanner(t, d)
	if _, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{161}, IdentifyOptions{ProbeTimeout: 60 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	reqs := resp.requests()
	if len(reqs) == 0 {
		t.Fatal("no SNMP request sent")
	}
	for _, req := range reqs {
		// Every SNMP datagram must be a v3 message: SEQUENCE, INTEGER version 3.
		body, ok := berSkipSeqHeader(req)
		if !ok || len(body) < 3 || body[0] != 0x02 || body[1] != 0x01 || body[2] != 0x03 {
			t.Errorf("SNMP request is not a v3 discovery message (first bytes %x) — a community guess would be v0/v1", req[:min(8, len(req))])
		}
	}
}

// ---- OT UDP gating ----------------------------------------------------------

func TestScanUDP_OTPortRequiresOptIn(t *testing.T) {
	resp := startUDPResponder(t, func([]byte) []byte { return nil })
	d := &remapUDPDialer{target: resp.addr}
	s := udpScanner(t, d)
	// 47808 is BACnet (OT). Without opt-in, no datagram at all.
	obs, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{47808}, IdentifyOptions{ProbeTimeout: 60 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	o := onlyObs(t, obs)
	if o.Identified || o.Notes != "ot-opt-in-not-given" {
		t.Errorf("OT UDP port without opt-in: identified=%v notes=%q", o.Identified, o.Notes)
	}
	if n := len(resp.requests()); n != 0 {
		t.Errorf("OT UDP port probed %d times without opt-in, want 0", n)
	}
}

// ---- context cancellation --------------------------------------------------

func TestScanUDP_CancelStopsPromptly(t *testing.T) {
	resp := startUDPResponder(t, func([]byte) []byte { return nil }) // black hole
	d := &remapUDPDialer{target: resp.addr}
	s := udpScanner(t, d)
	var ports []int
	for p := 20000; p < 20060; p++ { // 60 custom ports, each a timeout
		ports = append(ports, p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	start := time.Now()
	obs, err := s.ScanUDP(ctx, mustAddr(t, "127.0.0.1"), ports, IdentifyOptions{ProbeTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cancel took %s to return", elapsed)
	}
	if len(obs) >= len(ports) {
		t.Errorf("processed %d/%d ports despite cancel — ctx ignored", len(obs), len(ports))
	}
}

func TestScanUDP_RefusesBadAddress(t *testing.T) {
	s := udpScanner(t, &remapUDPDialer{target: "127.0.0.1:1"})
	if _, err := s.ScanUDP(context.Background(), netip.Addr{}, []int{53}, IdentifyOptions{}); err == nil {
		t.Error("accepted the zero address")
	}
}

func TestScanUDP_RejectsUnknownOTProbe(t *testing.T) {
	s := udpScanner(t, &remapUDPDialer{target: "127.0.0.1:1"})
	if _, err := s.ScanUDP(context.Background(), mustAddr(t, "127.0.0.1"), []int{47808}, IdentifyOptions{OTProbes: []string{"S7"}}); err == nil {
		t.Error("accepted an OT probe with no safe prober")
	}
}

func TestCuratedUDPPorts_ExcludeOTPorts(t *testing.T) {
	ot := map[int]bool{}
	for _, p := range OTUDPPorts() {
		ot[p] = true
	}
	if len(ot) == 0 {
		t.Fatal("no OT UDP ports")
	}
	for _, p := range CuratedUDPPorts() {
		if ot[p] {
			t.Errorf("curated UDP port %d is also an OT UDP port — OT must be gated separately", p)
		}
	}
}

func TestWithUDPPacketRate_Validation(t *testing.T) {
	if _, err := NewScanner(WithUDPPacketRate(-1)); err == nil {
		t.Error("accepted a negative UDP packet rate")
	}
	if _, err := NewScanner(WithUDPPacketRate(50)); err != nil {
		t.Errorf("WithUDPPacketRate(50): %v", err)
	}
}
