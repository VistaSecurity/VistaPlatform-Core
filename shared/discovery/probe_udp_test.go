package discovery

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestIsUDPProtocolReadsTheRegistry pins the transport of every OT prober. B-60
// was possible because the dispatch decision was hand-written ("probe these from
// the open-TCP-port loop") while the registration said UDP; the two disagreed
// and nothing noticed. Dispatch now derives from the registry, so this test is
// the statement of record for which protocols that makes UDP.
func TestIsUDPProtocolReadsTheRegistry(t *testing.T) {
	udp := []string{"BACnet", "BACNET", "EtherNet_IP", "ethernet-ip", "ETHERNETIP"}
	for _, p := range udp {
		if !IsUDPProtocol(p) {
			t.Errorf("IsUDPProtocol(%q) = false, want true — this prober dials UDP", p)
		}
	}
	tcp := []string{"Modbus", "OPC_UA", "SMB", "TLS", "SSH", "HTTPS", "nonsense"}
	for _, p := range tcp {
		if IsUDPProtocol(p) {
			t.Errorf("IsUDPProtocol(%q) = true, want false", p)
		}
	}
}

// TestPlanUDPProbesRequiresBothHalves pins the scope rule on the new dispatch
// path: a pair is planned only when the protocol AND the port were both
// requested. The planner may never invent a port — sending unauthenticated
// datagrams to a port nobody asked about would be a widening, not a fix.
func TestPlanUDPProbesRequiresBothHalves(t *testing.T) {
	tests := []struct {
		name             string
		protocols        []string
		ports            []int
		wantPairs        []ProtocolPort
		wantUndispatched []string
	}{
		{
			name:      "BACnet on its own port — the B-60 case",
			protocols: []string{"BACnet"},
			ports:     []int{47808},
			wantPairs: []ProtocolPort{{Protocol: "BACnet", Port: 47808}},
		},
		{
			name:      "EtherNet/IP on its own port",
			protocols: []string{"EtherNet_IP"},
			ports:     []int{44818},
			wantPairs: []ProtocolPort{{Protocol: "EtherNet_IP", Port: 44818}},
		},
		{
			name:      "OT protocol mixed into an IT port list probes only its own port",
			protocols: []string{"TLS", "BACnet"},
			ports:     []int{443, 8443, 47808},
			wantPairs: []ProtocolPort{{Protocol: "BACnet", Port: 47808}},
		},
		{
			name:             "requested protocol with no matching port is reported, not invented",
			protocols:        []string{"BACnet"},
			ports:            []int{443, 8443},
			wantUndispatched: []string{"BACnet"},
		},
		{
			name:      "TCP-registered OT protocols are not planned here",
			protocols: []string{"Modbus", "OPC_UA", "SMB"},
			ports:     []int{502, 4840, 445},
		},
		{
			name:      "TLS and SSH are never UDP-dispatched",
			protocols: []string{"TLS", "SSH"},
			ports:     []int{443, 22},
		},
		{
			name:      "duplicate requests collapse to one datagram stream",
			protocols: []string{"BACnet", "bacnet", "BAC-NET"},
			ports:     []int{47808, 47808},
			wantPairs: []ProtocolPort{{Protocol: "BACnet", Port: 47808}, {Protocol: "bacnet", Port: 47808}, {Protocol: "BAC-NET", Port: 47808}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pairs, undispatched := PlanUDPProbes(tt.protocols, tt.ports)
			if len(pairs) != len(tt.wantPairs) {
				t.Fatalf("pairs = %v, want %v", pairs, tt.wantPairs)
			}
			for i := range pairs {
				if pairs[i] != tt.wantPairs[i] {
					t.Errorf("pairs[%d] = %v, want %v", i, pairs[i], tt.wantPairs[i])
				}
			}
			if len(undispatched) != len(tt.wantUndispatched) {
				t.Fatalf("undispatched = %v, want %v", undispatched, tt.wantUndispatched)
			}
			for i := range undispatched {
				if undispatched[i] != tt.wantUndispatched[i] {
					t.Errorf("undispatched[%d] = %q, want %q", i, undispatched[i], tt.wantUndispatched[i])
				}
			}
		})
	}
}

// TestClassifyUDPProbeErrorSeparatesSilenceFromRefusal is the heart of "do not
// record an unanswered probe as a negative finding": a timeout and an ICMP port
// unreachable must not collapse into one bucket. Silence is inconclusive; a
// refusal is the host telling us nothing is bound there.
func TestClassifyUDPProbeErrorSeparatesSilenceFromRefusal(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
	refused := &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED)}
	garbage := errors.New("bacnet response wrong BVLC type 0x42")

	if got := classifyUDPProbeError(timeout); got != ProbeNoAnswer {
		t.Errorf("timeout classified as %q, want %q", got, ProbeNoAnswer)
	}
	if got := classifyUDPProbeError(refused); got != ProbeRefused {
		t.Errorf("ECONNREFUSED classified as %q, want %q", got, ProbeRefused)
	}
	if got := classifyUDPProbeError(garbage); got != ProbeError {
		t.Errorf("unparseable reply classified as %q, want %q", got, ProbeError)
	}
	if got := classifyUDPProbeError(nil); got != ProbeAnswered {
		t.Errorf("nil classified as %q, want %q", got, ProbeAnswered)
	}

	// Only silence and error leave the question open. A refusal is an answer.
	if !ProbeNoAnswer.Inconclusive() || !ProbeError.Inconclusive() {
		t.Error("no_answer and error must both be inconclusive")
	}
	if ProbeRefused.Inconclusive() || ProbeAnswered.Inconclusive() {
		t.Error("refused and answered are conclusive results")
	}
}

// TestProbeUDPRetriesSilence pins the retry choice: a single unanswered datagram
// is weak evidence — UDP has no retransmission, so one drop in either direction
// is indistinguishable from an absent device — so an unanswered probe sends two
// datagrams before reporting no_answer.
//
// The expected counts are LITERAL 2, not udpProbeAttempts. Asserting against the
// constant would make this test agree with any value the constant takes, which
// is a guard that cannot fail; changing the retry policy should have to change
// this line and its rationale deliberately.
func TestProbeUDPRetriesSilence(t *testing.T) {
	var received int64
	host, port := listenSilentUDP(t, &received)

	p := NewProber(200 * time.Millisecond)
	attempt := p.ProbeUDP(host, host, "BACnet", port)

	if attempt.Outcome != ProbeNoAnswer {
		t.Fatalf("Outcome = %q (detail %q), want %q", attempt.Outcome, attempt.Detail, ProbeNoAnswer)
	}
	if attempt.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", attempt.Attempts)
	}
	if got := atomic.LoadInt64(&received); got != 2 {
		t.Errorf("listener saw %d datagram(s), want 2 — the retry did not leave the host", got)
	}
	if attempt.Answered() {
		t.Error("an unanswered probe must never report Answered — that is the fabricated-device bug")
	}
	if !attempt.Outcome.Inconclusive() {
		t.Error("silence must be reported as inconclusive, not as confirmed absence")
	}
}

// TestProbeUDPAnsweredCarriesTheReply pins the success path: a device that does
// answer produces a parsed ProbeResult on the first attempt.
func TestProbeUDPAnsweredCarriesTheReply(t *testing.T) {
	var received int64
	host, port := listenBACnetResponder(t, &received)

	p := NewProber(2 * time.Second)
	attempt := p.ProbeUDP(host, host, "BACnet", port)

	if attempt.Outcome != ProbeAnswered {
		t.Fatalf("Outcome = %q (detail %q), want %q", attempt.Outcome, attempt.Detail, ProbeAnswered)
	}
	if attempt.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1 — an answer must stop the retry loop", attempt.Attempts)
	}
	if attempt.Result == nil {
		t.Fatal("Answered attempt carries no result")
	}
	if got := attempt.Result.Metadata["bacnet_device_instance"]; got != 1234 {
		t.Errorf("bacnet_device_instance = %v, want 1234", got)
	}
}

// TestProbeUDPUnregisteredProtocol pins that asking for a protocol with no UDP
// prober sends nothing at all rather than reporting a hollow no_answer.
func TestProbeUDPUnregisteredProtocol(t *testing.T) {
	p := NewProber(50 * time.Millisecond)
	attempt := p.ProbeUDP("192.0.2.1", "192.0.2.1", "Modbus", 502)
	if attempt.Outcome != ProbeError {
		t.Errorf("Outcome = %q, want %q", attempt.Outcome, ProbeError)
	}
	if attempt.Attempts != 0 {
		t.Errorf("Attempts = %d, want 0 — nothing should have been sent", attempt.Attempts)
	}
}

// listenSilentUDP binds a loopback UDP socket that reads datagrams and never
// replies — a device that is there but declines to answer, or a dropped reply.
func listenSilentUDP(t *testing.T, counter *int64) (host string, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback UDP: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			atomic.AddInt64(counter, 1)
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); wg.Wait() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), addr.Port
}

// listenBACnetResponder binds a loopback UDP socket that answers a Who-Is with a
// well-formed I-Am for device instance 1234.
func listenBACnetResponder(t *testing.T, counter *int64) (host string, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback UDP: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(counter, 1)
			if _, err := pc.WriteTo(bacnetIAm(), from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); wg.Wait() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), addr.Port
}

// bacnetIAm builds a BACnet/IP I-Am for device instance 1234 (object type 8 =
// device), per ASHRAE 135 §B.4 — the reply a real controller sends to a Who-Is.
func bacnetIAm() []byte {
	msg := []byte{
		0x81, 0x0A, 0x00, 0x00, // BVLC: BACnet/IP, Original-Unicast-NPDU, length patched below
		0x01, 0x00, // NPDU version, control
		0x10, 0x00, // APDU: Unconfirmed Request, service choice I-Am
		0xC4, 0x02, 0x00, 0x04, 0xD2, // Object identifier: (8 << 22) | 1234
		0x22, 0x01, 0xE0, // Max APDU length accepted
		0x91, 0x00, // Segmentation supported
		0x21, 0x63, // Vendor identifier
	}
	msg[2] = byte(len(msg) >> 8)
	msg[3] = byte(len(msg))
	return msg
}
