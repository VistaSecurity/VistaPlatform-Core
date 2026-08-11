package capture

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// newTestMMSFactory wires a factory to a buffered channel and a fresh
// 60-minute connection cache.
func newTestMMSFactory(t *testing.T) (*MMSStreamFactory, chan *models.CryptoDiscovery) {
	t.Helper()
	ch := make(chan *models.CryptoDiscovery, 4)
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	return NewMMSStreamFactory(ch, "test-sensor", connCache), ch
}

func feedMMS(s tcpassembly.Stream, data []byte) {
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: data, Seen: time.Now()}})
}

// preState builds a session map entry directly so tests don't have to
// construct gopacket.Flow objects to exercise New().
func preState(f *MMSStreamFactory) (*MMSStream, *mmsSessionState) {
	state := &mmsSessionState{
		sessionID:  "s1",
		serverIP:   "10.0.0.5",
		serverPort: 102,
		clientIP:   "10.0.0.10",
		iface:      "eth0",
	}
	f.mu.Lock()
	f.sessions[tlsFlowKey{}] = state
	f.mu.Unlock()
	return &MMSStream{factory: f, key: tlsFlowKey{}, state: state}, state
}

func TestMMSAssembler_CRPDUEmitsMMSWithTSAPs(t *testing.T) {
	t.Parallel()
	factory, ch := newTestMMSFactory(t)
	stream, _ := preState(factory)

	// Source TSAP: 0x00 0x01 ; Destination TSAP: ASCII "MMS"
	cr := buildCRPDU([]byte{0x00, 0x01}, []byte("MMS"))
	feedMMS(stream, cr)

	select {
	case d := <-ch:
		if d.Protocol != "MMS" {
			t.Errorf("Protocol=%s, want MMS", d.Protocol)
		}
		if d.CipherSuite != "" {
			t.Errorf("CipherSuite=%q, want empty", d.CipherSuite)
		}
		if d.Port != 102 {
			t.Errorf("Port=%d, want 102", d.Port)
		}
		if d.RawMetadata["security"] != "none" {
			t.Errorf("security=%v, want none", d.RawMetadata["security"])
		}
		if d.RawMetadata["iec62351_applicable"] != true {
			t.Errorf("iec62351_applicable=%v, want true", d.RawMetadata["iec62351_applicable"])
		}
		if d.RawMetadata["src_tsap"] != "0001" {
			t.Errorf("src_tsap=%v, want 0001", d.RawMetadata["src_tsap"])
		}
		if d.RawMetadata["dst_tsap"] != "4d4d53" {
			t.Errorf("dst_tsap=%v, want 4d4d53 (hex of 'MMS')", d.RawMetadata["dst_tsap"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected MMS discovery within 1s")
	}
}

func TestMMSAssembler_TASE2OIDInDTUpgradesToICCP(t *testing.T) {
	t.Parallel()
	factory, ch := newTestMMSFactory(t)
	stream, _ := preState(factory)

	// Step 1: CR PDU produces an MMS finding.
	cr := buildCRPDU([]byte{0x00, 0x01}, []byte("ICCP"))
	feedMMS(stream, cr)

	gotMMS := false
	select {
	case d := <-ch:
		if d.Protocol == "MMS" {
			gotMMS = true
		}
	case <-time.After(time.Second):
		t.Fatal("expected MMS discovery from CR")
	}
	if !gotMMS {
		t.Fatal("first discovery was not MMS")
	}

	// Step 2: DT PDU containing the TASE.2 OID upgrades to ICCP.
	payload := append([]byte("AARQ-prelude:"), tase2OIDPatternPrefix...)
	payload = append(payload, 0x02, 0x01, 0x00)
	dt := buildDTPDU(payload)
	feedMMS(stream, dt)

	select {
	case d := <-ch:
		if d.Protocol != "ICCP" {
			t.Errorf("Protocol=%s, want ICCP", d.Protocol)
		}
		if d.Version != "TASE.2" {
			t.Errorf("Version=%s, want TASE.2", d.Version)
		}
		if d.RawMetadata["standard"] != "TASE.2 / IEC 60870-6" {
			t.Errorf("standard=%v", d.RawMetadata["standard"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected ICCP upgrade discovery")
	}
}

func TestMMSAssembler_NonTPKTBytesDropTheBuffer(t *testing.T) {
	t.Parallel()
	factory, ch := newTestMMSFactory(t)
	stream, state := preState(factory)

	// TLS handshake bytes → not TPKT magic. The MMS assembler should
	// drop the buffer and never emit anything; the TLS assembler picks
	// up TLS-wrapped MMS via its own routing.
	feedMMS(stream, []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c})

	select {
	case d := <-ch:
		t.Errorf("expected no MMS discovery for TLS bytes, got %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if state.buffer != nil {
		t.Errorf("expected buffer to be dropped, got %d bytes", len(state.buffer))
	}
}

func TestMMSAssembler_BuffersUntilFullPDU(t *testing.T) {
	t.Parallel()
	factory, ch := newTestMMSFactory(t)
	stream, _ := preState(factory)

	cr := buildCRPDU([]byte{0x00, 0x02}, []byte("MMS"))
	// Deliver in two chunks split mid-frame.
	feedMMS(stream, cr[:5])
	select {
	case d := <-ch:
		t.Fatalf("did not expect discovery before full PDU, got %+v", d)
	case <-time.After(20 * time.Millisecond):
	}
	feedMMS(stream, cr[5:])
	select {
	case d := <-ch:
		if d.Protocol != "MMS" {
			t.Errorf("Protocol=%s, want MMS", d.Protocol)
		}
	case <-time.After(time.Second):
		t.Fatal("expected MMS discovery once frame completed")
	}
}

// =============================================================================
// Siemens S7 (port 102 — same TPKT/COTP stack as MMS, distinct app layer)
// =============================================================================

func TestDetectS7Variant(t *testing.T) {
	t.Parallel()
	if got := detectS7Variant(nil); got != "" {
		t.Errorf("nil payload → %q, want empty", got)
	}
	if got := detectS7Variant([]byte{}); got != "" {
		t.Errorf("empty payload → %q, want empty", got)
	}
	if got := detectS7Variant([]byte{0x32, 0x01, 0x00}); got != "S7Comm" {
		t.Errorf("0x32 → %q, want S7Comm", got)
	}
	if got := detectS7Variant([]byte{0x72, 0x01, 0x00}); got != "S7Plus" {
		t.Errorf("0x72 → %q, want S7Plus", got)
	}
	if got := detectS7Variant([]byte{0x60, 0x82}); got != "" {
		t.Errorf("MMS-like prefix (0x60) → %q, want empty", got)
	}
}

func TestMMSAssembler_S7DTPDUUpgradesToS7Comm(t *testing.T) {
	t.Parallel()
	factory, ch := newTestMMSFactory(t)
	stream, _ := preState(factory)

	// Step 1: CR PDU produces the initial MMS finding (S7 reuses the same
	// TPKT/COTP carrier so we can't distinguish until the first DT PDU).
	cr := buildCRPDU([]byte{0x01, 0x00}, []byte{0x01, 0x00, 0x01})
	feedMMS(stream, cr)
	select {
	case d := <-ch:
		if d.Protocol != "MMS" {
			t.Fatalf("expected MMS on CR, got %s", d.Protocol)
		}
	case <-time.After(time.Second):
		t.Fatal("expected initial MMS discovery from CR")
	}

	// Step 2: DT payload starting with 0x32 → S7Comm. The assembler
	// should re-emit as Protocol=S7, Version=S7Comm.
	payload := []byte{0x32, 0x01, 0x00, 0x00, 0x00, 0x00}
	feedMMS(stream, buildDTPDU(payload))

	select {
	case d := <-ch:
		if d.Protocol != "S7" {
			t.Errorf("Protocol=%s, want S7", d.Protocol)
		}
		if d.Version != "S7Comm" {
			t.Errorf("Version=%s, want S7Comm", d.Version)
		}
		if d.RawMetadata["vendor"] != "Siemens" {
			t.Errorf("vendor=%v, want Siemens", d.RawMetadata["vendor"])
		}
		if d.RawMetadata["s7_variant"] != "S7Comm" {
			t.Errorf("s7_variant=%v, want S7Comm", d.RawMetadata["s7_variant"])
		}
		if d.RawMetadata["plaintext_s7"] != true {
			t.Errorf("plaintext_s7=%v, want true", d.RawMetadata["plaintext_s7"])
		}
		// S7 is not IEC 61850 — those keys must NOT be set.
		if _, ok := d.RawMetadata["iec61850_protocol"]; ok {
			t.Errorf("S7 finding should not carry iec61850_protocol")
		}
		if _, ok := d.RawMetadata["iec62351_applicable"]; ok {
			t.Errorf("S7 finding should not carry iec62351_applicable")
		}
	case <-time.After(time.Second):
		t.Fatal("expected S7 upgrade discovery")
	}
}

func TestMMSAssembler_S7PlusDTPDUUpgradesToS7Plus(t *testing.T) {
	t.Parallel()
	factory, ch := newTestMMSFactory(t)
	stream, _ := preState(factory)

	cr := buildCRPDU([]byte{0x01, 0x00}, []byte{0x02, 0x00, 0x01})
	feedMMS(stream, cr)
	<-ch // drain the initial MMS finding

	payload := []byte{0x72, 0x01, 0x00}
	feedMMS(stream, buildDTPDU(payload))

	select {
	case d := <-ch:
		if d.Protocol != "S7" || d.Version != "S7Plus" {
			t.Errorf("got Protocol=%s Version=%s, want S7/S7Plus", d.Protocol, d.Version)
		}
	case <-time.After(time.Second):
		t.Fatal("expected S7Plus discovery")
	}
}

func TestMMSAssembler_PlainMMSDTPDUDoesNotMisclassifyAsS7(t *testing.T) {
	t.Parallel()
	factory, ch := newTestMMSFactory(t)
	stream, _ := preState(factory)

	cr := buildCRPDU([]byte{0x00, 0x01}, []byte("MMS"))
	feedMMS(stream, cr)
	<-ch // drain initial MMS finding

	// ASN.1 BER-like prefix (0x60 = APPLICATION 0 implicit tag) — must NOT
	// match S7 protocol IDs. No additional discovery should fire.
	payload := []byte{0x60, 0x82, 0x00, 0x10}
	feedMMS(stream, buildDTPDU(payload))

	select {
	case d := <-ch:
		t.Errorf("expected no upgrade for plain MMS DT payload, got %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMMSAssembler_FlushOldSessions(t *testing.T) {
	t.Parallel()
	factory, _ := newTestMMSFactory(t)
	old := &mmsSessionState{lastSeen: time.Now().Add(-2 * time.Hour)}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = old
	factory.mu.Unlock()
	factory.FlushOldSessions(time.Hour)
	factory.mu.Lock()
	if _, exists := factory.sessions[tlsFlowKey{}]; exists {
		t.Errorf("expected old session to be flushed")
	}
	factory.mu.Unlock()
}
