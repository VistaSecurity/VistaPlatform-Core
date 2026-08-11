package capture

import (
	"encoding/binary"
	"testing"
)

func TestIsTPKTHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		buf  []byte
		want bool
	}{
		{[]byte{0x03, 0x00, 0x00, 0x10}, true},
		{[]byte{0x03, 0x00, 0xFF, 0xFF}, true},  // any length is fine
		{[]byte{0x03, 0x01, 0x00, 0x10}, false}, // bad reserved byte
		{[]byte{0x16, 0x03, 0x01, 0x00}, false}, // TLS handshake
		{[]byte{0x03}, false},                   // too short
		{[]byte{}, false},
	}
	for _, c := range cases {
		if got := isTPKTHeader(c.buf); got != c.want {
			t.Errorf("isTPKTHeader(%x)=%v, want %v", c.buf, got, c.want)
		}
	}
}

func TestTPKTLength(t *testing.T) {
	t.Parallel()
	if got := tpktLength([]byte{0x03, 0x00, 0x01, 0x23, 0xAA}); got != 0x0123 {
		t.Errorf("tpktLength=%d want 0x0123", got)
	}
	if got := tpktLength([]byte{0x16, 0x03, 0x00, 0x10}); got != 0 {
		t.Errorf("tpktLength on TLS bytes should be 0, got %d", got)
	}
}

// buildCRPDU constructs a minimal COTP Connection Request PDU wrapped in
// TPKT, with optional source/destination TSAP variable parameters.
func buildCRPDU(srcTSAP, dstTSAP []byte) []byte {
	// COTP CR fixed header (after LI): PDUType(1) DSTREF(2) SRCREF(2) Class(1)
	// = 6 bytes. Plus per param: code(1) + len(1) + value(N).
	params := []byte{}
	if len(srcTSAP) > 0 {
		params = append(params, cotpParamSrcTSAP, byte(len(srcTSAP)))
		params = append(params, srcTSAP...)
	}
	if len(dstTSAP) > 0 {
		params = append(params, cotpParamDstTSAP, byte(len(dstTSAP)))
		params = append(params, dstTSAP...)
	}
	li := byte(6 + len(params))

	cotp := []byte{li, cotpPDUConnectionRequest, 0x00, 0x00, 0x00, 0x01, 0x00}
	cotp = append(cotp, params...)

	tpkt := make([]byte, tpktHeaderLen)
	tpkt[0] = 0x03
	tpkt[1] = 0x00
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(tpktHeaderLen+len(cotp)))

	return append(tpkt, cotp...)
}

// buildDTPDU builds a COTP Data PDU wrapped in TPKT, carrying the given
// application-layer payload bytes.
func buildDTPDU(payload []byte) []byte {
	// COTP DT header: LI(1=2) PDUType(1=0xF0) EOT/TPDU-NR(1)
	cotp := []byte{0x02, cotpPDUData, 0x80}
	tpkt := make([]byte, tpktHeaderLen)
	tpkt[0] = 0x03
	tpkt[1] = 0x00
	total := tpktHeaderLen + len(cotp) + len(payload)
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	out := append(tpkt, cotp...)
	out = append(out, payload...)
	return out
}

func TestExtractTSAPs(t *testing.T) {
	t.Parallel()
	src := []byte{0x00, 0x01}
	dst := []byte("MMS")
	frame := buildCRPDU(src, dst)
	gotSrc, gotDst := extractTSAPs(frame)
	if string(gotSrc) != string(src) {
		t.Errorf("src TSAP=%v want %v", gotSrc, src)
	}
	if string(gotDst) != string(dst) {
		t.Errorf("dst TSAP=%v want %v", gotDst, dst)
	}
}

func TestExtractTSAPs_NotCR(t *testing.T) {
	t.Parallel()
	dt := buildDTPDU([]byte("hello"))
	src, dst := extractTSAPs(dt)
	if src != nil || dst != nil {
		t.Errorf("expected nil TSAPs on DT PDU, got src=%v dst=%v", src, dst)
	}
}

func TestCotpPDUType(t *testing.T) {
	t.Parallel()
	cr := buildCRPDU([]byte{0}, []byte{0})
	if got := cotpPDUType(cr); got != cotpPDUConnectionRequest {
		t.Errorf("CR PDU type=0x%02x want 0x%02x", got, cotpPDUConnectionRequest)
	}
	dt := buildDTPDU([]byte("x"))
	if got := cotpPDUType(dt); got != cotpPDUData {
		t.Errorf("DT PDU type=0x%02x want 0x%02x", got, cotpPDUData)
	}
}

func TestCotpPayload(t *testing.T) {
	t.Parallel()
	payload := []byte("application-layer-bytes")
	dt := buildDTPDU(payload)
	got := cotpPayload(dt)
	if string(got) != string(payload) {
		t.Errorf("cotpPayload=%q want %q", got, payload)
	}
}

func TestFindTASE2OID(t *testing.T) {
	t.Parallel()
	// Embed the canonical TASE.2 OID prefix inside some surrounding bytes.
	withOID := append([]byte("AARQ:"), tase2OIDPatternPrefix...)
	withOID = append(withOID, 0x02, 0x01, 0x00) // some trailing bytes
	if !findTASE2OID(withOID) {
		t.Errorf("expected TASE.2 OID detection in %x", withOID)
	}

	// Pure MMS payload — no TASE.2 OID, should be false.
	mmsOnly := []byte{0x60, 0x35, 0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x01}
	if findTASE2OID(mmsOnly) {
		t.Errorf("false positive: %x", mmsOnly)
	}

	// Empty / too short
	if findTASE2OID(nil) || findTASE2OID([]byte{0x06}) {
		t.Errorf("expected false on short input")
	}
}
