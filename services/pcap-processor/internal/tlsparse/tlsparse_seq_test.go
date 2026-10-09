package tlsparse

import (
	"testing"
	"time"
)

// Sequence-ordered reassembly. Every test here fed segments in arrival order
// before the tracker read TCP sequence numbers, and every one of them lost the
// handshake: a capture of a real network carries retransmissions, duplicates
// and reordering, and appending in arrival order splices them into the record
// stream.

// largeClientHello is a ClientHello record bigger than one TCP segment — the
// shape a modern browser sends once a post-quantum key share is in it. The
// padding extension (RFC 7685) stands in for the key share's bulk.
func largeClientHello(sni string) []byte {
	return tlsRecord(0x16, 0x0301, handshakeMsg(0x01, clientHelloBody(0x0303, []uint16{0x1301, 0xC02F},
		sniExtension(sni),
		extension(0x0015, make([]byte, 1500)))))
}

const clientISN = uint32(7_000_000)
const serverISN = uint32(9_000_000)

func TestRetransmittedClientHelloSegmentIsIgnored(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	rec := largeClientHello("retransmit.example.com")
	first, second := rec[:1200], rec[1200:]

	tr.Feed(c, clientISN, first, ts)
	tr.Feed(c, clientISN, first, ts) // the retransmission
	tr.Feed(c, clientISN+uint32(len(first)), second, ts)
	tr.Flush()

	if tr.Desynced != 0 {
		t.Fatalf("desynced = %d: the retransmission was spliced into the stream", tr.Desynced)
	}
	if tr.Retransmitted != 1 {
		t.Errorf("retransmitted = %d, want 1", tr.Retransmitted)
	}
	if len(*got) != 1 || (*got)[0].SNI != "retransmit.example.com" {
		t.Fatalf("expected the ClientHello's session with its SNI, got %+v", *got)
	}
}

func TestOverlappingRetransmissionIsTrimmed(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	rec := largeClientHello("overlap.example.com")
	// The second segment is resent re-packetised: it starts 100 bytes before
	// the point the first one ended.
	tr.Feed(c, clientISN, rec[:1000], ts)
	tr.Feed(c, clientISN+900, rec[900:], ts)
	tr.Flush()

	if tr.Desynced != 0 {
		t.Fatalf("desynced = %d: the overlapping bytes were not trimmed", tr.Desynced)
	}
	if len(*got) != 1 || (*got)[0].SNI != "overlap.example.com" {
		t.Fatalf("expected the ClientHello's session with its SNI, got %+v", *got)
	}
}

func TestOutOfOrderSegmentsAreReordered(t *testing.T) {
	c, s := flow()
	tr, got := collect(t)
	ts := time.Now()

	leaf := selfSignedDER(t, "reorder.example.com")
	flight := tlsRecord(0x16, 0x0303, handshakeMsg(0x02, serverHelloBody(0x0303, 0xC02F)))
	flight = append(flight, tlsRecord(0x16, 0x0303, handshakeMsg(0x0b, certificateBody(leaf)))...)

	feedNext(tr, c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01, clientHelloBody(0x0303, []uint16{0xC02F}))), ts)

	// The server flight's second segment overtakes its first.
	split := len(flight) / 2
	tr.Feed(s, serverISN+uint32(split), flight[split:], ts)
	if len(*got) != 0 {
		t.Fatal("session emitted before the server flight was complete")
	}
	tr.Feed(s, serverISN, flight[:split], ts)
	tr.Flush()

	if tr.Desynced != 0 {
		t.Fatalf("desynced = %d", tr.Desynced)
	}
	if len(*got) != 1 {
		t.Fatalf("expected 1 session, got %d", len(*got))
	}
	sess := (*got)[0]
	if sess.CipherSuite == "" || len(sess.Certificates) != 1 {
		t.Errorf("server flight not read in sequence order: cipher=%q certs=%d", sess.CipherSuite, len(sess.Certificates))
	}
}

// TestSnapshotTruncatedSegmentLeavesAGap is the capture that started this: a
// snapshot length of 128 keeps ~62 bytes of each segment's payload. The bytes
// that are present are real, the rest is a gap, and the tracker must neither
// read past the gap nor call the flow desynchronised.
func TestSnapshotTruncatedSegmentLeavesAGap(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	rec := largeClientHello("snaplen.example.com")
	segLen := 1200
	tr.Feed(c, clientISN, rec[:62], ts) // captured prefix of a 1200-byte segment
	tr.Feed(c, clientISN+uint32(segLen), rec[segLen:segLen+62], ts)
	tr.Flush()

	if tr.Desynced != 0 {
		t.Errorf("desynced = %d: a gap is not a desync", tr.Desynced)
	}
	if tr.Gapped != 1 {
		t.Errorf("gapped = %d, want 1", tr.Gapped)
	}
	if len(*got) != 0 {
		t.Errorf("a ClientHello that was never captured whole produced %d session(s)", len(*got))
	}
}

// TestRecordsBeforeAGapAreStillRead: a segment whose captured prefix holds a
// complete record yields that record even though the rest of the segment is
// missing.
func TestRecordsBeforeAGapAreStillRead(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	hello := tlsRecord(0x16, 0x0301, handshakeMsg(0x01,
		clientHelloBody(0x0303, []uint16{0xC02F}, sniExtension("prefix.example.com"))))
	segment := append(append([]byte{}, hello...), tlsRecord(0x17, 0x0303, make([]byte, 400))...)

	tr.Feed(c, clientISN, segment[:len(hello)+3], ts)
	tr.Feed(c, clientISN+uint32(len(segment)), tlsRecord(0x17, 0x0303, []byte{1, 2, 3}), ts)
	tr.Flush()

	if len(*got) != 1 || (*got)[0].SNI != "prefix.example.com" {
		t.Fatalf("expected the ClientHello read from before the gap, got %+v", *got)
	}
}

// TestCompleteRecordBeforeDesyncIsApplied: when one feed completes a record
// and is followed by bytes that are not a record, the complete record is still
// applied before the flow is abandoned.
func TestCompleteRecordBeforeDesyncIsApplied(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	hello := tlsRecord(0x16, 0x0301, handshakeMsg(0x01,
		clientHelloBody(0x0303, []uint16{0xC02F}, sniExtension("before-desync.example.com"))))
	stream := append(append([]byte{}, hello...), 0x99, 0x99, 0x99, 0x99, 0x99, 0x99)

	tr.Feed(c, clientISN, stream, ts)

	if tr.Desynced != 1 {
		t.Errorf("desynced = %d, want 1", tr.Desynced)
	}
	if len(*got) != 1 || (*got)[0].SNI != "before-desync.example.com" {
		t.Fatalf("expected the complete ClientHello to be applied before abandoning, got %+v", *got)
	}
}

func TestSequenceNumberWraparound(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	rec := largeClientHello("wrap.example.com")
	isn := ^uint32(0) - 500 // the first segment crosses 2^32
	tr.Feed(c, isn, rec[:1200], ts)
	tr.Feed(c, isn+1200, rec[1200:], ts)
	tr.Flush()

	if len(*got) != 1 || (*got)[0].SNI != "wrap.example.com" {
		t.Fatalf("expected the session across the wrap, got %+v", *got)
	}
}

func TestPendingSegmentsAreBounded(t *testing.T) {
	c, _ := flow()
	tr, _ := collect(t)
	ts := time.Now()

	tr.Feed(c, clientISN, largeClientHello("bounded.example.com")[:100], ts)
	for i := 0; i <= maxPendingSegments; i++ {
		tr.Feed(c, clientISN+uint32(10_000+i*10), []byte{0x16, 0x03, 0x03, 0x00, 0x01}, ts)
	}
	if tr.Gapped != 1 {
		t.Errorf("gapped = %d, want 1 once more than %d segments wait behind a gap", tr.Gapped, maxPendingSegments)
	}
	if tr.Truncated != 0 {
		t.Errorf("truncated = %d: a gap that never fills is not the byte cap", tr.Truncated)
	}
	if len(tr.sessions) != 0 {
		t.Error("flow still tracked after its out-of-order backlog overflowed")
	}
}
