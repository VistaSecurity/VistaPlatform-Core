package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// Tests for H11: one uploaded PCAP could OOM-kill the single-replica,
// all-tenant pcap-processor. The SSH and QUIC paths accumulated a discovery and
// a dedup-map key per distinct flow with no ceiling; the auditor measured a
// 1.29 GiB heap against a 512 Mi pod limit.
//
// These tests FEED the oversized input rather than asserting a constant exists.
// One measures the heap a hostile capture retains; the other proves an ordinary
// capture is untouched, because a cap that eats legitimate uploads is the same
// bug pointed the other way.

// writeSSHFloodPcap writes a classic-format pcap of `flows` TCP packets, each
// carrying an SSH banner from a distinct source address — the shape of a
// capture engineered to make the SSH path allocate without bound. Every flow is
// unique, so nothing dedups and the accumulation is the worst case.
func writeSSHFloodPcap(t *testing.T, path string, flows int) {
	t.Helper()

	const banner = "SSH-2.0-OpenSSH_8.9p1\r\n"
	buf := make([]byte, 0, 24+flows*(16+14+20+20+len(banner)))

	// Global header: magic, version 2.4, no zone/sigfigs, snaplen, Ethernet.
	buf = binary.LittleEndian.AppendUint32(buf, 0xa1b2c3d4)
	buf = binary.LittleEndian.AppendUint16(buf, 2)
	buf = binary.LittleEndian.AppendUint16(buf, 4)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 65535)
	buf = binary.LittleEndian.AppendUint32(buf, 1)

	for i := 0; i < flows; i++ {
		frame := make([]byte, 0, 14+20+20+len(banner))

		// Ethernet II. The MACs vary with the flow so the passive
		// host-observation collector sees distinct subjects too — it has its
		// own coalescer cap, and this keeps the test honest about which
		// ceiling is doing the work.
		frame = append(frame, 0x02, 0, 0, 0, 0, byte(i), 0x02, 0, 0, 0, 1, byte(i>>8))
		frame = append(frame, 0x08, 0x00) // IPv4

		totalLen := 20 + 20 + len(banner)
		ip := []byte{
			0x45, 0x00,
			byte(totalLen >> 8), byte(totalLen),
			byte(i >> 8), byte(i),
			0x00, 0x00,
			64, 6, // TTL, TCP
			0x00, 0x00, // checksum: gopacket does not verify
			10, byte(i >> 16), byte(i >> 8), byte(i), // unique source
			10, 0, 0, 1,
		}
		frame = append(frame, ip...)

		srcPort := 1024 + (i % 60000)
		tcp := []byte{
			byte(srcPort >> 8), byte(srcPort),
			0x00, 22, // SSH
			0, 0, 0, 1,
			0, 0, 0, 1,
			0x50, 0x18, // offset 5, PSH|ACK
			0xff, 0xff,
			0x00, 0x00,
			0x00, 0x00,
		}
		frame = append(frame, tcp...)
		frame = append(frame, banner...)

		buf = binary.LittleEndian.AppendUint32(buf, uint32(1700000000+i))
		buf = binary.LittleEndian.AppendUint32(buf, 0)
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(frame)))
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(frame)))
		buf = append(buf, frame...)
	}

	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write pcap: %v", err)
	}
}

func testProcessor(t *testing.T) *Processor {
	t.Helper()
	return New(nil, &config.Config{MaxConcurrentJobs: 1}, nil, nil)
}

// retainedHeapMiB reports the live heap after a collection, which is what an
// accumulation bug actually costs: bytes the process cannot give back while the
// result is alive.
func retainedHeapMiB() float64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / (1 << 20)
}

// TestHostileCapture_DiscoveriesAndHeapStayBounded is the H11 regression.
//
// It feeds a capture with an order of magnitude more distinct SSH flows than
// MaxDiscoveriesPerCapture and asserts three things: the result stops at the
// cap, the shed is reported rather than silent, and the heap the run retains
// stays far below the pod's 512 Mi limit.
//
// The heap assertion is the one that matters, and it is the one that fails if
// the cap is removed: with MaxDiscoveriesPerCapture raised out of the way this
// same input retains hundreds of MiB, because every flow leaves behind a
// CryptoDiscovery, its RawMetadata map, and a dedup-map key.
func TestHostileCapture_DiscoveriesAndHeapStayBounded(t *testing.T) {
	const flows = 200000

	dir := t.TempDir()
	path := filepath.Join(dir, "flood.pcap")
	writeSSHFloodPcap(t, path, flows)

	before := retainedHeapMiB()

	p := testProcessor(t)
	result, err := p.processPcapFile(context.Background(), path, "sensor-under-test")
	if err != nil {
		t.Fatalf("processPcapFile: %v", err)
	}

	after := retainedHeapMiB()
	runtime.KeepAlive(result) // the measurement is about what the RESULT retains
	grew := after - before

	t.Logf("flows=%d kept=%d dropped=%d packets=%d retained_heap=%.1f MiB (was %.1f)",
		flows, len(result.Discoveries), result.DiscoveriesDropped, result.PacketsProcessed, after, before)

	if len(result.Discoveries) > MaxDiscoveriesPerCapture {
		t.Errorf("accumulated %d discoveries, cap is %d — the ceiling is not being applied",
			len(result.Discoveries), MaxDiscoveriesPerCapture)
	}
	if len(result.Discoveries) != MaxDiscoveriesPerCapture {
		t.Errorf("expected the capture to fill the cap exactly (%d), got %d — if this is short, the "+
			"fixture stopped producing distinct flows and the test is no longer measuring the cap",
			MaxDiscoveriesPerCapture, len(result.Discoveries))
	}
	if result.DiscoveriesDropped == 0 {
		t.Error("DiscoveriesDropped is 0 on a capture that demonstrably shed observations — " +
			"the truncation is silent, which is the failure mode the counter exists to prevent")
	}
	if result.DiscoveryCount != len(result.Discoveries) {
		t.Errorf("DiscoveryCount %d disagrees with the slice length %d", result.DiscoveryCount, len(result.Discoveries))
	}

	// 64 MiB against a 512 Mi pod limit. Generous enough not to be flaky on a
	// busy runner, an order of magnitude below the measured pre-fix figure.
	const budgetMiB = 64
	if grew > budgetMiB {
		t.Errorf("retained heap grew by %.1f MiB processing one capture (budget %d MiB) — "+
			"the accumulation is not bounded", grew, budgetMiB)
	}
}

// TestOrdinaryCapture_IsNotTruncated is the other polarity. A capture well
// under the ceiling must come back whole, with nothing dropped — a cap that
// quietly eats a real upload is the same defect facing the other way.
func TestOrdinaryCapture_IsNotTruncated(t *testing.T) {
	const flows = 500

	dir := t.TempDir()
	path := filepath.Join(dir, "ordinary.pcap")
	writeSSHFloodPcap(t, path, flows)

	p := testProcessor(t)
	result, err := p.processPcapFile(context.Background(), path, "sensor-under-test")
	if err != nil {
		t.Fatalf("processPcapFile: %v", err)
	}

	sshCount := 0
	for _, d := range result.Discoveries {
		if d.Protocol == "SSH" {
			sshCount++
		}
	}

	if sshCount != flows {
		t.Errorf("expected all %d SSH observations to survive, got %d — the cap is refusing "+
			"legitimate captures", flows, sshCount)
	}
	if result.DiscoveriesDropped != 0 {
		t.Errorf("DiscoveriesDropped = %d on a capture far below the ceiling", result.DiscoveriesDropped)
	}
	if result.PacketsProcessed != flows {
		t.Errorf("PacketsProcessed = %d, want %d", result.PacketsProcessed, flows)
	}
}

// TestDiscoverySink_DedupAndCap pins the sink's two jobs directly: a repeated
// key is recorded once, and neither the slice NOR the dedup map grows past the
// ceiling. The map is asserted explicitly because capping only the slice would
// leave the keys growing one per flow forever — which is most of the heap the
// test above measures.
func TestDiscoverySink_DedupAndCap(t *testing.T) {
	s := newDiscoverySink()

	if !s.add("a", CryptoDiscovery{Protocol: "SSH"}) {
		t.Fatal("first add of a fresh key was rejected")
	}
	if s.add("a", CryptoDiscovery{Protocol: "SSH"}) {
		t.Error("a repeated key was accepted twice — dedup is not working")
	}
	if len(s.discoveries) != 1 {
		t.Errorf("after one unique and one duplicate add, len = %d, want 1", len(s.discoveries))
	}
	if s.dropped != 0 {
		t.Errorf("a deduplicated add counted as a drop (%d); dedup is not truncation", s.dropped)
	}

	for i := 0; i < MaxDiscoveriesPerCapture+1000; i++ {
		s.add(fmt.Sprintf("k%d", i), CryptoDiscovery{Protocol: "SSH"})
	}

	if len(s.discoveries) != MaxDiscoveriesPerCapture {
		t.Errorf("sink holds %d discoveries, cap is %d", len(s.discoveries), MaxDiscoveriesPerCapture)
	}
	if len(s.seen) > MaxDiscoveriesPerCapture {
		t.Errorf("dedup map holds %d keys, above the cap of %d — the map is the unbounded half",
			len(s.seen), MaxDiscoveriesPerCapture)
	}
	if s.dropped == 0 {
		t.Error("dropped is 0 after pushing past the cap")
	}
}

// TestUnprocessableCapture_IsNotRedelivered is the other half of H11: the
// pcap-processor consumer subscribes with MaxDeliver=3, so before this an
// unprocessable capture cost the single-replica, all-tenant pod three full
// passes rather than one. HandlePcapJob deletes the temp file and marks the job
// failed on the way out, so there is nothing a retry could succeed at.
func TestUnprocessableCapture_IsNotRedelivered(t *testing.T) {
	p := newTestProcessor(t, &recordingSink{})

	job := &events.PcapJobEvent{
		JobID:            uuid.New(),
		TenantID:         uuid.New(),
		FilePath:         filepath.Join(t.TempDir(), "does-not-exist.pcap"),
		OriginalFilename: "does-not-exist.pcap",
	}

	err := p.HandlePcapJob(context.Background(), jobMsg(t, job))
	if err == nil {
		t.Fatal("expected an error for an unopenable capture")
	}
	if !events.IsPermanent(err) {
		t.Errorf("error is not marked permanent, so the subscriber will nack it and "+
			"MaxDeliver will repeat the whole job: %v", err)
	}
}

// TestMalformedJobEvent_IsNotRedelivered: bytes that will not unmarshal will
// not unmarshal differently on the second read either.
func TestMalformedJobEvent_IsNotRedelivered(t *testing.T) {
	p := newTestProcessor(t, &recordingSink{})

	err := p.HandlePcapJob(context.Background(), &nats.Msg{
		Subject: events.SubjectPcapJobsProcess,
		Data:    []byte("{not json"),
	})
	if err == nil {
		t.Fatal("expected an error for a malformed job event")
	}
	if !events.IsPermanent(err) {
		t.Errorf("a malformed event is not marked permanent: %v", err)
	}
}

// And the polarity that keeps the fix honest: a CANCELLED context is the
// service shutting down or the processing timeout expiring. That says nothing
// about the file, so it must stay retryable — marking it permanent would
// silently discard a tenant's upload on every rolling restart.
func TestCancelledProcessing_StaysRetryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary.pcap")
	writeSSHFloodPcap(t, path, 2000)

	p := newTestProcessor(t, &recordingSink{})

	job := &events.PcapJobEvent{
		JobID:            uuid.New(),
		TenantID:         uuid.New(),
		FilePath:         path,
		OriginalFilename: "ordinary.pcap",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := p.HandlePcapJob(ctx, jobMsg(t, job))
	if err == nil {
		t.Skip("processing completed before the cancellation was observed")
	}
	if events.IsPermanent(err) {
		t.Errorf("a cancelled job was marked permanent; a rolling restart would drop the "+
			"tenant's capture instead of retrying it: %v", err)
	}
}
