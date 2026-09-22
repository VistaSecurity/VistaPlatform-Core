package handlers

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The PCAP upload's size check used to sit BELOW c.FormFile, comparing
// fileHeader.Size against the platform limit — which gin can only populate
// after it has received the whole upload, buffered 32 MiB of it in heap and
// spilled the rest to the pcap-uploads volume. A check downstream of the
// buffering it is meant to prevent cannot prevent anything.
//
// These feed a real oversized multipart body through the real handler.

// streamingMultipart produces a well-formed multipart body of roughly `size`
// bytes on the fly, so the test does not have to hold the attack in memory
// itself — which would make the measurement meaningless.
type streamingMultipart struct {
	pr *io.PipeReader
	ct string
}

func newStreamingMultipart(t *testing.T, filename string, size int) *streamingMultipart {
	t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	ct := mw.FormDataContentType()

	go func() {
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		// A valid pcap magic up front, so the handler cannot reject this for
		// the wrong reason if the ceiling is ever removed.
		if _, err := fw.Write(validPcapMagic); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		chunk := bytes.Repeat([]byte{0xAB}, 64<<10)
		written := len(validPcapMagic)
		for written < size {
			n := len(chunk)
			if size-written < n {
				n = size - written
			}
			if _, err := fw.Write(chunk[:n]); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			written += n
		}
		_ = mw.Close()
		_ = pw.Close()
	}()

	return &streamingMultipart{pr: pr, ct: ct}
}

// countingReader records how many bytes the server actually pulled off the
// wire. This is the measurement that matters and the one that distinguishes the
// fix from the bug: "refused before buffering" means the server stopped reading
// near the cap. A heap figure alone does not say it — gin spills a large
// multipart body past 32 MiB to a temp file and the garbage is collected before
// any post-hoc reading, so the process can consume 200 MB of I/O and look calm
// afterwards. That is exactly how an earlier version of this test passed
// against the unfixed handler.
type countingReader struct {
	r    io.Reader
	read int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

// TestUploadPcap_OversizeIsRefusedBeforeBuffering is the measurement. The cap
// is set to 1 MB and a 200 MB upload is streamed at it; the handler must answer
// 413, must stop reading near the cap, must not allocate the body, and must
// leave nothing behind on disk.
func TestUploadPcap_OversizeIsRefusedBeforeBuffering(t *testing.T) {
	// The handler writes accepted uploads under /tmp/pcap-uploads/<tenant>/.
	// Nothing should land there for a refused upload, so record what is there
	// first and compare.
	tenantDir := filepath.Join("/tmp/pcap-uploads", testTenantID.String())
	beforeEntries := dirEntryCount(tenantDir)

	eng := newPcapEngine(&stubPcapService{maxMB: 1, created: samplePcapJob()})

	const attack = 200 << 20
	const capBytes = 1 << 20

	stream := newStreamingMultipart(t, "huge.pcap", attack)
	counted := &countingReader{r: stream.pr}
	req := httptest.NewRequest(http.MethodPost, base+"/pcap/upload", counted)
	req.Header.Set("Content-Type", stream.ct)
	req.ContentLength = -1 // chunked: the size is not declared up front
	w := httptest.NewRecorder()

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	eng.ServeHTTP(w, req)
	_ = stream.pr.Close()

	runtime.ReadMemStats(&after)
	allocatedMiB := float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
	readMiB := float64(counted.read) / (1 << 20)
	t.Logf("200 MB upload against a 1 MB cap: status=%d bytes_read=%.1f MiB total_allocated=%.1f MiB",
		w.Code, readMiB, allocatedMiB)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	// A few MiB of slack over the cap for net/http's read buffering. Two
	// hundred times under the attack size either way.
	if counted.read > 8*capBytes {
		t.Errorf("the server read %.1f MiB of a %d MiB upload against a 1 MiB cap — "+
			"the ceiling is downstream of the buffering it exists to prevent", readMiB, attack>>20)
	}
	if allocatedMiB > 32 {
		t.Errorf("the refused upload allocated %.1f MiB in total", allocatedMiB)
	}
	if got := dirEntryCount(tenantDir); got != beforeEntries {
		t.Errorf("a refused upload left %d new file(s) under %s — partial state after a 413",
			got-beforeEntries, tenantDir)
	}
}

// TestUploadPcap_AtTheLimitStillSucceeds is the other polarity, and it is the
// one that matters for this endpoint: PCAP files are genuinely large, so a
// transport ceiling set carelessly would refuse uploads the product is supposed
// to accept. A file of exactly the configured maximum must go through — the
// multipart envelope sits on top of the file, so the ceiling has to allow for
// it.
func TestUploadPcap_AtTheLimitStillSucceeds(t *testing.T) {
	const capMB = 2
	content := make([]byte, capMB<<20)
	copy(content, validPcapMagic)

	eng := newPcapEngine(&stubPcapService{maxMB: capMB, created: samplePcapJob()})
	body, ct := pcapMultipart(t, "file", "exactly-at-the-limit.pcap", content)

	// The envelope pushes the REQUEST over the file cap; that is precisely the
	// case the allowance exists for.
	if int64(body.Len()) <= int64(capMB)<<20 {
		t.Fatalf("the multipart envelope did not push the request past the file cap (%d bytes vs %d) — "+
			"this test is no longer exercising the allowance", body.Len(), int64(capMB)<<20)
	}

	w := doMultipart(eng, base+"/pcap/upload", body, ct)
	if w.Code != http.StatusCreated {
		t.Fatalf("an upload of exactly the configured maximum was refused with %d: %s", w.Code, w.Body.String())
	}
}

func dirEntryCount(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(entries)
}
