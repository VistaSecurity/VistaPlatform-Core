package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// Tests for H10: cluster-sensor-service had no request-body ceiling anywhere,
// so one 100 MiB POST from any authenticated tenant user OOM-killed a pod
// limited to 256 Mi. These drive a real gin router through MaxBody with a real
// oversized body rather than asserting a constant exists.

const testCap = 1 << 20 // 1 MiB, the cluster-sensor-service ceiling

// echoRouter is the shape a service mounts: the cap first, then a handler that
// binds the body. The handler reports how many bytes it managed to read, so a
// test can tell "refused at the socket" from "read it all, then complained".
func echoRouter(cap int64) (*gin.Engine, *int64) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var read int64
	r.Use(MaxBody(cap))
	r.POST("/x", func(c *gin.Context) {
		n, err := io.Copy(io.Discard, c.Request.Body)
		read = n
		if err != nil {
			if sharedapi.RequestBodyTooLarge(err) {
				sharedapi.PayloadTooLarge(c, "too large")
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"read": n})
	})
	return r, &read
}

// endlessBody streams bytes without declaring a Content-Length, which is what
// a chunked upload looks like. It counts what was pulled out of it, so the test
// can assert the server stopped reading rather than draining the whole stream.
//
// It EOFs after `budget` rather than running forever on purpose: with the
// MaxBytesReader removed, a truly endless body makes this test hang instead of
// fail, and a hang is not a signal anyone reads. The budget is far above the
// cap, so the assertions below still detect the removal — cleanly.
type endlessBody struct {
	served int64
	budget int64
}

func (b *endlessBody) Read(p []byte) (int, error) {
	if b.served >= b.budget {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'A'
	}
	b.served += int64(len(p))
	return len(p), nil
}

func TestMaxBody_RefusesDeclaredOversizeWithoutReading(t *testing.T) {
	r, read := echoRouter(testCap)

	body := strings.NewReader(strings.Repeat("A", testCap+1))
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", w.Code)
	}
	if *read != 0 {
		t.Errorf("handler read %d bytes of an over-cap body; the ceiling is downstream of the "+
			"allocation it exists to prevent", *read)
	}
	if !strings.Contains(w.Body.String(), "1024 KiB") {
		t.Errorf("the refusal does not name the limit, so a caller cannot act on it: %s", w.Body.String())
	}
}

func TestMaxBody_StopsAnUndeclaredStreamAtTheCap(t *testing.T) {
	r, read := echoRouter(testCap)

	stream := &endlessBody{budget: 100 << 20}
	req := httptest.NewRequest(http.MethodPost, "/x", stream)
	req.ContentLength = -1 // chunked: the length is not declared
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 — a chunked body slipped past the Content-Length check", w.Code)
	}
	// The handler must see at most the cap. MaxBytesReader allows the cap plus
	// the one byte it needs to know the cap was exceeded.
	if *read > testCap+1 {
		t.Errorf("handler read %d bytes, cap is %d", *read, testCap)
	}
	// And the server must not have pulled an unbounded amount off the wire. A
	// generous multiple of the cap: net/http reads in buffered chunks, so an
	// exact bound would be brittle.
	if stream.served > 8*testCap {
		t.Errorf("the server drained %d bytes from an endless stream (cap %d) — "+
			"an attacker still gets to decide how much this process reads", stream.served, testCap)
	}
}

func TestMaxBody_AcceptsANormalBody(t *testing.T) {
	// The other polarity. A cap that refuses legitimate traffic is the same
	// defect facing the other way, so this asserts a body at the ceiling — the
	// largest thing the service says it accepts — still goes through whole.
	for _, size := range []int{0, 1024, testCap - 1, testCap} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			r, read := echoRouter(testCap)

			req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("A", size)))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("a %d-byte body was refused with %d: %s", size, w.Code, w.Body.String())
			}
			if int(*read) != size {
				t.Errorf("handler read %d of %d bytes — the body was truncated", *read, size)
			}
		})
	}
}

// TestMaxBody_BoundsHeapAgainstTheAuditedAttack is the H10 measurement: the
// 100 MiB request the auditor used, against the process rather than against a
// constant. Without the ceiling the router hands the handler a body it reads
// whole; with it, the heap barely moves.
func TestMaxBody_BoundsHeapAgainstTheAuditedAttack(t *testing.T) {
	// A handler that does what the vulnerable one did: read the whole body and
	// hold it. This is the code path being protected, not a stand-in.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MaxBody(testCap))
	var held []byte
	r.POST("/x", func(c *gin.Context) {
		b, err := io.ReadAll(c.Request.Body)
		held = b
		if err != nil {
			sharedapi.PayloadTooLarge(c, "too large")
			return
		}
		c.JSON(http.StatusOK, gin.H{"n": len(b)})
	})

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	const attack = 100 << 20 // the audited request size
	req := httptest.NewRequest(http.MethodPost, "/x", &cappedStream{remaining: attack})
	req.ContentLength = -1
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(held)

	grewMiB := (float64(after.HeapAlloc) - float64(before.HeapAlloc)) / (1 << 20)
	t.Logf("100 MiB request: status=%d bytes_held=%d retained_heap_delta=%.1f MiB", w.Code, len(held), grewMiB)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", w.Code)
	}
	if len(held) > testCap+1 {
		t.Errorf("the handler ended up holding %d bytes of a %d-byte request", len(held), attack)
	}
	// 16 MiB, against a pod limited to 256 Mi and an attack of 100 MiB.
	if grewMiB > 16 {
		t.Errorf("retained heap grew %.1f MiB on one refused request — the body is still being buffered", grewMiB)
	}
}

// cappedStream serves `remaining` bytes and then EOFs, so the test cannot hang
// if the ceiling is removed — it fails on the heap assertion instead, which is
// the signal we want.
type cappedStream struct{ remaining int }

func (s *cappedStream) Read(p []byte) (int, error) {
	if s.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > s.remaining {
		n = s.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 'A'
	}
	s.remaining -= n
	return n, nil
}
