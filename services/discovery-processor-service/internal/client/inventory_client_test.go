package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
)

func clientFor(t *testing.T, h http.HandlerFunc) *InventoryClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func withLimit(t *testing.T, n int64) {
	t.Helper()
	prev := maxResponseBytes
	maxResponseBytes = n
	t.Cleanup(func() { maxResponseBytes = prev })
}

// A response larger than the cap is refused, not buffered. Mutation: replace the
// io.LimitReader with a bare resp.Body and the oversize answer is accepted.
func TestImportFindings_RefusesAnOversizeSuccessBody(t *testing.T) {
	withLimit(t, 64)
	c := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"imported":1,"padding":"` + strings.Repeat("x", 1024) + `"}`))
	})
	_, err := c.ImportFindings(uuid.New(), uuid.New(), nil)
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("err = %v, want the oversize refusal", err)
	}
}

// An oversize ERROR body still classifies on its status (a 503 stays transient)
// and keeps only a bounded excerpt.
func TestImportFindings_OversizeErrorBodyKeepsItsStatus(t *testing.T) {
	withLimit(t, 64)
	c := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(strings.Repeat("y", 1<<20)))
	})
	_, err := c.ImportFindings(uuid.New(), uuid.New(), nil)
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want an HTTPStatusError 503", err)
	}
	if len(se.Body) > maxErrorBodyBytes {
		t.Fatalf("kept %d body bytes, want at most %d", len(se.Body), maxErrorBodyBytes)
	}
}

func TestImportFindings_ReadsAResponseUnderTheCap(t *testing.T) {
	c := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"imported":3}`))
	})
	resp, err := c.ImportFindings(uuid.New(), uuid.New(), nil)
	if err != nil || resp.Imported != 3 {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
}

// The client stops READING at the cap. The server tries to stream 64 MiB; the
// client must hang up long before it has consumed that much, not buffer it all
// and check the size afterwards.
//
// Mutation: read resp.Body directly (no io.LimitReader) and the server gets all
// 64 MiB out.
func TestImportFindings_StopsReadingAtTheCap(t *testing.T) {
	withLimit(t, 1024)
	var written int64
	c := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 64<<10)
		for i := 0; i < 1024; i++ {
			n, err := w.Write(chunk)
			atomic.AddInt64(&written, int64(n))
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	if _, err := c.ImportFindings(uuid.New(), uuid.New(), nil); err == nil {
		t.Fatal("want an error for an endless body")
	}
	time.Sleep(100 * time.Millisecond) // let the handler observe the hang-up
	if got := atomic.LoadInt64(&written); got > 16<<20 {
		t.Fatalf("the server got %d bytes out; the client should have hung up near the 1 KiB cap", got)
	}
}
