package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// H10: this service had no request-body ceiling anywhere. CreateJob read the
// whole body with c.GetRawData(), string()ed it into a log line, and copied it
// into a fresh buffer for binding — three live copies of an attacker-chosen
// body, in a pod limited to 256 Mi. One 100 MiB POST from any authenticated
// tenant user killed it.

// limitedRouter mounts MaxBody exactly as cmd/main.go does, in front of a
// handler that binds a body the way CreateJob does.
func limitedRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sharedmw.MaxBody(MaxRequestBytes))
	r.POST("/jobs", func(c *gin.Context) {
		var req struct {
			Targets []string `json:"targets"`
		}
		if !bindJSON(c, &req) {
			return
		}
		c.JSON(http.StatusOK, gin.H{"targets": len(req.Targets)})
	})
	return r
}

// bigBody serves `size` bytes of a document that stays syntactically plausible
// the whole way — an unterminated JSON string — so the decoder keeps reading
// instead of rejecting the second byte. A body that fails to parse immediately
// would make this test pass for the wrong reason.
//
// It declares no Content-Length, which is the chunked shape a header check
// alone cannot see.
type bigBody struct {
	emitted int
	size    int
}

func (b *bigBody) Read(p []byte) (int, error) {
	if b.emitted >= b.size {
		return 0, io.EOF
	}
	const prefix = `{"targets":["`
	n := 0
	for n < len(p) && b.emitted < b.size {
		if b.emitted < len(prefix) {
			p[n] = prefix[b.emitted]
		} else {
			p[n] = 'A'
		}
		b.emitted++
		n++
	}
	return n, nil
}

func TestCreateJob_OversizedBodyIsRefusedCleanly(t *testing.T) {
	r := limitedRouter()

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	const attack = 100 << 20 // the size the auditor used
	req := httptest.NewRequest(http.MethodPost, "/jobs", &bigBody{size: attack})
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	runtime.GC()
	runtime.ReadMemStats(&after)
	grewMiB := (float64(after.HeapAlloc) - float64(before.HeapAlloc)) / (1 << 20)
	t.Logf("100 MiB POST: status=%d retained_heap_delta=%.1f MiB", w.Code, grewMiB)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "1 MiB") {
		t.Errorf("the 413 does not name the limit: %s", w.Body.String())
	}
	// 16 MiB against a pod limited to 256 Mi, for a 100 MiB request.
	if grewMiB > 16 {
		t.Errorf("retained heap grew %.1f MiB on one refused request — the body is still being buffered", grewMiB)
	}
}

func TestCreateJob_OrdinaryBodyStillWorks(t *testing.T) {
	// The other polarity. A discovery job with the service's own maximum
	// target count must still be accepted — DiscoveryService.CreateJob refuses
	// more than 1000 targets, so this is the largest legitimate request and it
	// has to fit under the ceiling comfortably.
	var sb strings.Builder
	sb.WriteString(`{"targets":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"`)
	}
	sb.WriteString(`]}`)

	body := sb.String()
	if len(body) >= MaxRequestBytes {
		t.Fatalf("a maximal 1000-target request is %d bytes, at or above the %d-byte ceiling — "+
			"the cap would refuse requests the service itself accepts", len(body), MaxRequestBytes)
	}
	t.Logf("maximal legitimate request: %d bytes, ceiling %d bytes", len(body), MaxRequestBytes)

	r := limitedRouter()
	req := httptest.NewRequest(http.MethodPost, "/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("a maximal legitimate request was refused with %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"targets":1000`) {
		t.Errorf("the body was truncated: %s", w.Body.String())
	}
}

// TestCreateJob_DoesNotLogTheRequestBody guards the second half of H10: the
// handler used to write the raw body to the pod log verbatim, so tenant input
// (and anything a tenant chose to put in it) landed in cluster logs.
//
// It reads the source because the defect IS a source construct — a
// c.GetRawData() feeding a log.Printf with a %s of the bytes. A behavioural
// test would have to capture the log writer and prove a negative about every
// possible body.
func TestCreateJob_DoesNotLogTheRequestBody(t *testing.T) {
	src, err := os.ReadFile("discovery_handler.go")
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	// Statement positions only — a line whose first non-space character is `/`
	// is a comment, and the comment explaining why this was removed names the
	// call. Matching comments would make the guard fire on its own explanation.
	code := regexp.MustCompile(`(?m)^\s*[^/\s].*`).FindAllString(string(src), -1)
	joined := strings.Join(code, "\n")

	if strings.Contains(joined, "c.GetRawData()") {
		t.Error("the handler reads the raw body again; that was the OOM path and the log-leak path")
	}
	if regexp.MustCompile(`log\.Printf\([^)]*string\(body`).MatchString(joined) {
		t.Error("the handler stringifies a request body into a log line")
	}
}

// TestRouterMountsTheBodyCeiling asserts the middleware is actually installed
// in cmd/main.go.
//
// The behavioural tests above drive a router this file builds, which proves the
// middleware works but not that production uses it — the exact gap this
// codebase has been bitten by twice (a correct fix whose wiring line could be
// deleted with every test still green). cmd is package main and cannot be
// imported, so the wiring is checked at its source.
func TestRouterMountsTheBodyCeiling(t *testing.T) {
	path := filepath.Join("..", "..", "cmd", "main.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(src)

	const mount = "sharedmw.MaxBody(handlers.MaxRequestBytes)"
	idx := strings.Index(text, mount)
	if idx < 0 {
		t.Fatalf("cmd/main.go no longer mounts %s — every route on this service is unbounded again", mount)
	}

	// And it has to be FIRST. A ceiling mounted after middleware that reads the
	// body is downstream of the allocation it exists to prevent.
	for _, later := range []string{"auditMiddleware.LogRequest()", `router.Group("/api/v1")`} {
		if j := strings.Index(text, later); j >= 0 && j < idx {
			t.Errorf("%q is mounted before the body ceiling; the cap must come first", later)
		}
	}
}
