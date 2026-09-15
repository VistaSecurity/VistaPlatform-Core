package resourcetracking_test

// The resource-tracking middleware must not consume the request body
// (security review X.5, follow-up to X5-02).
//
// X5-02 fixed the AUDIT middleware, which read every request body into a buffer
// and never used the bytes, and it fixed it with a test that drove the audit
// middleware alone. That test stayed green while the hole stayed open, because
// the six services that carry an upload cap register
// `resourcetracking.Middleware` FIRST — auth, admin, cbom, compliance-engine,
// inventory-service and sensor-manager all do `router.Use(resourcetracking…)`
// before `router.Use(audit…)` — and this middleware drained the body too, for
// the same stated reason and with the same bytes thrown away.
//
// So the caps X5-02 is about (the SBOM upload's 32 MiB, the catalogue bundle's,
// /ask's, draft-controls') were still being applied to a body that was already
// resident after that fix landed. This test is written against the PRODUCTION
// ORDER of the two middlewares rather than against either one on its own,
// because the order is what made the first fix inert.
//
// To mutation-test: restore
//
//	bodyBytes, err := io.ReadAll(c.Request.Body)
//	if err == nil {
//	        requestSize = int64(len(bodyBytes))
//	        c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
//	}
//
// in Tracker.Middleware and the first test fails with the full body length. The
// second test is the other polarity, and it is the one that makes the fix a
// change rather than a deletion: the usage meter must still report the bytes,
// so a middleware that simply stopped touching the body fails it.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	auditmw "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
)

// countingBody offers `remaining` bytes of 'x' and reports how many were pulled
// out of it, so the test can tell "the handler's cap stopped the read" from
// "something upstream had already drained it".
type countingBody struct {
	remaining int
	read      *int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > b.remaining {
		n = b.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	b.remaining -= n
	atomic.AddInt64(b.read, int64(n))
	return n, nil
}

func (b *countingBody) Close() error { return nil }

// newServiceRouter mounts the two global middlewares in the order every service
// that carries an upload cap mounts them: resource tracking, then audit, then
// the handler. The returned channel receives the metric batch the tracker
// actually posts, so the second test can assert the usage number rather than
// assume it.
func newServiceRouter(t *testing.T, handler gin.HandlerFunc) (*gin.Engine, <-chan resourcetracking.BatchRequest) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	posted := make(chan resourcetracking.BatchRequest, 4)
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req resourcetracking.BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		select {
		case posted <- req:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tracker.Close)

	trackerCfg := resourcetracking.DefaultConfig()
	trackerCfg.Enabled = true
	trackerCfg.ServiceName = "test-service"
	trackerCfg.TrackerURL = tracker.URL
	trackerCfg.BatchSize = 1 // flush on the first metric
	trackerCfg.FlushInterval = time.Hour
	trackerCfg.DisableCircuitBreaker = true

	auditCfg := auditmw.DefaultConfig()
	auditCfg.Enabled = true
	auditCfg.AuditServiceURL = "http://127.0.0.1:1" // never reached; the batch is async

	r := gin.New()
	r.Use(resourcetracking.Middleware(trackerCfg))
	r.Use(auditmw.NewMiddleware(auditCfg).LogRequest())
	r.POST("/upload", handler)
	return r, posted
}

func TestServiceMiddlewareStack_DoesNotDrainTheBodyAheadOfAHandlersCap(t *testing.T) {
	const bodySize = 1 << 20 // 1 MiB offered
	const handlerCap = 1024  // the handler will accept this much

	var read int64
	r, _ := newServiceRouter(t, func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, handlerCap)
		if _, err := io.ReadAll(c.Request.Body); err == nil {
			t.Error("the handler read the whole body past its own cap")
		}
		c.Status(http.StatusRequestEntityTooLarge)
	})

	req := httptest.NewRequest(http.MethodPost, "/upload", &countingBody{remaining: bodySize, read: &read})
	req.Header.Set("X-Tenant-ID", uuid.NewString())
	req.ContentLength = bodySize
	r.ServeHTTP(httptest.NewRecorder(), req)

	// MaxBytesReader reads up to cap+1 to decide it is over; a little slack for
	// the buffering io.ReadAll does around that.
	if got := atomic.LoadInt64(&read); got > handlerCap+4096 {
		t.Fatalf("%d bytes were pulled out of the request body for a handler that caps at %d — "+
			"something upstream of the cap drained it, so every upload bound in this codebase is decoration",
			got, handlerCap)
	}
}

// The inverse polarity: a handler that wants the body still gets ALL of it,
// byte for byte, and the meter still reports the bytes it read. A middleware
// that stopped touching the body would pass the test above perfectly and
// silently stop metering every tenant's payload.
func TestServiceMiddlewareStack_LeavesTheBodyReadableAndStillMetersIt(t *testing.T) {
	const payload = `{"question":"which assets are end of life?"}`

	var got string
	r, posted := newServiceRouter(t, func(c *gin.Context) {
		b, err := io.ReadAll(c.Request.Body)
		if err != nil {
			t.Errorf("reading the body in the handler: %v", err)
		}
		got = string(b)
		// No response body, so the metric's network_bytes IS the request size.
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/upload", io.NopCloser(newStringBody(payload)))
	req.Header.Set("X-Tenant-ID", uuid.NewString())
	req.ContentLength = int64(len(payload))
	r.ServeHTTP(httptest.NewRecorder(), req)

	if got != payload {
		t.Fatalf("handler read %q, want %q", got, payload)
	}

	select {
	case batch := <-posted:
		if batch.NetworkBytes != int64(len(payload)) {
			t.Fatalf("the meter reported %d network bytes for a %d-byte request with an empty "+
				"response — the usage number the fix was not supposed to change has changed",
				batch.NetworkBytes, len(payload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the tracker posted no metric; the meter stopped measuring")
	}
}

func newStringBody(s string) io.Reader { return &stringBody{s: s} }

type stringBody struct {
	s string
	i int
}

func (b *stringBody) Read(p []byte) (int, error) {
	if b.i >= len(b.s) {
		return 0, io.EOF
	}
	n := copy(p, b.s[b.i:])
	b.i += n
	return n, nil
}
