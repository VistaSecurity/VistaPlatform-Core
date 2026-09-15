package audit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The audit middleware must not consume the request body (security review X.5).
//
// It runs as a GLOBAL r.Use() in every service, ahead of every handler. When it
// read the body into a buffer and handed the handler a NopCloser over it, every
// http.MaxBytesReader downstream was already too late: the bytes were resident
// before the handler that bounds them got to run. The SBOM upload's 32 MiB cap
// and device-interrogation's host-inventory cap are both derived numbers with
// an argument behind them, and both were preceded by an unbounded read.
//
// The test is written against the READ, not against memory, because "how much
// did this allocate" is not a thing a test can assert and "how many bytes were
// pulled from the body" is exactly what the bug was.
//
// To mutation-test: restore
//
//	requestBody, _ := io.ReadAll(c.Request.Body)
//	c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
//
// in LogRequest and this test fails with the full body length. Restore the
// deletion and it passes. The second test is the other polarity: a handler that
// DOES want the body must still get all of it.

// countingBody reports how many bytes anything pulled out of it, so the test
// can tell "the handler's cap stopped the read" from "something upstream had
// already drained it".
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

// newAuditRouter mounts LogRequest exactly as every service's main.go does.
// Enabled is what matters: the middleware returns early when it is false, which
// is why no handler could ever have depended on the buffering.
func newAuditRouter(t *testing.T, handler gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuditServiceURL = "http://127.0.0.1:1" // never dialled; the batch is async
	m := &Middleware{config: cfg, batch: make([]*ActivityLogRequest, 0, cfg.BatchSize), stopChan: make(chan struct{})}

	r := gin.New()
	r.Use(m.LogRequest())
	r.POST("/upload", handler)
	return r
}

func TestLogRequest_DoesNotDrainTheBodyAheadOfAHandlersCap(t *testing.T) {
	const bodySize = 1 << 20 // 1 MiB offered
	const handlerCap = 1024  // the handler will accept this much

	var read int64
	r := newAuditRouter(t, func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, handlerCap)
		_, err := io.ReadAll(c.Request.Body)
		if err == nil {
			t.Error("the handler read the whole body past its own cap")
		}
		c.Status(http.StatusRequestEntityTooLarge)
	})

	req := httptest.NewRequest(http.MethodPost, "/upload", &countingBody{remaining: bodySize, read: &read})
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

// The inverse polarity: a handler that wants the body still gets all of it.
// Breaking the read outright would be the same bug pointed the other way.
func TestLogRequest_LeavesTheBodyReadableByTheHandler(t *testing.T) {
	const payload = `{"question":"which assets are end of life?"}`

	var got string
	r := newAuditRouter(t, func(c *gin.Context) {
		b, err := io.ReadAll(c.Request.Body)
		if err != nil {
			t.Errorf("reading the body in the handler: %v", err)
		}
		got = string(b)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/upload", io.NopCloser(newStringBody(payload)))
	req.ContentLength = int64(len(payload))
	r.ServeHTTP(httptest.NewRecorder(), req)

	if got != payload {
		t.Fatalf("handler read %q, want %q", got, payload)
	}
}

// The RECORD is unchanged by the deletion.
//
// The read that was removed was write-only — nothing in LogRequest ever looked
// at `requestBody`, and the entry is built from the method, the path, the
// status, the query string and the caller's identity. Stating that as a test
// rather than as a claim: this drives the real middleware over a request of the
// shape every service serves and asserts each of those fields is still on the
// entry the batch would send.
//
// It is what makes the deletion provably a deletion. A change that quietly
// dropped a field would otherwise show up as a thinner audit trail on a
// deployment, months later, with nothing to point at.
func TestLogRequest_TheRecordStillCarriesWhatItCarried(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ServiceName = "inventory-service"
	cfg.AuditServiceURL = "http://127.0.0.1:1"
	cfg.BatchSize = 100 // keep the entry in the batch so it can be read back
	m := &Middleware{config: cfg, batch: make([]*ActivityLogRequest, 0, cfg.BatchSize), stopChan: make(chan struct{})}

	tenant, user := uuid.New(), uuid.New()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", tenant)
		c.Set("userID", user)
		c.Set("email", "someone@example.test")
		c.Set("role", "tenant_admin")
		c.Set("request_id", "req-42")
		c.Next()
	})
	r.Use(m.LogRequest())
	r.POST("/api/v1/inventory-service/assets", func(c *gin.Context) {
		_, _ = io.ReadAll(c.Request.Body)
		c.Status(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/inventory-service/assets?search=web01", io.NopCloser(newStringBody(`{"hostname":"web01"}`)))
	req.Header.Set("User-Agent", "vista-test/1")
	r.ServeHTTP(httptest.NewRecorder(), req)

	entries := m.PendingEntries()
	if len(entries) != 1 {
		t.Fatalf("%d entries batched, want 1", len(entries))
	}
	e := entries[0]

	if e.TenantID == nil || *e.TenantID != tenant {
		t.Errorf("tenant_id = %v, want %s", e.TenantID, tenant)
	}
	if e.UserID == nil || *e.UserID != user {
		t.Errorf("user_id = %v, want %s", e.UserID, user)
	}
	if e.UserEmail == nil || *e.UserEmail != "someone@example.test" {
		t.Errorf("user_email = %v", e.UserEmail)
	}
	// `asset`, through the real router. This used to assert only that the
	// value was storable, because determineEventType read the VERSION segment
	// as the service name and every audited request in all sixteen services
	// fell through to `system` (storable by accident). That is fixed in
	// request_category.go; this is the wiring half of the proof — the derived
	// category reaches the batched entry, not just the helper's return value.
	if e.EventCategory != EventCategoryAsset {
		t.Errorf("event_category = %q, want %q", e.EventCategory, EventCategoryAsset)
	}
	if e.EventType != "asset.assets.create" {
		t.Errorf("event_type = %q, want asset.assets.create", e.EventType)
	}
	if e.Action != "create" {
		t.Errorf("action = %q, want create", e.Action)
	}
	if !e.Success {
		t.Error("success = false for a 201")
	}
	if e.RequestID == nil || *e.RequestID != "req-42" {
		t.Errorf("request_id = %v", e.RequestID)
	}
	if e.UserAgent == nil || *e.UserAgent != "vista-test/1" {
		t.Errorf("user_agent = %v", e.UserAgent)
	}
	for _, k := range []string{"method", "path", "status_code", "duration_ms", "operation_type", "search_query_preview"} {
		if _, ok := e.Metadata[k]; !ok {
			t.Errorf("metadata is missing %q — the record is thinner than it was", k)
		}
	}
	if got := e.Metadata["path"]; got != "/api/v1/inventory-service/assets" {
		t.Errorf("metadata.path = %v", got)
	}
	if got := e.Metadata["search_query_preview"]; got != "web01" {
		t.Errorf("metadata.search_query_preview = %v — the query string is read, not the body", got)
	}
}

// newStringBody is strings.NewReader without importing strings for one call.
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
