package audit

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// newTestMiddleware builds a Middleware that batches in memory and never
// starts the flush goroutine, so a test can inspect exactly what was recorded.
// BatchSize is large enough that addToBatch never triggers a flush.
func newTestMiddleware() *Middleware {
	cfg := DefaultConfig()
	cfg.BatchSize = 1000
	return &Middleware{
		config: cfg,
		batch:  make([]*ActivityLogRequest, 0, cfg.BatchSize),
	}
}

func (m *Middleware) recorded() []*ActivityLogRequest { return m.PendingEntries() }

func TestLogConsumerEvent_RecordsTenantSubjectOutcomeAndCounts(t *testing.T) {
	m := newTestMiddleware()
	tenantID := uuid.New()
	jobID := uuid.New()

	err := m.LogConsumerEvent(context.Background(), ConsumerEvent{
		TenantID:      &tenantID,
		Source:        "pcap.jobs.process",
		Stream:        "PCAP_JOBS",
		EventCategory: "discovery",
		EventType:     "discovery.pcap.processed",
		ResourceType:  "pcap_job",
		ResourceID:    &jobID,
		Counts:        map[string]int{"discoveries": 7, "packets_processed": 1200},
		Duration:      1500 * time.Millisecond,
		Success:       true,
	})
	if err != nil {
		t.Fatalf("LogConsumerEvent returned error: %v", err)
	}

	entries := m.recorded()
	if len(entries) != 1 {
		t.Fatalf("recorded %d entries, want 1", len(entries))
	}
	e := entries[0]

	if e.TenantID == nil || *e.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", e.TenantID, tenantID)
	}
	if e.ResourceID == nil || *e.ResourceID != jobID {
		t.Errorf("ResourceID = %v, want %v", e.ResourceID, jobID)
	}
	if e.ResourceType == nil || *e.ResourceType != "pcap_job" {
		t.Errorf("ResourceType = %v, want pcap_job", e.ResourceType)
	}
	if e.EventType != "discovery.pcap.processed" {
		t.Errorf("EventType = %q", e.EventType)
	}
	// user_type must stay within the activity_logs valid_user_type CHECK.
	if e.UserType != "tenant" && e.UserType != "platform" {
		t.Errorf("UserType = %q, must be tenant or platform", e.UserType)
	}
	if !e.Success {
		t.Error("Success = false, want true")
	}
	if e.Action != "process" {
		t.Errorf("Action = %q, want default %q", e.Action, "process")
	}
	if got := e.Metadata["source"]; got != "pcap.jobs.process" {
		t.Errorf("metadata source = %v", got)
	}
	if got := e.Metadata["stream"]; got != "PCAP_JOBS" {
		t.Errorf("metadata stream = %v", got)
	}
	if got := e.Metadata["duration_ms"]; got != int64(1500) {
		t.Errorf("metadata duration_ms = %v, want 1500", got)
	}
	counts, ok := e.Metadata["counts"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata counts missing or wrong type: %#v", e.Metadata["counts"])
	}
	if counts["discoveries"] != 7 || counts["packets_processed"] != 1200 {
		t.Errorf("counts = %#v", counts)
	}
	if len(e.Tags) == 0 || e.Tags[0] != "system_initiated" {
		t.Errorf("Tags = %v, want system_initiated", e.Tags)
	}
}

// The audit record must describe the work, never the data. The consumer event
// carries no payload field by construction (Counts is map[string]int); this
// pins that nothing else smuggles one in.
func TestLogConsumerEvent_CarriesNoPayload(t *testing.T) {
	m := newTestMiddleware()
	tenantID := uuid.New()

	if err := m.LogConsumerEvent(context.Background(), ConsumerEvent{
		TenantID:      &tenantID,
		Source:        "db-poll",
		EventCategory: "discovery",
		EventType:     "discovery.batch.processed",
		Counts:        map[string]int{"discoveries_read": 3},
		Success:       true,
	}); err != nil {
		t.Fatalf("LogConsumerEvent returned error: %v", err)
	}

	e := m.recorded()[0]
	if e.OldValues != nil || e.NewValues != nil {
		t.Error("consumer events must not carry old/new value snapshots")
	}
	for k, v := range e.Metadata {
		if k == "counts" {
			continue
		}
		if s, ok := v.(string); ok && len(s) > 128 {
			t.Errorf("metadata %q holds a %d-char string — payloads must not reach the audit trail", k, len(s))
		}
	}
}

func TestLogConsumerEvent_FailureRecordsClassificationNotErrorText(t *testing.T) {
	m := newTestMiddleware()
	tenantID := uuid.New()

	longKind := strings.Repeat("x", maxErrorKindLen+40)
	if err := m.LogConsumerEvent(context.Background(), ConsumerEvent{
		TenantID:      &tenantID,
		Source:        "db-poll",
		EventCategory: "discovery",
		EventType:     "discovery.batch.failed",
		Success:       false,
		ErrorKind:     longKind,
	}); err != nil {
		t.Fatalf("LogConsumerEvent returned error: %v", err)
	}

	e := m.recorded()[0]
	if e.ErrorMessage == nil {
		t.Fatal("failed event recorded no error classification")
	}
	if len(*e.ErrorMessage) > maxErrorKindLen {
		t.Errorf("ErrorMessage len = %d, want <= %d (an err.Error() must truncate, not paste)", len(*e.ErrorMessage), maxErrorKindLen)
	}
	if !e.RequiresAttention {
		t.Error("failed consumer event should set RequiresAttention")
	}
}

func TestLogConsumerEvent_RejectsCategoryTheSchemaWouldReject(t *testing.T) {
	m := newTestMiddleware()
	err := m.LogConsumerEvent(context.Background(), ConsumerEvent{
		EventCategory: "not-a-real-category",
		EventType:     "x.y",
		Success:       true,
	})
	if err == nil {
		t.Fatal("expected an error for a category outside valid_event_category")
	}
	if len(m.recorded()) != 0 {
		t.Error("invalid event was still recorded")
	}
}

func TestLogConsumerEvent_NilMiddlewareIsSafe(t *testing.T) {
	var m *Middleware
	if err := m.LogConsumerEvent(context.Background(), ConsumerEvent{
		EventCategory: "discovery",
		EventType:     "discovery.batch.processed",
	}); err != nil {
		t.Fatalf("nil middleware should be a no-op, got %v", err)
	}
}

// TestExtractAuditMiddleware_RealGinContext pins the gin-1.11 regression:
// ExtractAuditMiddleware was duck-typed on Get(string), gin widened it to
// Get(any), and every caller silently got (nil, false) — skipping its explicit
// audit entry with no error anywhere. A stub context cannot catch that, so this
// drives a real *gin.Context.
func TestExtractAuditMiddleware_RealGinContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware()

	r := gin.New()
	var got *Middleware
	var ok bool
	r.GET("/x", func(c *gin.Context) {
		c.Set("audit_middleware", m)
		got, ok = ExtractAuditMiddleware(c)
		c.Status(200)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))

	if !ok || got != m {
		t.Fatalf("ExtractAuditMiddleware(*gin.Context) = (%v, %v), want the middleware", got, ok)
	}
}

func TestExtractAuditMiddleware_MissingOrWrongType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var absent, wrong bool
	r.GET("/x", func(c *gin.Context) {
		_, absent = ExtractAuditMiddleware(c)
		c.Set("audit_middleware", "not a middleware")
		_, wrong = ExtractAuditMiddleware(c)
		c.Status(200)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))

	if absent {
		t.Error("reported a middleware when the key was absent")
	}
	if wrong {
		t.Error("reported a middleware for a value of the wrong type")
	}
}
