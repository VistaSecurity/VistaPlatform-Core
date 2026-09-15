package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/ai"
)

type captureLogger struct{ entries []*ActivityLogRequest }

func (c *captureLogger) LogActivity(_ context.Context, e *ActivityLogRequest) error {
	c.entries = append(c.entries, e)
	return nil
}

func (c *captureLogger) only(t *testing.T) *ActivityLogRequest {
	t.Helper()
	if len(c.entries) != 1 {
		t.Fatalf("entries = %d, want exactly 1", len(c.entries))
	}
	return c.entries[0]
}

func TestAISink_RecordsTheD47Fields(t *testing.T) {
	log := &captureLogger{}
	sink := NewAISink(log, "cbom-service")

	tenant := uuid.New()
	user := uuid.New()
	at := time.Now().UTC()

	sink.Record(WithAIActor(context.Background(), tenant, "tenant"), ai.AuditRecord{
		At:           at,
		Seam:         ai.SeamNarrator,
		Provider:     "anthropic",
		ModelID:      "some-model-1",
		PromptSHA256: "abc123",
		InputTokens:  120,
		OutputTokens: 30,
		Invoker:      user.String(),
	})

	e := log.only(t)
	if e.EventType != EventTypeAIProviderCall {
		t.Fatalf("event_type = %q", e.EventType)
	}
	if e.Action != string(ai.SeamNarrator) {
		t.Fatalf("action = %q, want the seam name", e.Action)
	}
	if !e.Success || e.RequiresAttention {
		t.Fatalf("a successful call recorded as %+v", e)
	}
	if e.TenantID == nil || *e.TenantID != tenant {
		t.Fatalf("tenant_id = %v, want %v", e.TenantID, tenant)
	}
	if e.UserID == nil || *e.UserID != user {
		t.Fatalf("user_id = %v, want %v", e.UserID, user)
	}
	if !e.OccurredAt.Equal(at) {
		t.Fatalf("occurred_at = %v, want %v", e.OccurredAt, at)
	}
	for k, want := range map[string]any{
		"provider":      "anthropic",
		"model_id":      "some-model-1",
		"prompt_sha256": "abc123",
		"input_tokens":  120,
		"output_tokens": 30,
		"seam":          string(ai.SeamNarrator),
		"service":       "cbom-service",
	} {
		if got := e.Metadata[k]; got != want {
			t.Fatalf("metadata[%q] = %v, want %v", k, got, want)
		}
	}
}

// The event_category has to be one audit.activity_logs will accept — its CHECK
// constraint names twelve, and a thirteenth would be a schema change. A row the
// database rejects is an audit trail that silently has a hole in it.
func TestAISink_UsesAnAcceptedCategoryAndUserType(t *testing.T) {
	accepted := map[string]bool{
		"asset": true, "discovery": true, "compliance": true, "user": true,
		"tenant": true, "system": true, "report": true, "certificate": true,
		"data": true, "config": true, "job": true, "authentication": true,
	}
	log := &captureLogger{}
	NewAISink(log, "svc").Record(context.Background(), ai.AuditRecord{Seam: ai.SeamNarrator})

	e := log.only(t)
	if !accepted[e.EventCategory] {
		t.Fatalf("event_category = %q, which audit.activity_logs will reject", e.EventCategory)
	}
	if e.UserType != "tenant" && e.UserType != "platform" {
		t.Fatalf("user_type = %q, which audit.activity_logs will reject", e.UserType)
	}
}

// A refused call is a boundary violation by the calling service — an
// unredacted prompt, or one naming no invoker. It is recorded, marked as
// needing attention, and marked unsuccessful.
func TestAISink_RefusalIsRecordedAndFlagged(t *testing.T) {
	log := &captureLogger{}
	NewAISink(log, "svc").Record(context.Background(), ai.AuditRecord{
		Seam:    ai.SeamNarrator,
		Refused: true,
		Err:     ai.ErrUnattributed.Error(),
	})

	e := log.only(t)
	if e.Success {
		t.Fatal("a refused call recorded as successful")
	}
	if !e.RequiresAttention {
		t.Fatal("a refused call does not ask for attention")
	}
	if e.ErrorMessage == nil || !strings.Contains(*e.ErrorMessage, "invoker") {
		t.Fatalf("error_message = %v, want the refusal reason", e.ErrorMessage)
	}
	if e.Metadata["refused"] != true {
		t.Fatalf("metadata.refused = %v, want true", e.Metadata["refused"])
	}
}

// D4.7: "Prompts themselves are not stored unless the tenant opts in." The
// record carries a digest; nothing here may turn it back into text.
func TestAISink_NeverCarriesPromptText(t *testing.T) {
	log := &captureLogger{}
	NewAISink(log, "svc").Record(context.Background(), ai.AuditRecord{
		Seam:         ai.SeamNarrator,
		PromptSHA256: "deadbeef",
		Invoker:      "reconcile-worker",
	})

	e := log.only(t)
	if e.OldValues != nil || e.NewValues != nil {
		t.Fatal("the sink populated a values column, which is where a prompt would end up")
	}
	if _, present := e.Metadata["prompt"]; present {
		t.Fatal("metadata carries a prompt")
	}
	// A rule name is not a user id: it belongs in metadata, not coerced into a
	// uuid column where it would either fail the write or invent a user.
	if e.UserID != nil {
		t.Fatalf("user_id = %v for a non-uuid invoker", e.UserID)
	}
	if e.Metadata["invoker"] != "reconcile-worker" {
		t.Fatalf("metadata.invoker = %v", e.Metadata["invoker"])
	}
}

// A service whose audit middleware is disabled wires the boundary exactly the
// same way; the sink is nil and calling it is not a panic.
func TestAISink_NilIsSafe(t *testing.T) {
	var sink *AISink
	sink.Record(context.Background(), ai.AuditRecord{Seam: ai.SeamNarrator})
	if got := NewAISink(nil, "svc"); got != nil {
		t.Fatalf("NewAISink(nil) = %v, want nil", got)
	}
}

// Middleware is what production passes in. If its signature drifts from what
// the sink needs, this fails at build time rather than at the first generative
// call.
var _ ActivityLogger = (*Middleware)(nil)

// TestAISink_ForwardsSeamAttributes carries the facts only a seam knows onto
// the audit rail.
//
// The grounded query seam makes several provider calls to answer one question,
// and the per-call records cannot say which query it ended up running or
// whether anything matched. That goes in Attributes.
func TestAISink_ForwardsSeamAttributes(t *testing.T) {
	log := &captureLogger{}
	NewAISink(log, "inventory-service").Record(context.Background(), ai.AuditRecord{
		Seam:     ai.SeamQuery,
		Provider: "anthropic",
		ModelID:  "some-model-1",
		Invoker:  uuid.New().String(),
		Attributes: map[string]string{
			"canonical_query": "environment:production and status:monitoring",
			"outcome":         "answered",
		},
	})

	e := log.only(t)
	attrs, ok := e.Metadata["attributes"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata.attributes = %T, want a map", e.Metadata["attributes"])
	}
	if attrs["canonical_query"] != "environment:production and status:monitoring" {
		t.Errorf("canonical_query = %v", attrs["canonical_query"])
	}
	if attrs["outcome"] != "answered" {
		t.Errorf("outcome = %v", attrs["outcome"])
	}
}

// TestAISink_SeamAttributesCannotShadowTheD47Fields.
//
// Attributes are nested under one key rather than merged into the metadata map,
// so a seam-supplied name cannot displace prompt_sha256, invoker or model_id —
// the fields the record exists to carry. A shadowed row would look exactly like
// a real one, which is the quietest possible way to break an audit trail.
func TestAISink_SeamAttributesCannotShadowTheD47Fields(t *testing.T) {
	log := &captureLogger{}
	NewAISink(log, "svc").Record(context.Background(), ai.AuditRecord{
		Seam:         ai.SeamQuery,
		PromptSHA256: "the-real-digest",
		Invoker:      "the-real-invoker",
		Attributes: map[string]string{
			"prompt_sha256": "forged",
			"invoker":       "forged",
		},
	})

	e := log.only(t)
	if e.Metadata["prompt_sha256"] != "the-real-digest" {
		t.Errorf("prompt_sha256 = %v, want the boundary's own digest", e.Metadata["prompt_sha256"])
	}
	if e.Metadata["invoker"] != "the-real-invoker" {
		t.Errorf("invoker = %v, want the boundary's own invoker", e.Metadata["invoker"])
	}
}

// TestAISink_OmitsAnEmptyAttributesMap keeps the common shape unchanged: the
// narrator and the author write no attributes at all, and an empty nested map
// on every one of their rows would be noise in every audit query.
func TestAISink_OmitsAnEmptyAttributesMap(t *testing.T) {
	log := &captureLogger{}
	NewAISink(log, "svc").Record(context.Background(), ai.AuditRecord{Seam: ai.SeamNarrator, Invoker: "x"})
	if _, present := log.only(t).Metadata["attributes"]; present {
		t.Error("an empty attributes map was written")
	}
}
