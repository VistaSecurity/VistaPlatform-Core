package audit

import (
	"context"
	"strconv"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/ai"
)

// AI provider-call audit vocabulary.
//
// EventCategoryData rather than a new "ai" category: audit.activity_logs
// carries a CHECK constraint listing the twelve categories it accepts, and a
// thirteenth would be a schema change. "data" is the honest fit — a generative
// call is tenant-derived data leaving the deployment — and the event type
// carries the precision the category cannot.
const (
	// EventTypeAIProviderCall is one crossing of the ADR-0008 provider
	// boundary: one prompt, one model, one invoker. It is written whether the
	// call succeeded, failed, or was refused at the boundary.
	EventTypeAIProviderCall = "ai.provider.call"
)

// ActivityLogger is the slice of [Middleware] an [AISink] needs. Narrowed to
// one method so a test can substitute a buffer, and so nothing here depends on
// the batching, NATS or mTLS machinery around it.
type ActivityLogger interface {
	LogActivity(ctx context.Context, entry *ActivityLogRequest) error
}

// AISink writes ADR-0008 D4.7 audit events onto the platform audit rail.
//
// It is the adapter between [ai.AuditSink] — which shared/ai defines and
// ai.WithAudit calls once per provider call — and the activity-log shape every
// other audited action in the platform already uses. Wire it with:
//
//	sink := audit.NewAISink(auditMiddleware, "cbom-service")
//	provider = ai.Boundary(provider, sink)
//
// # What it does NOT do
//
// It does not store the prompt. D4.7 is explicit: "Prompts themselves are not
// stored unless the tenant opts in", and [ai.AuditRecord] carries only the
// SHA-256 of what crossed the boundary. Recording the prompt here would put a
// second copy of everything the model was told into a table with different
// retention rules from the one it came out of.
//
// It also never fails a completion. [ai.AuditSink.Record] returns nothing by
// design, and a write failure is logged by the layer below rather than
// propagated: an audit sink that can fail a call makes the audit trail a source
// of outages.
type AISink struct {
	logger      ActivityLogger
	serviceName string
}

// NewAISink returns a sink writing through logger. A nil logger yields a nil
// *AISink, which is still safe to call — Record is nil-receiver tolerant — so a
// service whose audit middleware is disabled wires the boundary the same way
// and simply records nothing.
func NewAISink(logger ActivityLogger, serviceName string) *AISink {
	if logger == nil {
		return nil
	}
	return &AISink{logger: logger, serviceName: serviceName}
}

// actorKey carries the tenant on whose behalf a generative call is made.
//
// [ai.Request] deliberately holds no tenant id — ADR-0008 D6 puts tenant
// isolation in the tool layer and keeps the prompt free of anything that looks
// like an authorisation claim — so the tenant reaches the audit row through the
// context instead of through the prompt. The invoker DOES travel on the
// request (D4.7 asks which user), so only the tenant needs carrying here.
type actorKey struct{}

type actor struct {
	tenantID uuid.UUID
	userType string
}

// WithAIActor records the tenant a generative call is being made for, so the
// audit row lands in that tenant's activity log rather than as an
// unattributable platform event.
//
// userType must be "tenant" or "platform": audit.activity_logs constrains it to
// those two. Anything else is normalised to "tenant".
func WithAIActor(ctx context.Context, tenantID uuid.UUID, userType string) context.Context {
	if userType != "platform" {
		userType = "tenant"
	}
	return context.WithValue(ctx, actorKey{}, actor{tenantID: tenantID, userType: userType})
}

func actorFrom(ctx context.Context) (actor, bool) {
	a, ok := ctx.Value(actorKey{}).(actor)
	return a, ok
}

// Record implements [ai.AuditSink].
func (s *AISink) Record(ctx context.Context, rec ai.AuditRecord) {
	if s == nil || s.logger == nil {
		return
	}

	entry := &ActivityLogRequest{
		EventType:     EventTypeAIProviderCall,
		EventCategory: EventCategoryData,
		Action:        string(rec.Seam),
		UserType:      "tenant",
		Success:       rec.Err == "" && !rec.Refused,
		OccurredAt:    rec.At,
		// A refused call is a boundary violation by the calling service — an
		// unredacted prompt, or one naming no invoker. It is exactly the thing
		// an operator should be shown rather than left to find in a log.
		RequiresAttention: rec.Refused,
		Metadata: map[string]interface{}{
			"service":       s.serviceName,
			"seam":          string(rec.Seam),
			"provider":      rec.Provider,
			"model_id":      rec.ModelID,
			"prompt_sha256": rec.PromptSHA256,
			"input_tokens":  rec.InputTokens,
			"output_tokens": rec.OutputTokens,
			"refused":       rec.Refused,
			"invoker":       rec.Invoker,
		},
		Tags: []string{"ai", string(rec.Seam)},
	}
	if rec.Err != "" {
		msg := rec.Err
		entry.ErrorMessage = &msg
	}
	if id, err := uuid.Parse(rec.Invoker); err == nil {
		// Only a real user id goes in user_id. A rule name ("reconcile-worker")
		// stays in metadata.invoker rather than being coerced into a uuid
		// column, where it would either fail the write or invent a user.
		entry.UserID = &id
	}
	if a, ok := actorFrom(ctx); ok {
		if a.tenantID != uuid.Nil {
			tenant := a.tenantID
			entry.TenantID = &tenant
		}
		entry.UserType = a.userType
	}
	if rec.InputTokens+rec.OutputTokens > 0 {
		entry.Metadata["total_tokens"] = strconv.Itoa(rec.InputTokens + rec.OutputTokens)
	}
	if len(rec.Attributes) > 0 {
		// Nested under one key rather than merged into the metadata map. A
		// merge would let a seam-supplied name shadow "prompt_sha256" or
		// "invoker" — the fields this record exists to carry — and the shadowed
		// row would look exactly like a real one.
		attrs := make(map[string]interface{}, len(rec.Attributes))
		for k, v := range rec.Attributes {
			attrs[k] = v
		}
		entry.Metadata["attributes"] = attrs
	}

	_ = s.logger.LogActivity(ctx, entry)
}

// Compile-time proof that the adapter still satisfies the interface it exists
// for. If ai.AuditSink grows a method, this fails at build time rather than at
// the first generative call in production.
var _ ai.AuditSink = (*AISink)(nil)
