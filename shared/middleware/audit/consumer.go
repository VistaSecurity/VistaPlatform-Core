package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ConsumerEvent is one unit of queue- or poller-driven work that mutated (or
// tried to mutate) tenant data.
//
// LogRequest covers HTTP surfaces. The processor services (pcap-processor,
// discovery-processor-service) mutate tenant data without ever serving a
// tenant HTTP request — their only HTTP surface is /health — so nothing they
// did was recorded anywhere durable. This is the consumer-path equivalent:
// same store, same batch/NATS transport, same ActivityLogRequest shape.
//
// # Counts, never payloads
//
// Counts is deliberately map[string]int and not map[string]interface{}. A
// discovery batch or a PCAP carries certificates, hostnames, cipher material
// and whatever else was on the wire; an audit record must say *what was
// processed and how much*, never *what the data was*. Typing the field as int
// makes payload leakage a compile error rather than a review catch. Same
// reasoning as "Collect posture, never key material" in CLAUDE.md.
//
// ErrorKind is a short classification ("transient", "permanent",
// "import_failed"), not err.Error(). Wrapped errors routinely quote the
// payload that failed to parse, which would smuggle exactly the content
// Counts is designed to keep out. The raw error still goes to the service log;
// the audit trail records the fact and its class.
type ConsumerEvent struct {
	// TenantID is the tenant whose data was processed. Nil only for work that
	// genuinely has no tenant (there is very little of it).
	TenantID *uuid.UUID

	// Source identifies where the work arrived from — a NATS subject, or a
	// short label like "db-poll" for poller-driven work.
	Source string

	// Stream is the JetStream stream name, when the work came from NATS.
	Stream string

	// EventCategory must be one of the activity_logs valid_event_category
	// values. Invalid categories are rejected here rather than silently
	// failing the insert inside audit-service.
	EventCategory string

	// EventType is the dotted event name, e.g. "discovery.batch.processed".
	EventType string

	// Action is the verb recorded on the entry; defaults to "process".
	Action string

	// ResourceType / ResourceID identify what was worked on (e.g. "pcap_job"
	// plus the job id, or "discovery_batch").
	ResourceType string
	ResourceID   *uuid.UUID

	// ResourceRef is a non-UUID identifier for the unit of work, used when the
	// id is not a UUID (discovery batch ids are free-form strings).
	ResourceRef string

	// Counts records what was materialized. Keys are caller-chosen; values are
	// counts only. See the type doc.
	Counts map[string]int

	// Duration is how long the unit of work took.
	Duration time.Duration

	// Success reports the outcome.
	Success bool

	// ErrorKind is a short, payload-free classification of the failure.
	ErrorKind string
}

// PendingEntries returns a copy of the entries batched but not yet flushed.
//
// This exists so a service can TEST that it actually mounted audit logging.
// Without it the only way to prove LogRequest is wired is to stand up a fake
// audit-service and wait for a flush, which is slow and racy — and a wiring
// check that is awkward to write is a wiring check nobody writes, which is how
// six services shipped with no audit logging at all.
func (m *Middleware) PendingEntries() []*ActivityLogRequest {
	if m == nil {
		return nil
	}
	m.batchMutex.Lock()
	defer m.batchMutex.Unlock()
	out := make([]*ActivityLogRequest, len(m.batch))
	copy(out, m.batch)
	return out
}

// maxErrorKindLen bounds ErrorKind so a caller that passes err.Error() by
// mistake truncates to something harmless instead of pasting a payload into
// the audit trail.
const maxErrorKindLen = 64

// validEventCategories mirrors the activity_logs valid_event_category CHECK
// constraint in scripts/database/schema.sql. Keeping the list here means a bad
// category fails loudly at the caller instead of being dropped by a constraint
// violation three hops away, inside a batch flush nobody is watching.
var validEventCategories = map[string]bool{
	"asset": true, "discovery": true, "compliance": true, "user": true,
	"tenant": true, "system": true, "report": true, "certificate": true,
	"data": true, "config": true, "job": true, "authentication": true,
}

// LogConsumerEvent records one unit of consumer/poller work on the shared
// audit path.
//
// It is safe on a nil receiver: a service that could not build the middleware
// (no audit-service configured in a dev shell) still runs, it just records
// nothing — the same posture LogRequest takes when Enabled is false.
func (m *Middleware) LogConsumerEvent(ctx context.Context, ev ConsumerEvent) error {
	if m == nil {
		return nil
	}
	if !validEventCategories[ev.EventCategory] {
		return fmt.Errorf("audit: invalid event_category %q for consumer event %q", ev.EventCategory, ev.EventType)
	}

	action := ev.Action
	if action == "" {
		action = "process"
	}

	metadata := map[string]interface{}{
		"source":      ev.Source,
		"duration_ms": ev.Duration.Milliseconds(),
		// The actor is the platform itself, on a tenant's data. user_type has
		// to stay 'tenant' or 'platform' (activity_logs valid_user_type), so
		// the system-initiated fact is recorded here and as a tag rather than
		// by inventing a third user_type the insert would reject.
		"initiated_by": "system",
	}
	if ev.Stream != "" {
		metadata["stream"] = ev.Stream
	}
	if ev.ResourceRef != "" {
		metadata["resource_ref"] = ev.ResourceRef
	}
	if len(ev.Counts) > 0 {
		counts := make(map[string]interface{}, len(ev.Counts))
		for k, v := range ev.Counts {
			counts[k] = v
		}
		metadata["counts"] = counts
	}

	entry := &ActivityLogRequest{
		TenantID:       ev.TenantID,
		UserType:       "tenant",
		EventType:      ev.EventType,
		EventCategory:  ev.EventCategory,
		Action:         action,
		ResourceID:     ev.ResourceID,
		Success:        ev.Success,
		OccurredAt:     time.Now(),
		Metadata:       metadata,
		Tags:           []string{"system_initiated"},
		ComplianceTags: determineComplianceTags(ev.EventCategory, action),
	}
	if ev.ResourceType != "" {
		entry.ResourceType = stringPtr(ev.ResourceType)
	}
	if !ev.Success {
		kind := ev.ErrorKind
		if kind == "" {
			kind = "unknown"
		}
		if len(kind) > maxErrorKindLen {
			kind = kind[:maxErrorKindLen]
		}
		entry.ErrorMessage = stringPtr(kind)
		entry.RequiresAttention = true
	}

	return m.LogActivity(ctx, entry)
}
