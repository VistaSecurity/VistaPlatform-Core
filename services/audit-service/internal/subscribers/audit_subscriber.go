package subscribers

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// alertEvaluator is the narrow surface of *services.AlertService the subscriber
// uses, so the ingestion path can be tested without a NATS server or a rule DB.
type alertEvaluator interface {
	EvaluateEvent(ctx context.Context, event map[string]interface{}) []services.Alert
}

// AuditSubscriber consumes audit events from NATS and persists them
// via the ActivityLogService, replacing the legacy HTTP ingestion path.
//
// It evaluates alert rules on every ingested entry, exactly as the HTTP
// ingestion handler does. Ingestion has two transports and detection must not
// depend on which one carried the event: when this path skipped rule
// evaluation, turning on the NATS transport silently disabled every audit
// alert rule with no error anywhere.
type AuditSubscriber struct {
	natsClient         *events.NATSClient
	subscriber         *events.Subscriber
	activityLogService *services.ActivityLogService
	alertService       alertEvaluator
}

// NewAuditSubscriber creates a new audit event subscriber. alertService may be
// nil, in which case ingested entries are persisted but not evaluated.
func NewAuditSubscriber(natsClient *events.NATSClient, activityLogService *services.ActivityLogService,
	alertService alertEvaluator) *AuditSubscriber {
	return &AuditSubscriber{
		natsClient:         natsClient,
		subscriber:         events.NewSubscriber(natsClient),
		activityLogService: activityLogService,
		alertService:       alertService,
	}
}

// Start subscribes to the audit.activity-logs subject and begins processing.
func (s *AuditSubscriber) Start() error {
	cfg := events.SubscriptionConfig{
		Stream:            "AUDIT",
		Subject:           events.SubjectAuditActivityLogs,
		Durable:           "audit-service-activity-logs",
		QueueGroup:        "audit-service",
		MaxDeliver:        5,
		AckWait:           30 * time.Second,
		ProcessingTimeout: 25 * time.Second,
	}

	return s.subscriber.Subscribe(cfg, s.handleAuditBatch)
}

// Stop drains all subscriptions gracefully.
func (s *AuditSubscriber) Stop() {
	if s.subscriber != nil {
		s.subscriber.Drain()
	}
}

// handleAuditBatch processes a batch of audit events from NATS.
func (s *AuditSubscriber) handleAuditBatch(ctx context.Context, msg *nats.Msg) error {
	var batch events.AuditBatchEvent
	if err := events.UnmarshalMsg(msg, &batch); err != nil {
		log.Printf("[AuditSubscriber] Failed to unmarshal batch: %v", err)
		return nil // Don't redeliver bad data
	}

	log.Printf("[AuditSubscriber] Processing batch of %d audit entries from %s", batch.Count, batch.Source)

	var lastErr error
	for _, entry := range batch.Entries {
		activityLog := convertAuditEventToActivityLog(&entry)
		if err := s.activityLogService.LogActivity(ctx, activityLog); err != nil {
			log.Printf("[AuditSubscriber] Failed to log activity %s: %v", entry.EventID, err)
			lastErr = err
			continue
		}
		s.evaluateAlerts(ctx, activityLog)
	}

	return lastErr
}

// evaluateAlerts runs the audit alert rules over one ingested entry. The event
// map shape mirrors the HTTP ingestion handler's exactly, so a rule cannot
// match on one transport and miss on the other.
func (s *AuditSubscriber) evaluateAlerts(ctx context.Context, entry *models.ActivityLog) {
	if s.alertService == nil {
		return
	}
	s.alertService.EvaluateEvent(ctx, map[string]interface{}{
		"id":             entry.ID,
		"event_type":     entry.EventType,
		"event_category": entry.EventCategory,
		"action":         entry.Action,
		"success":        entry.Success,
		"user_id":        entry.UserID,
		"tenant_id":      entry.TenantID,
		"occurred_at":    entry.OccurredAt,
	})
}

// convertAuditEventToActivityLog maps a NATS AuditEvent to the audit-service ActivityLog model.
func convertAuditEventToActivityLog(e *events.AuditEvent) *models.ActivityLog {
	log := &models.ActivityLog{
		ID:         e.EventID,
		Action:     e.Action,
		Success:    e.StatusCode < 400,
		OccurredAt: e.Timestamp,
		Metadata:   e.Metadata,
	}

	// An explicitly-authored entry carries its own outcome. Only fall back to
	// deriving it from the HTTP status when the publisher sent none — a
	// hand-logged failure has StatusCode 0, which the derivation reads as
	// success.
	if e.Success != nil {
		log.Success = *e.Success
	}

	// TenantID
	if e.TenantID != uuid.Nil {
		tid := e.TenantID
		log.TenantID = &tid
	}

	// UserID
	if e.UserID != "" {
		if uid, err := uuid.Parse(e.UserID); err == nil {
			log.UserID = &uid
		}
	}

	// Resource mapping
	if e.Resource != "" {
		log.ResourceType = &e.Resource
	}
	if e.ResourceID != "" {
		if rid, err := uuid.Parse(e.ResourceID); err == nil {
			log.ResourceID = &rid
		}
	}

	// Network info
	if e.IPAddress != "" {
		log.IPAddress = &e.IPAddress
	}
	if e.UserAgent != "" {
		log.UserAgent = &e.UserAgent
	}

	// Prefer the publisher's own event type/category; derive from the action
	// only for envelopes that carry none (auto-logged HTTP requests, and any
	// publisher predating those fields).
	log.EventType = e.EventType
	if log.EventType == "" {
		log.EventType = e.Action
	}
	log.EventCategory = e.EventCategory
	if log.EventCategory == "" {
		log.EventCategory = "api"
	}

	// UserType: propagate from the event; the activity_logs CHECK constraint
	// only allows 'tenant' or 'platform'. Events from older publishers (or
	// system-originated events with no user context) arrive without a
	// user_type — default those to 'platform' so the insert never violates
	// the constraint.
	log.UserType = e.UserType
	if log.UserType == "" {
		log.UserType = "platform"
	}

	return log
}
