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

// AuditSubscriber consumes audit events from NATS and persists them
// via the ActivityLogService, replacing the legacy HTTP ingestion path.
type AuditSubscriber struct {
	natsClient         *events.NATSClient
	subscriber         *events.Subscriber
	activityLogService *services.ActivityLogService
}

// NewAuditSubscriber creates a new audit event subscriber.
func NewAuditSubscriber(natsClient *events.NATSClient, activityLogService *services.ActivityLogService) *AuditSubscriber {
	return &AuditSubscriber{
		natsClient:         natsClient,
		subscriber:         events.NewSubscriber(natsClient),
		activityLogService: activityLogService,
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
		}
	}

	return lastErr
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

	// Derive event type and category from action
	log.EventType = e.Action
	log.EventCategory = "api"

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
