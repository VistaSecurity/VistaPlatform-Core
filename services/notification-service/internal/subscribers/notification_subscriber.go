package subscribers

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// NotificationSubscriber consumes notification events from NATS and
// dispatches them through the NotificationService, replacing the
// legacy HTTP ingestion path used by monitoring-service and others.
type NotificationSubscriber struct {
	natsClient          *events.NATSClient
	subscriber          *events.Subscriber
	notificationService *services.NotificationService
}

// NewNotificationSubscriber creates a new notification event subscriber.
func NewNotificationSubscriber(natsClient *events.NATSClient, notificationService *services.NotificationService) *NotificationSubscriber {
	return &NotificationSubscriber{
		natsClient:          natsClient,
		subscriber:          events.NewSubscriber(natsClient),
		notificationService: notificationService,
	}
}

// Start subscribes to the notifications.send subject and begins processing.
func (s *NotificationSubscriber) Start() error {
	cfg := events.SubscriptionConfig{
		Stream:            "NOTIFICATIONS",
		Subject:           events.SubjectNotificationsSend,
		Durable:           "notification-service-send",
		QueueGroup:        "notification-service",
		MaxDeliver:        5,
		AckWait:           30 * time.Second,
		ProcessingTimeout: 25 * time.Second,
	}

	return s.subscriber.Subscribe(cfg, s.handleNotification)
}

// Stop drains all subscriptions gracefully.
func (s *NotificationSubscriber) Stop() {
	if s.subscriber != nil {
		s.subscriber.Drain()
	}
}

// handleNotification processes a single notification event from NATS.
func (s *NotificationSubscriber) handleNotification(ctx context.Context, msg *nats.Msg) error {
	var event events.NotificationEvent
	if err := events.UnmarshalMsg(msg, &event); err != nil {
		log.Printf("[NotificationSubscriber] Failed to unmarshal event: %v", err)
		return nil // Don't redeliver bad data
	}

	log.Printf("[NotificationSubscriber] Processing notification: source=%s type=%s severity=%s",
		event.AlertSource, event.AlertType, event.Severity)

	req := convertNotificationEventToRequest(&event)
	if err := s.notificationService.SendNotification(ctx, req); err != nil {
		log.Printf("[NotificationSubscriber] Failed to send notification: %v", err)
		return err
	}

	return nil
}

// convertNotificationEventToRequest maps a NATS NotificationEvent to
// the notification-service SendNotificationRequest model.
func convertNotificationEventToRequest(e *events.NotificationEvent) *models.SendNotificationRequest {
	req := &models.SendNotificationRequest{
		AlertSource:      e.AlertSource,
		AlertType:        e.AlertType,
		Severity:         e.Severity,
		Message:          e.Message,
		Metadata:         e.Metadata,
		NotificationType: "alert",
	}

	if e.TenantID != uuid.Nil {
		tid := e.TenantID
		req.TenantID = &tid
	}

	// Propagate title from metadata if present
	if e.Metadata != nil {
		if title, ok := e.Metadata["title"]; ok {
			if req.Metadata == nil {
				req.Metadata = make(map[string]interface{})
			}
			req.Metadata["title"] = title
		}
	}

	return req
}
