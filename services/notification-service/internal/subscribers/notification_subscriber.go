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
//
// e.Title used to be dropped on the floor here — SendNotificationRequest had
// no Title field, so a properly-composed title (e.g. compliance-engine's
// "Control noncompliant: PCI-3.4") never reached the bell. It was replaced by
// delivery_service.go's unconditional "[severity] alert_type" fallback. Carry
// it through now so a producer that composed a real title gets to use it.
func convertNotificationEventToRequest(e *events.NotificationEvent) *models.SendNotificationRequest {
	req := &models.SendNotificationRequest{
		AlertSource:      e.AlertSource,
		AlertType:        e.AlertType,
		Severity:         e.Severity,
		Title:            e.Title,
		Message:          e.Message,
		Metadata:         e.Metadata,
		NotificationType: "alert",
	}

	// uuid.Nil and the platform sentinel BOTH mean "this is a platform
	// notification" — route it to the platform rules, not to a tenant.
	//
	// Platform-track alerts (service_down, metric_threshold,
	// tenant_health_degraded) are raised under events.PlatformAlertTenantID
	// because alerts.tenant_id is NOT NULL and RLS-partitioned, and the alert
	// engine carries that sentinel straight through onto notifications.send.
	// Passing it on as a real tenant id sent every platform alert down the
	// TENANT path: GetTenantRulesForAlert for a tenant that intentionally has
	// no tenants row, which matches nothing — and then the history INSERT
	// violates notification_history_tenant_id_fkey. So the seeded platform
	// pack could never be consulted no matter how it was configured.
	if e.TenantID != uuid.Nil && e.TenantID != events.PlatformAlertTenantID {
		tid := e.TenantID
		req.TenantID = &tid
	}

	return req
}
