package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// AlertSubscriber consumes alert lifecycle subjects:
//   - alerts.raise / alerts.resolve — the generic path any service uses to
//     open/escalate/auto-resolve a stateful alert
//   - inventory.lifecycle.certificate.expiring — translated into cert-expiry
//     alert raises (the alert engine took over cert notifications from the
//     retired notification-service certificate subscriber, so open/escalate
//     fan-out happens once, on tier crossings, with alert linkage)
type AlertSubscriber struct {
	subscriber  *events.Subscriber
	alertEngine *AlertEngineService
}

func NewAlertSubscriber(natsClient *events.NATSClient, alertEngine *AlertEngineService) *AlertSubscriber {
	return &AlertSubscriber{
		subscriber:  events.NewSubscriber(natsClient),
		alertEngine: alertEngine,
	}
}

// Start subscribes to the alert lifecycle subjects.
func (s *AlertSubscriber) Start() error {
	if err := s.subscriber.Subscribe(events.SubscriptionConfig{
		Stream:            "ALERTS",
		Subject:           events.SubjectAlertsRaise,
		Durable:           "compliance-alerts-raise",
		QueueGroup:        "compliance-engine",
		MaxDeliver:        3,
		AckWait:           15 * time.Second,
		ProcessingTimeout: 10 * time.Second,
	}, s.handleRaise); err != nil {
		return fmt.Errorf("subscribe alerts.raise: %w", err)
	}

	if err := s.subscriber.Subscribe(events.SubscriptionConfig{
		Stream:            "ALERTS",
		Subject:           events.SubjectAlertsResolve,
		Durable:           "compliance-alerts-resolve",
		QueueGroup:        "compliance-engine",
		MaxDeliver:        3,
		AckWait:           15 * time.Second,
		ProcessingTimeout: 10 * time.Second,
	}, s.handleResolve); err != nil {
		return fmt.Errorf("subscribe alerts.resolve: %w", err)
	}

	if err := s.subscriber.Subscribe(events.SubscriptionConfig{
		Stream:            "INVENTORY_LIFECYCLE",
		Subject:           events.SubjectLifecycleCertificateExpiring,
		Durable:           "compliance-alerts-cert-expiring",
		QueueGroup:        "compliance-engine",
		MaxDeliver:        3,
		AckWait:           15 * time.Second,
		ProcessingTimeout: 10 * time.Second,
	}, s.handleCertificateExpiring); err != nil {
		return fmt.Errorf("subscribe certificate.expiring: %w", err)
	}

	return nil
}

// Stop drains all subscriptions gracefully.
func (s *AlertSubscriber) Stop() {
	if s.subscriber != nil {
		if err := s.subscriber.Drain(); err != nil {
			log.Printf("[AlertSubscriber] Drain failed: %v", err)
		}
	}
}

func (s *AlertSubscriber) handleRaise(ctx context.Context, msg *nats.Msg) error {
	var ev events.AlertRaiseEvent
	if err := events.UnmarshalMsg(msg, &ev); err != nil {
		log.Printf("[AlertSubscriber] Bad raise payload: %v", err)
		return nil // don't redeliver bad data
	}
	if _, err := s.alertEngine.Raise(ctx, ev); err != nil {
		log.Printf("[AlertSubscriber] Raise failed (type=%s tenant=%s): %v", ev.AlertType, ev.TenantID, err)
		return err
	}
	return nil
}

func (s *AlertSubscriber) handleResolve(ctx context.Context, msg *nats.Msg) error {
	var ev events.AlertResolveEvent
	if err := events.UnmarshalMsg(msg, &ev); err != nil {
		log.Printf("[AlertSubscriber] Bad resolve payload: %v", err)
		return nil
	}
	if err := s.alertEngine.ResolveAuto(ctx, ev); err != nil {
		log.Printf("[AlertSubscriber] Auto-resolve failed (type=%s tenant=%s): %v", ev.AlertType, ev.TenantID, err)
		return err
	}
	return nil
}

// handleCertificateExpiring turns cert lifecycle tier crossings into alert
// raises. Severity mirrors the tier mapping the notification path used
// (normalized enum): ≤7d critical, ≤14d high, ≤30d medium, else info.
func (s *AlertSubscriber) handleCertificateExpiring(ctx context.Context, msg *nats.Msg) error {
	var envelope events.LifecycleEnvelope
	if err := events.UnmarshalMsg(msg, &envelope); err != nil {
		log.Printf("[AlertSubscriber] Bad lifecycle envelope: %v", err)
		return nil
	}
	var payload events.CertificateExpiringPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		log.Printf("[AlertSubscriber] Bad certificate payload: %v", err)
		return nil
	}

	severity := "info"
	switch {
	case payload.DaysRemaining <= 7:
		severity = "critical"
	case payload.DaysRemaining <= 14:
		severity = "high"
	case payload.DaysRemaining <= 30:
		severity = "medium"
	}

	commonName := "unknown"
	if payload.CommonName != nil {
		commonName = *payload.CommonName
	}

	title := fmt.Sprintf("Certificate expiring: %s", commonName)
	message := fmt.Sprintf("Certificate %s expires in %d days (on %s)",
		commonName, payload.DaysRemaining, payload.NotAfter.Format("2006-01-02"))
	if payload.DaysRemaining <= 0 {
		title = fmt.Sprintf("Certificate expired: %s", commonName)
		message = fmt.Sprintf("Certificate %s expired on %s", commonName, payload.NotAfter.Format("2006-01-02"))
	}

	certID := payload.CertificateID
	_, err := s.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      envelope.EventID,
		TenantID:     envelope.TenantID,
		AlertType:    "certificate_expiring",
		Source:       "inventory-service",
		SubjectType:  "certificate",
		SubjectID:    &certID,
		SubjectLabel: commonName,
		Severity:     severity,
		Title:        title,
		Message:      message,
		Metadata: map[string]interface{}{
			"certificate_id": payload.CertificateID.String(),
			"asset_id":       payload.AssetID.String(),
			"common_name":    commonName,
			"not_after":      payload.NotAfter.Format(time.RFC3339),
			"days_remaining": payload.DaysRemaining,
			"title":          title,
		},
		Timestamp: time.Now(),
	})
	if err != nil {
		log.Printf("[AlertSubscriber] Cert alert raise failed (cert=%s tenant=%s): %v",
			payload.CertificateID, envelope.TenantID, err)
		return err
	}
	return nil
}
