package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

// IncidentAlertType identifies security-incident notifications to
// notification-service's routing. The alert SOURCE is the literal "monitoring"
// below (kept a literal so frontend-v2's alert-sources.test.ts, which scans
// producers for AlertSource literals, sees it): the platform-track producers
// (service_down, metric_threshold) already use it, the seeded platform rules
// match any source, and the tenant routing-rule dropdown deliberately does not
// offer it — these are operator-facing, so no tenant rule can ever claim them.
const IncidentAlertType = "security_incident"

// BuildIncidentResponseHook is the one place monitoring-service turns its
// configuration into the log-triggered incident hook, so main.go and the tests
// wire the same thing. Disabled returns nil (the log store treats nil as "no
// hook"). Enabled with a nil NATS client still returns a hook: each incident
// then fails visibly (logged and recorded in the access audit) rather than the
// hook silently not existing.
func BuildIncidentResponseHook(db *sql.DB, client *events.NATSClient, enabled bool) *IncidentResponseHook {
	if !enabled {
		return nil
	}
	return NewIncidentResponseHook(db, NewNotificationIncidentCreator(client), true)
}

// NotificationIncidentCreator implements IncidentCreator by publishing the
// incident to notification-service on NATS `notifications.send`, the one
// delivery path. notification-service applies platform routing rules (channels,
// severity filters, digests, retries, history) — this service owns no delivery
// code of its own.
//
// SCOPE: platform. Incidents are raised from platform service logs (PII in a
// log line, a critical security event, an auth-failure pattern), so the people
// who must act on them are platform operators. The event carries no tenant id —
// notification-service reads that as "platform notification" — and the tenant
// the log line belonged to travels only as metadata.affected_tenants. Routing
// it to that tenant would hand one customer the platform's internal security
// posture.
type NotificationIncidentCreator struct {
	// publish sends one message to a NATS subject. A func rather than a
	// *events.NATSClient so the wiring can be tested without a server.
	publish func(subject string, data interface{}) error
}

// NewNotificationIncidentCreator builds an incident creator that publishes to
// notification-service over the given NATS client. A nil client is allowed:
// every incident then returns an error (logged, and recorded as a failed hook
// in the access audit) instead of vanishing.
func NewNotificationIncidentCreator(client *events.NATSClient) *NotificationIncidentCreator {
	return &NotificationIncidentCreator{publish: func(subject string, data interface{}) error {
		if client == nil {
			return fmt.Errorf("NATS unavailable: incident notification not published")
		}
		return events.PublishJSON(client, subject, data)
	}}
}

// CreateSecurityIncident publishes the incident as a notification.
func (n *NotificationIncidentCreator) CreateSecurityIncident(_ context.Context, incident SecurityIncident) (*SecurityIncident, error) {
	if n == nil || n.publish == nil {
		return &incident, nil
	}

	message := incident.Title
	if incident.Description != nil && *incident.Description != "" {
		message = *incident.Description
	}

	affected := make([]string, 0, len(incident.AffectedTenants))
	for _, t := range incident.AffectedTenants {
		affected = append(affected, t.String())
	}

	event := events.NotificationEvent{
		// The incident's own id: a NATS redelivery is then the same event id to
		// a webhook receiver / PagerDuty dedup key, not a second incident.
		EventID:     incident.ID,
		AlertSource: "monitoring",
		AlertType:   IncidentAlertType,
		Severity:    incident.Severity,
		Title:       incident.Title,
		Message:     message,
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"incident_id":      incident.IncidentID,
			"category":         incident.Category,
			"priority":         incident.Priority,
			"log_id":           incident.Metadata["log_id"],
			"service_name":     incident.Metadata["service_name"],
			"affected_tenants": affected,
		},
	}

	if err := n.publish(events.SubjectNotificationsSend, event); err != nil {
		return nil, fmt.Errorf("failed to publish incident notification: %w", err)
	}
	return &incident, nil
}
