package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// AlertEngineService owns the stateful alert lifecycle ():
// dedupe-on-raise, severity escalation, ack/snooze/resolve with an append-only
// evidence chain, the ticket bridge, and notification fan-out through the
// normal rails (open + severity increase only — never every re-raise).
type AlertEngineService struct {
	db         *sqlx.DB
	bypassDB   *sqlx.DB
	natsClient *events.NATSClient
	ticketSvc  *TicketService
	stop       chan struct{}
}

var (
	// ErrAlertNotFound is returned when the alert doesn't exist for the tenant.
	ErrAlertNotFound = errors.New("alert not found")
	// ErrInvalidTransition is returned when an action is not legal from the
	// alert's current status (e.g. acknowledging a resolved alert).
	ErrInvalidTransition = errors.New("invalid alert state transition")
)

func NewAlertEngineService(db, bypassDB *sqlx.DB, natsClient *events.NATSClient, ticketSvc *TicketService) *AlertEngineService {
	return &AlertEngineService{
		db:         db,
		bypassDB:   bypassDB,
		natsClient: natsClient,
		ticketSvc:  ticketSvc,
		stop:       make(chan struct{}),
	}
}

// --- pure lifecycle rules (unit-tested in alert_engine_test.go) -------------

// severityRank orders the normalized severity enum; higher = more urgent.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // info or unknown
		return 0
	}
}

// transitionFor validates an action against the alert's current status and
// returns the resulting status. The lifecycle is
// active → acknowledged → snoozed → resolved with these legal moves:
//
//	acknowledge: active|snoozed → acknowledged
//	snooze:      active|acknowledged → snoozed
//	unsnooze:    snoozed → active
//	resolve:     active|acknowledged|snoozed → resolved
//
// Raises never transition an existing alert's status (they escalate severity);
// a raise against a resolved alert opens a NEW alert (dedup index excludes
// resolved rows).
func transitionFor(current, action string) (string, error) {
	switch action {
	case "acknowledge":
		if current == "active" || current == "snoozed" {
			return "acknowledged", nil
		}
	case "snooze":
		if current == "active" || current == "acknowledged" {
			return "snoozed", nil
		}
	case "unsnooze":
		if current == "snoozed" {
			return "active", nil
		}
	case "resolve":
		if current == "active" || current == "acknowledged" || current == "snoozed" {
			return "resolved", nil
		}
	}
	return "", fmt.Errorf("%w: cannot %s a %s alert", ErrInvalidTransition, action, current)
}

// --- raise / auto-resolve (event-driven producers) ---------------------------

// RaiseOutcome describes what a raise did, so callers (and tests) can assert
// notification behavior: notifications fire on "opened" and "escalated" only.
type RaiseOutcome string

const (
	RaiseOpened    RaiseOutcome = "opened"
	RaiseEscalated RaiseOutcome = "escalated"
	RaiseTouched   RaiseOutcome = "touched"
)

// Raise opens or escalates the open alert for (tenant, type, subject).
func (s *AlertEngineService) Raise(ctx context.Context, ev events.AlertRaiseEvent) (RaiseOutcome, error) {
	if ev.TenantID == uuid.Nil {
		return "", fmt.Errorf("alert raise requires tenant_id")
	}
	severity := ev.Severity
	if severityRank(severity) == 0 && severity != "info" {
		severity = "info"
	}

	outcome := RaiseTouched
	var alertID uuid.UUID

	err := shareddatabase.WithTenantTx(ctx, s.db.DB, ev.TenantID, func(tx *sql.Tx) error {
		var (
			existingID       uuid.UUID
			existingSeverity string
		)
		// Lock the open alert row (if any) so concurrent raises serialize.
		row := tx.QueryRowContext(ctx, `
			SELECT id, severity FROM alerts
			WHERE tenant_id = $1 AND alert_type = $2
			  AND COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE($3, '00000000-0000-0000-0000-000000000000'::uuid)
			  AND status <> 'resolved'
			FOR UPDATE
		`, ev.TenantID, ev.AlertType, ev.SubjectID)
		scanErr := row.Scan(&existingID, &existingSeverity)

		switch {
		case scanErr == sql.ErrNoRows:
			alertID = uuid.New()
			metadataJSON, _ := json.Marshal(ev.Metadata)
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO alerts (id, tenant_id, alert_type, source, subject_type, subject_id, subject_label,
				                    severity, status, title, message, metadata)
				VALUES ($1, $2, $3, $4, NULLIF($5,''), $6, NULLIF($7,''), $8, 'active', $9, $10, $11)
			`, alertID, ev.TenantID, ev.AlertType, ev.Source, ev.SubjectType, ev.SubjectID, ev.SubjectLabel,
				severity, ev.Title, ev.Message, metadataJSON); err != nil {
				return fmt.Errorf("insert alert: %w", err)
			}
			if err := s.appendEvent(ctx, tx, alertID, ev.TenantID, "opened", "system", nil, map[string]interface{}{
				"source": ev.Source, "severity": severity,
			}); err != nil {
				return err
			}
			outcome = RaiseOpened
			return nil

		case scanErr != nil:
			return fmt.Errorf("lookup open alert: %w", scanErr)

		default:
			alertID = existingID
			if severityRank(severity) > severityRank(existingSeverity) {
				if _, err := tx.ExecContext(ctx, `
					UPDATE alerts SET severity = $1, title = $2, message = $3,
					       last_event_at = NOW(), updated_at = NOW()
					WHERE id = $4
				`, severity, ev.Title, ev.Message, existingID); err != nil {
					return fmt.Errorf("escalate alert: %w", err)
				}
				if err := s.appendEvent(ctx, tx, existingID, ev.TenantID, "severity_changed", "system", nil, map[string]interface{}{
					"from": existingSeverity, "to": severity,
				}); err != nil {
					return err
				}
				outcome = RaiseEscalated
				return nil
			}
			// Same or lower severity: touch only, no event spam, no notification.
			if _, err := tx.ExecContext(ctx, `
				UPDATE alerts SET last_event_at = NOW(), updated_at = NOW() WHERE id = $1
			`, existingID); err != nil {
				return fmt.Errorf("touch alert: %w", err)
			}
			return nil
		}
	})
	if err != nil {
		return "", err
	}

	if outcome == RaiseOpened || outcome == RaiseEscalated {
		s.publishAlertNotification(ev.TenantID, ev.Source, ev.AlertType, severity, ev.Title, ev.Message,
			alertID, string(outcome), ev.Metadata)
	}
	return outcome, nil
}

// ResolveAuto resolves the open alert for (tenant, type, subject) with the
// system's observation that the condition cleared. No-op if no open alert.
func (s *AlertEngineService) ResolveAuto(ctx context.Context, ev events.AlertResolveEvent) error {
	if ev.TenantID == uuid.Nil {
		return fmt.Errorf("alert resolve requires tenant_id")
	}
	var (
		alertID uuid.UUID
		title   string
		source  string
	)
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, ev.TenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT id, title, source FROM alerts
			WHERE tenant_id = $1 AND alert_type = $2
			  AND COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE($3, '00000000-0000-0000-0000-000000000000'::uuid)
			  AND status <> 'resolved'
			FOR UPDATE
		`, ev.TenantID, ev.AlertType, ev.SubjectID)
		if scanErr := row.Scan(&alertID, &title, &source); scanErr == sql.ErrNoRows {
			return nil // nothing open — fine
		} else if scanErr != nil {
			return scanErr
		}
		observationJSON, _ := json.Marshal(ev.Observation)
		if _, err := tx.ExecContext(ctx, `
			UPDATE alerts SET status = 'resolved', resolution = 'auto', resolved_at = NOW(),
			       resolution_observation = $1, last_event_at = NOW(), updated_at = NOW()
			WHERE id = $2
		`, observationJSON, alertID); err != nil {
			return fmt.Errorf("auto-resolve alert: %w", err)
		}
		return s.appendEvent(ctx, tx, alertID, ev.TenantID, "resolved", "system", nil, map[string]interface{}{
			"resolution": "auto", "observation": ev.Observation,
		})
	})
	if err != nil || alertID == uuid.Nil {
		return err
	}
	s.publishAlertNotification(ev.TenantID, source, ev.AlertType, "info",
		fmt.Sprintf("Resolved: %s", title),
		"The condition cleared and the alert auto-resolved.", alertID, "resolved", ev.Observation)
	return nil
}

// --- user lifecycle actions ---------------------------------------------------

// Acknowledge marks the alert acknowledged by userID.
func (s *AlertEngineService) Acknowledge(ctx context.Context, tenantID, alertID, userID uuid.UUID) (*models.Alert, error) {
	return s.userTransition(ctx, tenantID, alertID, userID, "acknowledge", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE alerts SET status = 'acknowledged', acknowledged_by = $1, acknowledged_at = NOW(),
			       snoozed_by = NULL, snoozed_until = NULL, snooze_reason = NULL,
			       last_event_at = NOW(), updated_at = NOW()
			WHERE id = $2
		`, userID, alertID)
		return err
	}, "acknowledged", nil)
}

// Snooze pauses escalation/re-notification until `until`.
func (s *AlertEngineService) Snooze(ctx context.Context, tenantID, alertID, userID uuid.UUID, until time.Time, reason string) (*models.Alert, error) {
	if !until.After(time.Now()) {
		return nil, fmt.Errorf("snooze until must be in the future")
	}
	details := map[string]interface{}{"until": until.Format(time.RFC3339)}
	if reason != "" {
		details["reason"] = reason
	}
	return s.userTransition(ctx, tenantID, alertID, userID, "snooze", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE alerts SET status = 'snoozed', snoozed_by = $1, snoozed_until = $2, snooze_reason = NULLIF($3,''),
			       last_event_at = NOW(), updated_at = NOW()
			WHERE id = $4
		`, userID, until, reason, alertID)
		return err
	}, "snoozed", details)
}

// Unsnooze returns a snoozed alert to active.
func (s *AlertEngineService) Unsnooze(ctx context.Context, tenantID, alertID, userID uuid.UUID) (*models.Alert, error) {
	return s.userTransition(ctx, tenantID, alertID, userID, "unsnooze", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE alerts SET status = 'active', snoozed_by = NULL, snoozed_until = NULL, snooze_reason = NULL,
			       last_event_at = NOW(), updated_at = NOW()
			WHERE id = $1
		`, alertID)
		return err
	}, "unsnoozed", nil)
}

// ResolveManual resolves the alert by a user with an optional note.
func (s *AlertEngineService) ResolveManual(ctx context.Context, tenantID, alertID, userID uuid.UUID, note string) (*models.Alert, error) {
	details := map[string]interface{}{"resolution": "manual"}
	if note != "" {
		details["note"] = note
	}
	return s.userTransition(ctx, tenantID, alertID, userID, "resolve", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE alerts SET status = 'resolved', resolution = 'manual', resolved_by = $1, resolved_at = NOW(),
			       resolution_note = NULLIF($2,''), last_event_at = NOW(), updated_at = NOW()
			WHERE id = $3
		`, userID, note, alertID)
		return err
	}, "resolved", details)
}

// userTransition wraps the shared load → validate → mutate → append-event flow.
func (s *AlertEngineService) userTransition(ctx context.Context, tenantID, alertID, userID uuid.UUID,
	action string, mutate func(tx *sql.Tx) error, eventType string, details map[string]interface{}) (*models.Alert, error) {

	var out *models.Alert
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		var current string
		row := tx.QueryRowContext(ctx, `SELECT status FROM alerts WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, alertID, tenantID)
		if scanErr := row.Scan(&current); scanErr == sql.ErrNoRows {
			return ErrAlertNotFound
		} else if scanErr != nil {
			return scanErr
		}
		if _, tErr := transitionFor(current, action); tErr != nil {
			return tErr
		}
		if err := mutate(tx); err != nil {
			return fmt.Errorf("%s alert: %w", action, err)
		}
		if err := s.appendEvent(ctx, tx, alertID, tenantID, eventType, "user", &userID, details); err != nil {
			return err
		}
		loaded, lErr := s.loadAlertTx(ctx, tx, alertID)
		out = loaded
		return lErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- ticket bridge -------------------------------------------------------------

// CreateTicketFromAlert creates a unified ticket carrying the alert's full
// evidence timeline and links the two. Resolving the ticket does NOT resolve
// the alert — the alert closes only when the condition is observed clear or a
// user resolves it explicitly.
func (s *AlertEngineService) CreateTicketFromAlert(ctx context.Context, tenantID, alertID, userID uuid.UUID) (*models.Ticket, error) {
	alert, evts, err := s.Get(ctx, tenantID, alertID)
	if err != nil {
		return nil, err
	}
	if alert.TicketID != nil {
		return nil, fmt.Errorf("alert already has a linked ticket")
	}

	category := "operational"
	var certificateID *string
	if alert.SubjectType != nil && *alert.SubjectType == "certificate" && alert.SubjectID != nil {
		category = "certificate"
		idStr := alert.SubjectID.String()
		certificateID = &idStr
	}
	ticketSeverity := alert.Severity
	if ticketSeverity == "info" {
		ticketSeverity = "low"
	}

	description := ""
	if alert.Message != nil {
		description = *alert.Message + "\n\n"
	}
	description += "--- Alert evidence timeline (alert " + alert.ID.String() + ") ---\n" + formatAlertTimeline(evts)

	input := models.CreateTicketInput{
		Category:      category,
		Title:         alert.Title,
		Description:   &description,
		Priority:      ticketSeverity,
		Severity:      &ticketSeverity,
		CertificateID: certificateID,
	}
	ticket, err := s.ticketSvc.Create(tenantID, userID, input)
	if err != nil {
		return nil, fmt.Errorf("create ticket from alert: %w", err)
	}

	err = shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		if _, uErr := tx.ExecContext(ctx, `UPDATE tickets SET alert_id = $1 WHERE id = $2 AND tenant_id = $3`,
			alertID, ticket.ID, tenantID); uErr != nil {
			return uErr
		}
		if _, uErr := tx.ExecContext(ctx, `UPDATE alerts SET ticket_id = $1, last_event_at = NOW(), updated_at = NOW() WHERE id = $2`,
			ticket.ID, alertID); uErr != nil {
			return uErr
		}
		return s.appendEvent(ctx, tx, alertID, tenantID, "ticket_linked", "user", &userID, map[string]interface{}{
			"ticket_id": ticket.ID.String(),
		})
	})
	if err != nil {
		return nil, fmt.Errorf("link ticket to alert: %w", err)
	}
	return ticket, nil
}

// formatAlertTimeline renders the evidence chain as readable ticket text so
// the ticket inherits the full pre-conversion history (who/what/when).
func formatAlertTimeline(evts []models.AlertEvent) string {
	out := ""
	for _, e := range evts {
		line := e.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC") + "  " + e.EventType
		if e.ActorType == "user" && e.ActorID != nil {
			line += " by user " + e.ActorID.String()
		} else {
			line += " (system)"
		}
		if len(e.Details) > 0 {
			if b, err := json.Marshal(e.Details); err == nil {
				line += " " + string(b)
			}
		}
		out += line + "\n"
	}
	return out
}

// --- queries --------------------------------------------------------------------

const alertColumns = `id, tenant_id, alert_type, source, subject_type, subject_id, subject_label,
	severity, status, title, message, metadata, acknowledged_by, acknowledged_at,
	snoozed_by, snoozed_until, snooze_reason, resolved_at, resolved_by, resolution,
	resolution_note, resolution_observation, ticket_id, first_raised_at, last_event_at,
	created_at, updated_at`

// List returns filtered alerts, most recent activity first.
func (s *AlertEngineService) List(ctx context.Context, tenantID uuid.UUID, f models.AlertFilters) ([]models.Alert, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	query := `SELECT ` + alertColumns + ` FROM alerts WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	i := 2
	if f.Status != "" && f.Status != "all" {
		query += fmt.Sprintf(" AND status = $%d", i)
		args = append(args, f.Status)
		i++
	}
	if f.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", i)
		args = append(args, f.Severity)
		i++
	}
	if f.AlertType != "" {
		query += fmt.Sprintf(" AND alert_type = $%d", i)
		args = append(args, f.AlertType)
		i++
	}
	query += fmt.Sprintf(" ORDER BY last_event_at DESC LIMIT $%d", i)
	args = append(args, limit)

	alerts := []models.Alert{}
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, args...)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			a, sErr := scanAlert(rows)
			if sErr != nil {
				return sErr
			}
			alerts = append(alerts, *a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return alerts, nil
}

// Stats returns the summary counts for the Alerts page cards.
func (s *AlertEngineService) Stats(ctx context.Context, tenantID uuid.UUID) (*models.AlertStats, error) {
	stats := &models.AlertStats{}
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT
			  COUNT(*) FILTER (WHERE status = 'active'),
			  COUNT(*) FILTER (WHERE status = 'acknowledged'),
			  COUNT(*) FILTER (WHERE status = 'snoozed'),
			  COUNT(*) FILTER (WHERE status = 'resolved'),
			  COUNT(*) FILTER (WHERE status <> 'resolved' AND severity = 'critical'),
			  COUNT(*) FILTER (WHERE status <> 'resolved' AND severity = 'high')
			FROM alerts WHERE tenant_id = $1
		`, tenantID).Scan(&stats.Active, &stats.Acknowledged, &stats.Snoozed, &stats.Resolved, &stats.Critical, &stats.High)
	})
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// Get returns one alert with its full evidence chain (oldest event first).
func (s *AlertEngineService) Get(ctx context.Context, tenantID, alertID uuid.UUID) (*models.Alert, []models.AlertEvent, error) {
	var alert *models.Alert
	evts := []models.AlertEvent{}
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		loaded, lErr := s.loadAlertTx(ctx, tx, alertID)
		if lErr != nil {
			return lErr
		}
		alert = loaded
		rows, qErr := tx.QueryContext(ctx, `
			SELECT id, alert_id, tenant_id, event_type, actor_type, actor_id, details, created_at
			FROM alert_events WHERE alert_id = $1 ORDER BY created_at ASC, id ASC
		`, alertID)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var e models.AlertEvent
			var details []byte
			if err := rows.Scan(&e.ID, &e.AlertID, &e.TenantID, &e.EventType, &e.ActorType, &e.ActorID, &details, &e.CreatedAt); err != nil {
				return err
			}
			if len(details) > 0 {
				_ = json.Unmarshal(details, &e.Details)
			}
			evts = append(evts, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, err
	}
	return alert, evts, nil
}

func (s *AlertEngineService) loadAlertTx(ctx context.Context, tx *sql.Tx, alertID uuid.UUID) (*models.Alert, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+alertColumns+` FROM alerts WHERE id = $1`, alertID)
	a, err := scanAlert(row)
	if err == sql.ErrNoRows {
		return nil, ErrAlertNotFound
	}
	return a, err
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanAlert(row rowScanner) (*models.Alert, error) {
	var a models.Alert
	var metadata, observation []byte
	err := row.Scan(&a.ID, &a.TenantID, &a.AlertType, &a.Source, &a.SubjectType, &a.SubjectID, &a.SubjectLabel,
		&a.Severity, &a.Status, &a.Title, &a.Message, &metadata, &a.AcknowledgedBy, &a.AcknowledgedAt,
		&a.SnoozedBy, &a.SnoozedUntil, &a.SnoozeReason, &a.ResolvedAt, &a.ResolvedBy, &a.Resolution,
		&a.ResolutionNote, &observation, &a.TicketID, &a.FirstRaisedAt, &a.LastEventAt,
		&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &a.Metadata)
	}
	if len(observation) > 0 {
		_ = json.Unmarshal(observation, &a.ResolutionObservation)
	}
	return &a, nil
}

// appendEvent writes one evidence-chain entry. Append-only by convention:
// nothing in this service (or anywhere) updates or deletes alert_events rows.
// When the alert is linked to a ticket, the event is also echoed onto the
// ticket as a comment (: the ticket keeps receiving post-conversion
// evidence — e.g. the auto-resolve observation lands on the ticket too).
// System echoes carry a NULL author (rendered as "System").
func (s *AlertEngineService) appendEvent(ctx context.Context, tx *sql.Tx, alertID, tenantID uuid.UUID,
	eventType, actorType string, actorID *uuid.UUID, details map[string]interface{}) error {
	detailsJSON, _ := json.Marshal(details)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO alert_events (alert_id, tenant_id, event_type, actor_type, actor_id, details)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, alertID, tenantID, eventType, actorType, actorID, detailsJSON); err != nil {
		return fmt.Errorf("append alert event: %w", err)
	}
	// Echo onto the linked ticket, if any. Same transaction — a no-op single
	// statement when the alert has no ticket_id.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ticket_comments (ticket_id, author_id, content)
		SELECT a.ticket_id, $2, $3 FROM alerts a
		WHERE a.id = $1 AND a.ticket_id IS NOT NULL
	`, alertID, actorID, alertEventComment(eventType, details)); err != nil {
		return fmt.Errorf("echo alert event to ticket: %w", err)
	}
	return nil
}

// alertEventComment renders one evidence event as human-readable ticket
// comment text.
func alertEventComment(eventType string, details map[string]interface{}) string {
	str := func(key string) string {
		if v, ok := details[key].(string); ok {
			return v
		}
		return ""
	}
	switch eventType {
	case "severity_changed":
		return fmt.Sprintf("[Alert] Severity changed: %s → %s", str("from"), str("to"))
	case "acknowledged":
		return "[Alert] Acknowledged"
	case "snoozed":
		msg := "[Alert] Snoozed"
		if until := str("until"); until != "" {
			msg += " until " + until
		}
		if reason := str("reason"); reason != "" {
			msg += " (reason: " + reason + ")"
		}
		return msg
	case "unsnoozed":
		if str("reason") == "snooze expired" {
			return "[Alert] Snooze expired — alert active again"
		}
		return "[Alert] Unsnoozed"
	case "resolved":
		if obs, ok := details["observation"]; ok && obs != nil {
			obsJSON, _ := json.Marshal(obs)
			return "[Alert] Auto-resolved — condition observed clear: " + string(obsJSON)
		}
		msg := "[Alert] Resolved"
		if note := str("note"); note != "" {
			msg += " (note: " + note + ")"
		}
		return msg
	case "ticket_linked":
		return "[Alert] Ticket created from alert — the evidence timeline up to this point is in the ticket description; subsequent alert events are appended here as comments."
	default:
		detailsJSON, _ := json.Marshal(details)
		return fmt.Sprintf("[Alert] %s %s", eventType, string(detailsJSON))
	}
}

// --- notification fan-out ------------------------------------------------------

func (s *AlertEngineService) publishAlertNotification(tenantID uuid.UUID, source, alertType, severity, title, message string,
	alertID uuid.UUID, transition string, metadata map[string]interface{}) {
	if s.natsClient == nil {
		return
	}
	md := map[string]interface{}{
		"alert_id":         alertID.String(),
		"alert_transition": transition,
	}
	for k, v := range metadata {
		if _, exists := md[k]; !exists {
			md[k] = v
		}
	}
	notif := events.NotificationEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertSource: source,
		AlertType:   alertType,
		Severity:    severity,
		Title:       title,
		Message:     message,
		Timestamp:   time.Now(),
		Metadata:    md,
	}
	if err := events.PublishJSON(s.natsClient, events.SubjectNotificationsSend, notif); err != nil {
		log.Printf("[AlertEngine] Failed to publish notification (non-fatal): %v", err)
	}
}

// --- snooze expiry sweeper -------------------------------------------------------

// StartSnoozeExpirySweeper wakes snoozed alerts whose snoozed_until has
// passed, appending a system 'unsnoozed' event for the evidence chain.
// Cross-tenant sweep — bypass role, mirroring the ticket due-date checker.
func (s *AlertEngineService) StartSnoozeExpirySweeper(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.sweepExpiredSnoozes()
			}
		}
	}()
}

// Stop terminates background goroutines.
func (s *AlertEngineService) Stop() { close(s.stop) }

func (s *AlertEngineService) sweepExpiredSnoozes() {
	rows, err := s.bypassDB.Query(`
		SELECT id, tenant_id FROM alerts
		WHERE status = 'snoozed' AND snoozed_until IS NOT NULL AND snoozed_until <= NOW()
	`)
	if err != nil {
		log.Printf("[AlertEngine] Snooze sweep query failed: %v", err)
		return
	}
	type pair struct{ id, tenant uuid.UUID }
	var expired []pair
	for rows.Next() {
		var p pair
		if scanErr := rows.Scan(&p.id, &p.tenant); scanErr == nil {
			expired = append(expired, p)
		}
	}
	_ = rows.Close()

	for _, p := range expired {
		err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, p.tenant, func(tx *sql.Tx) error {
			res, uErr := tx.ExecContext(context.Background(), `
				UPDATE alerts SET status = 'active', snoozed_by = NULL, snoozed_until = NULL, snooze_reason = NULL,
				       last_event_at = NOW(), updated_at = NOW()
				WHERE id = $1 AND status = 'snoozed'
			`, p.id)
			if uErr != nil {
				return uErr
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return nil // raced with a user action; nothing to record
			}
			return s.appendEvent(context.Background(), tx, p.id, p.tenant, "unsnoozed", "system", nil, map[string]interface{}{
				"reason": "snooze expired",
			})
		})
		if err != nil {
			log.Printf("[AlertEngine] Failed to wake snoozed alert %s: %v", p.id, err)
		}
	}
}
