package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// AlertingService handles alert threshold configuration and alert triggering
type AlertingService struct {
	db *sql.DB
}

// NewAlertingService creates a new alerting service
func NewAlertingService(db *sql.DB) *AlertingService {
	return &AlertingService{
		db: db,
	}
}

// GetAlertThresholds retrieves all alert thresholds (with optional filtering)
func (s *AlertingService) GetAlertThresholds(serviceName *string, enabled *bool) ([]models.AlertThreshold, error) {
	baseQuery := `
		SELECT
			id, threshold_name, metric_type, service_name,
			warning_threshold, critical_threshold, severity, enabled,
			notify_email, notify_slack, notify_webhook, notify_in_app,
			comparison_operator, duration_minutes, description,
			created_by, created_at, updated_at, updated_by
		FROM monitoring_alert_thresholds
	`
	wb := shareddatabase.NewWhereBuilder()

	if serviceName != nil {
		wb.Add("(service_name = %s OR service_name IS NULL)", *serviceName)
	}
	if enabled != nil {
		wb.Add("enabled = %s", *enabled)
	}

	whereClause, args := wb.Build()
	query := baseQuery + whereClause + " ORDER BY threshold_name ASC" //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query alert thresholds: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var thresholds []models.AlertThreshold
	for rows.Next() {
		var threshold models.AlertThreshold
		var warningThreshold, criticalThreshold sql.NullFloat64
		var serviceName, description sql.NullString
		var createdBy, updatedBy sql.NullString
		var createdByUUID, updatedByUUID *uuid.UUID

		err := rows.Scan(
			&threshold.ID,
			&threshold.ThresholdName,
			&threshold.MetricType,
			&serviceName,
			&warningThreshold,
			&criticalThreshold,
			&threshold.Severity,
			&threshold.Enabled,
			&threshold.NotifyEmail,
			&threshold.NotifySlack,
			&threshold.NotifyWebhook,
			&threshold.NotifyInApp,
			&threshold.ComparisonOperator,
			&threshold.DurationMinutes,
			&description,
			&createdBy,
			&threshold.CreatedAt,
			&threshold.UpdatedAt,
			&updatedBy,
		)
		if err != nil {
			continue
		}

		if serviceName.Valid {
			threshold.ServiceName = &serviceName.String
		}
		if warningThreshold.Valid {
			threshold.WarningThreshold = &warningThreshold.Float64
		}
		if criticalThreshold.Valid {
			threshold.CriticalThreshold = &criticalThreshold.Float64
		}
		if description.Valid {
			threshold.Description = &description.String
		}
		if createdBy.Valid {
			if uuid, err := uuid.Parse(createdBy.String); err == nil {
				createdByUUID = &uuid
			}
			threshold.CreatedBy = createdByUUID
		}
		if updatedBy.Valid {
			if uuid, err := uuid.Parse(updatedBy.String); err == nil {
				updatedByUUID = &uuid
			}
			threshold.UpdatedBy = updatedByUUID
		}

		thresholds = append(thresholds, threshold)
	}

	return thresholds, nil
}

// GetAlertThreshold retrieves a single alert threshold by ID
func (s *AlertingService) GetAlertThreshold(id uuid.UUID) (*models.AlertThreshold, error) {
	query := `
		SELECT 
			id, threshold_name, metric_type, service_name,
			warning_threshold, critical_threshold, severity, enabled,
			notify_email, notify_slack, notify_webhook, notify_in_app,
			comparison_operator, duration_minutes, description,
			created_by, created_at, updated_at, updated_by
		FROM monitoring_alert_thresholds
		WHERE id = $1
	`

	var threshold models.AlertThreshold
	var warningThreshold, criticalThreshold sql.NullFloat64
	var serviceName, description sql.NullString
	var createdBy, updatedBy sql.NullString
	var createdByUUID, updatedByUUID *uuid.UUID

	err := s.db.QueryRow(query, id).Scan(
		&threshold.ID,
		&threshold.ThresholdName,
		&threshold.MetricType,
		&serviceName,
		&warningThreshold,
		&criticalThreshold,
		&threshold.Severity,
		&threshold.Enabled,
		&threshold.NotifyEmail,
		&threshold.NotifySlack,
		&threshold.NotifyWebhook,
		&threshold.NotifyInApp,
		&threshold.ComparisonOperator,
		&threshold.DurationMinutes,
		&description,
		&createdBy,
		&threshold.CreatedAt,
		&threshold.UpdatedAt,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("alert threshold not found")
		}
		return nil, fmt.Errorf("failed to query alert threshold: %w", err)
	}

	if serviceName.Valid {
		threshold.ServiceName = &serviceName.String
	}
	if warningThreshold.Valid {
		threshold.WarningThreshold = &warningThreshold.Float64
	}
	if criticalThreshold.Valid {
		threshold.CriticalThreshold = &criticalThreshold.Float64
	}
	if description.Valid {
		threshold.Description = &description.String
	}
	if createdBy.Valid {
		if uuid, err := uuid.Parse(createdBy.String); err == nil {
			createdByUUID = &uuid
		}
		threshold.CreatedBy = createdByUUID
	}
	if updatedBy.Valid {
		if uuid, err := uuid.Parse(updatedBy.String); err == nil {
			updatedByUUID = &uuid
		}
		threshold.UpdatedBy = updatedByUUID
	}

	return &threshold, nil
}

// CreateAlertThreshold creates a new alert threshold
func (s *AlertingService) CreateAlertThreshold(req *models.CreateAlertThresholdRequest, createdBy *uuid.UUID) (*models.AlertThreshold, error) {
	threshold := &models.AlertThreshold{
		ID:                 uuid.New(),
		ThresholdName:      req.ThresholdName,
		MetricType:         req.MetricType,
		ServiceName:        req.ServiceName,
		WarningThreshold:   req.WarningThreshold,
		CriticalThreshold:  req.CriticalThreshold,
		Severity:           req.Severity,
		Enabled:            req.Enabled,
		NotifyEmail:        req.NotifyEmail,
		NotifySlack:        req.NotifySlack,
		NotifyWebhook:      req.NotifyWebhook,
		NotifyInApp:        req.NotifyInApp,
		ComparisonOperator: req.ComparisonOperator,
		DurationMinutes:    req.DurationMinutes,
		CreatedBy:          createdBy,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		UpdatedBy:          createdBy,
	}

	if req.Description != "" {
		threshold.Description = &req.Description
	}

	if threshold.Severity == "" {
		threshold.Severity = "medium"
	}
	if threshold.ComparisonOperator == "" {
		threshold.ComparisonOperator = "gt"
	}
	if threshold.DurationMinutes == 0 {
		threshold.DurationMinutes = 5
	}

	query := `
		INSERT INTO monitoring_alert_thresholds (
			id, threshold_name, metric_type, service_name,
			warning_threshold, critical_threshold, severity, enabled,
			notify_email, notify_slack, notify_webhook, notify_in_app,
			comparison_operator, duration_minutes, description,
			created_by, created_at, updated_at, updated_by
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
	`

	_, err := s.db.Exec(query,
		threshold.ID,
		threshold.ThresholdName,
		threshold.MetricType,
		threshold.ServiceName,
		threshold.WarningThreshold,
		threshold.CriticalThreshold,
		threshold.Severity,
		threshold.Enabled,
		threshold.NotifyEmail,
		threshold.NotifySlack,
		threshold.NotifyWebhook,
		threshold.NotifyInApp,
		threshold.ComparisonOperator,
		threshold.DurationMinutes,
		threshold.Description,
		threshold.CreatedBy,
		threshold.CreatedAt,
		threshold.UpdatedAt,
		threshold.UpdatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create alert threshold: %w", err)
	}

	return threshold, nil
}

// UpdateAlertThreshold updates an existing alert threshold
func (s *AlertingService) UpdateAlertThreshold(id uuid.UUID, req *models.UpdateAlertThresholdRequest, updatedBy *uuid.UUID) (*models.AlertThreshold, error) {
	// Build update query dynamically
	query := "UPDATE monitoring_alert_thresholds SET updated_at = NOW(), updated_by = $1"
	args := []interface{}{updatedBy}
	argIndex := 2

	if req.WarningThreshold != nil {
		query += fmt.Sprintf(", warning_threshold = $%d", argIndex)
		args = append(args, *req.WarningThreshold)
		argIndex++
	}
	if req.CriticalThreshold != nil {
		query += fmt.Sprintf(", critical_threshold = $%d", argIndex)
		args = append(args, *req.CriticalThreshold)
		argIndex++
	}
	if req.Severity != nil {
		query += fmt.Sprintf(", severity = $%d", argIndex)
		args = append(args, *req.Severity)
		argIndex++
	}
	if req.Enabled != nil {
		query += fmt.Sprintf(", enabled = $%d", argIndex)
		args = append(args, *req.Enabled)
		argIndex++
	}
	if req.NotifyEmail != nil {
		query += fmt.Sprintf(", notify_email = $%d", argIndex)
		args = append(args, *req.NotifyEmail)
		argIndex++
	}
	if req.NotifySlack != nil {
		query += fmt.Sprintf(", notify_slack = $%d", argIndex)
		args = append(args, *req.NotifySlack)
		argIndex++
	}
	if req.NotifyWebhook != nil {
		query += fmt.Sprintf(", notify_webhook = $%d", argIndex)
		args = append(args, *req.NotifyWebhook)
		argIndex++
	}
	if req.NotifyInApp != nil {
		query += fmt.Sprintf(", notify_in_app = $%d", argIndex)
		args = append(args, *req.NotifyInApp)
		argIndex++
	}
	if req.ComparisonOperator != nil {
		query += fmt.Sprintf(", comparison_operator = $%d", argIndex)
		args = append(args, *req.ComparisonOperator)
		argIndex++
	}
	if req.DurationMinutes != nil {
		query += fmt.Sprintf(", duration_minutes = $%d", argIndex)
		args = append(args, *req.DurationMinutes)
		argIndex++
	}
	if req.Description != nil {
		query += fmt.Sprintf(", description = $%d", argIndex)
		args = append(args, *req.Description)
		argIndex++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argIndex) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	args = append(args, id)

	result, err := s.db.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update alert threshold: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return nil, fmt.Errorf("alert threshold not found")
	}

	return s.GetAlertThreshold(id)
}

// DeleteAlertThreshold deletes an alert threshold
func (s *AlertingService) DeleteAlertThreshold(id uuid.UUID) error {
	query := `DELETE FROM monitoring_alert_thresholds WHERE id = $1`
	result, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete alert threshold: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("alert threshold not found")
	}

	return nil
}

// GetAlertHistory retrieves alert history with optional filtering
func (s *AlertingService) GetAlertHistory(serviceName *string, status *string, limit int, offset int) ([]models.AlertHistory, int, error) {
	// Count query
	countQuery := `SELECT COUNT(*) FROM monitoring_alert_history WHERE 1=1`
	countArgs := []interface{}{}

	if serviceName != nil {
		countQuery += " AND (service_name = $1 OR service_name IS NULL)"
		countArgs = append(countArgs, *serviceName)
	}
	if status != nil {
		argIndex := len(countArgs) + 1
		countQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		countArgs = append(countArgs, *status)
	}

	var totalCount int
	if err := s.db.QueryRow(countQuery, countArgs...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed to count alert history: %w", err)
	}

	// Data query
	query := `
		SELECT 
			id, threshold_id, threshold_name, metric_type, service_name,
			threshold_value, actual_value, severity, status,
			acknowledged_by, acknowledged_at, resolved_at,
			notifications_sent, message, metadata, triggered_at
		FROM monitoring_alert_history
		WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1

	if serviceName != nil {
		query += fmt.Sprintf(" AND (service_name = $%d OR service_name IS NULL)", argIndex)
		args = append(args, *serviceName)
		argIndex++
	}
	if status != nil {
		query += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, *status)
		argIndex++
	}

	query += " ORDER BY triggered_at DESC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query alert history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var alerts []models.AlertHistory
	for rows.Next() {
		var alert models.AlertHistory
		var thresholdID sql.NullString
		var serviceName sql.NullString
		var acknowledgedBy sql.NullString
		var acknowledgedAt, resolvedAt sql.NullTime
		var message sql.NullString
		var notificationsSentJSON []byte
		var metadataJSON []byte

		err := rows.Scan(
			&alert.ID,
			&thresholdID,
			&alert.ThresholdName,
			&alert.MetricType,
			&serviceName,
			&alert.ThresholdValue,
			&alert.ActualValue,
			&alert.Severity,
			&alert.Status,
			&acknowledgedBy,
			&acknowledgedAt,
			&resolvedAt,
			&notificationsSentJSON,
			&message,
			&metadataJSON,
			&alert.TriggeredAt,
		)
		if err != nil {
			continue
		}

		if thresholdID.Valid {
			if uuid, err := uuid.Parse(thresholdID.String); err == nil {
				alert.ThresholdID = &uuid
			}
		}
		if serviceName.Valid {
			alert.ServiceName = &serviceName.String
		}
		if acknowledgedBy.Valid {
			if uuid, err := uuid.Parse(acknowledgedBy.String); err == nil {
				alert.AcknowledgedBy = &uuid
			}
		}
		if acknowledgedAt.Valid {
			alert.AcknowledgedAt = &acknowledgedAt.Time
		}
		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}
		if message.Valid {
			alert.Message = &message.String
		}

		// Parse JSONB fields
		if len(notificationsSentJSON) > 0 {
			if err := json.Unmarshal(notificationsSentJSON, &alert.NotificationsSent); err != nil {
				alert.NotificationsSent = []map[string]interface{}{}
			}
		} else {
			alert.NotificationsSent = []map[string]interface{}{}
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
				alert.Metadata = make(map[string]interface{})
			}
		} else {
			alert.Metadata = make(map[string]interface{})
		}

		alerts = append(alerts, alert)
	}

	return alerts, totalCount, nil
}

// --- Stateful alert lifecycle -----------------------------------------------
//
// The alert evaluator used to build a models.AlertHistory, log it, fire a
// notification and then throw the struct away — the code carried the comment
// "Save alert to database (this would need to be added to AlertingService) / For
// now, log it". Because nothing was ever written, the evaluator's own
// "already triggered recently?" guard queried an always-empty table and could
// never suppress anything, so a single breached threshold re-notified on every
// evaluation cycle, forever, and never resolved. These three methods are
// the missing persistence layer; monitoring_alert_history already had the
// columns (status / resolved_at) for it.

// RecordAlert persists a newly triggered alert as 'active'.
func (s *AlertingService) RecordAlert(alert *models.AlertHistory) error {
	if alert.ID == uuid.Nil {
		alert.ID = uuid.New()
	}
	if alert.TriggeredAt.IsZero() {
		alert.TriggeredAt = time.Now()
	}
	if alert.Status == "" {
		alert.Status = "active"
	}

	metadataJSON, err := json.Marshal(alert.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal alert metadata: %w", err)
	}
	notificationsJSON, err := json.Marshal(alert.NotificationsSent)
	if err != nil {
		return fmt.Errorf("failed to marshal alert notifications: %w", err)
	}
	if alert.NotificationsSent == nil {
		notificationsJSON = []byte("[]")
	}

	// Platform-scoped table (no tenant_id column): the owner connection is
	// correct here, same as every other read/write in this service.
	_, err = s.db.Exec(`
		INSERT INTO monitoring_alert_history (
			id, threshold_id, threshold_name, metric_type, service_name,
			threshold_value, actual_value, severity, status,
			notifications_sent, message, metadata, triggered_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		alert.ID, alert.ThresholdID, alert.ThresholdName, alert.MetricType, alert.ServiceName,
		alert.ThresholdValue, alert.ActualValue, alert.Severity, alert.Status,
		notificationsJSON, alert.Message, metadataJSON, alert.TriggeredAt,
	)
	if err != nil {
		return fmt.Errorf("failed to record alert: %w", err)
	}
	return nil
}

// GetActiveAlertForThreshold returns the open alert for a threshold, or nil.
//
// Keyed on threshold_id rather than "the newest active alert for this service"
// (what the evaluator used to ask for): a service can have several thresholds,
// and asking for the newest one across all of them meant a busy threshold could
// suppress a quiet one and vice versa. 'acknowledged' counts as open — an
// operator who has seen the alert should not be re-notified either.
func (s *AlertingService) GetActiveAlertForThreshold(thresholdID uuid.UUID) (*models.AlertHistory, error) {
	var alert models.AlertHistory
	var serviceName, message sql.NullString
	var metadataJSON []byte

	err := s.db.QueryRow(`
		SELECT id, threshold_id, threshold_name, metric_type, service_name,
			threshold_value, actual_value, severity, status, message, metadata, triggered_at
		FROM monitoring_alert_history
		WHERE threshold_id = $1 AND status IN ('active', 'acknowledged')
		ORDER BY triggered_at DESC
		LIMIT 1`, thresholdID,
	).Scan(
		&alert.ID, &alert.ThresholdID, &alert.ThresholdName, &alert.MetricType, &serviceName,
		&alert.ThresholdValue, &alert.ActualValue, &alert.Severity, &alert.Status,
		&message, &metadataJSON, &alert.TriggeredAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up active alert: %w", err)
	}

	if serviceName.Valid {
		alert.ServiceName = &serviceName.String
	}
	if message.Valid {
		alert.Message = &message.String
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
			alert.Metadata = map[string]interface{}{}
		}
	}
	return &alert, nil
}

// ResolveAlertsForThreshold closes every open alert for a threshold, recording
// the value that cleared it. Returns how many rows it closed. This is the half
// that makes an alert a state rather than an event stream: without it an alert
// stays 'active' after the metric recovers and the next breach is indefinitely
// suppressed by the de-duplication guard.
func (s *AlertingService) ResolveAlertsForThreshold(thresholdID uuid.UUID, observedValue float64) (int64, error) {
	// observedValue is bound twice, as $2 (numeric) and $3 (text). Reusing a
	// single placeholder in both positions makes Postgres try to deduce one type
	// for both and fail with "inconsistent types deduced for parameter $2".
	res, err := s.db.Exec(`
		UPDATE monitoring_alert_history
		SET status = 'resolved',
		    resolved_at = NOW(),
		    actual_value = $2,
		    metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('resolved_value', $3::text)
		WHERE threshold_id = $1 AND status IN ('active', 'acknowledged')`,
		thresholdID, observedValue, fmt.Sprintf("%v", observedValue),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve alerts: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
