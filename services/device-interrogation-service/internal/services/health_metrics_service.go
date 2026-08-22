package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// HealthMetricsService handles device and integration health metrics
type HealthMetricsService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
	// cross-tenant platform health summary. Pre-flip it resolves to the same
	// connection as db.
	bypassDB *sql.DB
}

// DeviceHealthMetrics represents health metrics for a device
type DeviceHealthMetrics struct {
	DeviceID                   uuid.UUID  `json:"device_id"`
	ConnectionSuccessCount     int        `json:"connection_success_count"`
	ConnectionFailureCount     int        `json:"connection_failure_count"`
	InterrogationSuccessCount  int        `json:"interrogation_success_count"`
	InterrogationFailureCount  int        `json:"interrogation_failure_count"`
	AverageInterrogationTimeMs int        `json:"average_interrogation_time_ms"`
	LastSuccessfulConnection   *time.Time `json:"last_successful_connection,omitempty"`
	LastFailedConnection       *time.Time `json:"last_failed_connection,omitempty"`
	LastConnectionError        string     `json:"last_connection_error,omitempty"`
}

// IntegrationHealthMetrics represents health metrics for a cloud integration
type IntegrationHealthMetrics struct {
	IntegrationID           uuid.UUID  `json:"integration_id"`
	DiscoverySuccessCount   int        `json:"discovery_success_count"`
	DiscoveryFailureCount   int        `json:"discovery_failure_count"`
	AverageDiscoveryTimeMs  int        `json:"average_discovery_time_ms"`
	LastSuccessfulDiscovery *time.Time `json:"last_successful_discovery,omitempty"`
	LastFailedDiscovery     *time.Time `json:"last_failed_discovery,omitempty"`
	LastDiscoveryError      string     `json:"last_discovery_error,omitempty"`
	ResourceCount           int        `json:"resource_count"`
}

// PlatformHealthSummary represents aggregate health metrics across all tenants
type PlatformHealthSummary struct {
	TotalDevices           int            `json:"total_devices"`
	ConnectedDevices       int            `json:"connected_devices"`
	DisconnectedDevices    int            `json:"disconnected_devices"`
	TotalIntegrations      int            `json:"total_integrations"`
	ActiveIntegrations     int            `json:"active_integrations"`
	ErrorIntegrations      int            `json:"error_integrations"`
	JobsLast24h            int            `json:"jobs_last_24h"`
	SuccessfulJobsLast24h  int            `json:"successful_jobs_last_24h"`
	FailedJobsLast24h      int            `json:"failed_jobs_last_24h"`
	SuccessRate            float64        `json:"success_rate"`
	AverageJobDurationMs   int            `json:"average_job_duration_ms"`
	DevicesByType          map[string]int `json:"devices_by_type"`
	IntegrationsByProvider map[string]int `json:"integrations_by_provider"`
}

// HealthTimelinePoint represents a point in the health timeline
type HealthTimelinePoint struct {
	Timestamp         time.Time `json:"timestamp"`
	SuccessCount      int       `json:"success_count"`
	FailureCount      int       `json:"failure_count"`
	AverageDurationMs int       `json:"average_duration_ms"`
}

// NewHealthMetricsService creates a new health metrics service. db is the
// RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass)
// connection for the cross-tenant platform summary. Pre-flip both handles
// resolve to the same connection.
func NewHealthMetricsService(db, bypassDB *sql.DB) *HealthMetricsService {
	return &HealthMetricsService{db: db, bypassDB: bypassDB}
}

// GetDeviceHealthMetrics retrieves health metrics for a specific device, scoped
// to tenantID (device_jobs is RLS-scoped). tenantID is threaded from the caller.
func (s *HealthMetricsService) GetDeviceHealthMetrics(ctx context.Context, tenantID, deviceID uuid.UUID, hours int) (*DeviceHealthMetrics, error) {
	if hours <= 0 {
		hours = 24
	}

	metrics := &DeviceHealthMetrics{
		DeviceID: deviceID,
	}

	// Query job stats for the device
	query := `
		SELECT 
			COUNT(CASE WHEN status = 'completed' THEN 1 END) as success_count,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failure_count,
			COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)::int, 0) as avg_duration_ms,
			MAX(CASE WHEN status = 'completed' THEN completed_at END) as last_success,
			MAX(CASE WHEN status = 'failed' THEN completed_at END) as last_failure
		FROM device_jobs
		WHERE device_id = $1 
			AND created_at >= NOW() - INTERVAL '%d hours'
			AND job_type = 'device_interrogation'
	`

	errorQuery := `
		SELECT error_message
		FROM device_jobs
		WHERE device_id = $1 AND status = 'failed'
		ORDER BY completed_at DESC
		LIMIT 1
	`
	var lastSuccess, lastFailure sql.NullTime
	var errorMsg sql.NullString
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(ctx, fmt.Sprintf(query, hours), deviceID).Scan(
			&metrics.InterrogationSuccessCount,
			&metrics.InterrogationFailureCount,
			&metrics.AverageInterrogationTimeMs,
			&lastSuccess,
			&lastFailure,
		); e != nil && e != sql.ErrNoRows {
			return fmt.Errorf("failed to query device health metrics: %w", e)
		}
		// Best-effort last error (ignore errors, including no rows).
		_ = tx.QueryRowContext(ctx, errorQuery, deviceID).Scan(&errorMsg)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if lastSuccess.Valid {
		metrics.LastSuccessfulConnection = &lastSuccess.Time
	}
	if lastFailure.Valid {
		metrics.LastFailedConnection = &lastFailure.Time
	}
	if errorMsg.Valid {
		metrics.LastConnectionError = errorMsg.String
	}

	return metrics, nil
}

// GetIntegrationHealthMetrics retrieves health metrics for a cloud integration,
// scoped to tenantID (device_jobs is RLS-scoped).
func (s *HealthMetricsService) GetIntegrationHealthMetrics(ctx context.Context, tenantID, integrationID uuid.UUID, hours int) (*IntegrationHealthMetrics, error) {
	if hours <= 0 {
		hours = 24
	}

	metrics := &IntegrationHealthMetrics{
		IntegrationID: integrationID,
	}

	// Query job stats for the integration
	query := `
		SELECT 
			COUNT(CASE WHEN status = 'completed' THEN 1 END) as success_count,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failure_count,
			COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)::int, 0) as avg_duration_ms,
			MAX(CASE WHEN status = 'completed' THEN completed_at END) as last_success,
			MAX(CASE WHEN status = 'failed' THEN completed_at END) as last_failure
		FROM device_jobs
		WHERE integration_id = $1 
			AND created_at >= NOW() - INTERVAL '%d hours'
			AND job_type = 'cloud_discovery'
	`

	errorQuery := `
		SELECT error_message
		FROM device_jobs
		WHERE integration_id = $1 AND status = 'failed'
		ORDER BY completed_at DESC
		LIMIT 1
	`
	var lastSuccess, lastFailure sql.NullTime
	var errorMsg sql.NullString
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(ctx, fmt.Sprintf(query, hours), integrationID).Scan(
			&metrics.DiscoverySuccessCount,
			&metrics.DiscoveryFailureCount,
			&metrics.AverageDiscoveryTimeMs,
			&lastSuccess,
			&lastFailure,
		); e != nil && e != sql.ErrNoRows {
			return fmt.Errorf("failed to query integration health metrics: %w", e)
		}
		_ = tx.QueryRowContext(ctx, errorQuery, integrationID).Scan(&errorMsg)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if lastSuccess.Valid {
		metrics.LastSuccessfulDiscovery = &lastSuccess.Time
	}
	if lastFailure.Valid {
		metrics.LastFailedDiscovery = &lastFailure.Time
	}
	if errorMsg.Valid {
		metrics.LastDiscoveryError = errorMsg.String
	}

	return metrics, nil
}

// GetPlatformHealthSummary retrieves aggregate health metrics (for admin dashboard).
//
// RLS: cross-tenant aggregate (no tenant filter) → runs on the bypass role.
// Gated by RequirePlatformAdmin in the router.
func (s *HealthMetricsService) GetPlatformHealthSummary(ctx context.Context) (*PlatformHealthSummary, error) {
	summary := &PlatformHealthSummary{
		DevicesByType:          make(map[string]int),
		IntegrationsByProvider: make(map[string]int),
	}

	// Query device counts
	deviceQuery := `
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN connection_status = 'connected' THEN 1 END) as connected,
			COUNT(CASE WHEN connection_status IN ('error', 'disconnected') THEN 1 END) as disconnected
		FROM devices
		WHERE deleted_at IS NULL
	`
	err := s.bypassDB.QueryRowContext(ctx, deviceQuery).Scan(
		&summary.TotalDevices,
		&summary.ConnectedDevices,
		&summary.DisconnectedDevices,
	)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query device counts: %w", err)
	}

	// Query devices by type
	deviceTypeQuery := `
		SELECT device_type, COUNT(*) as count
		FROM devices
		WHERE deleted_at IS NULL
		GROUP BY device_type
	`
	rows, err := s.bypassDB.QueryContext(ctx, deviceTypeQuery)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var deviceType string
			var count int
			if err := rows.Scan(&deviceType, &count); err == nil {
				summary.DevicesByType[deviceType] = count
			}
		}
	}

	// Query integration counts
	integrationQuery := `
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'connected' OR status = 'configured' THEN 1 END) as active,
			COUNT(CASE WHEN status = 'error' THEN 1 END) as error
		FROM platform_integrations
		WHERE deleted_at IS NULL AND provider IN ('aws', 'azure', 'gcp')
	`
	err = s.bypassDB.QueryRowContext(ctx, integrationQuery).Scan(
		&summary.TotalIntegrations,
		&summary.ActiveIntegrations,
		&summary.ErrorIntegrations,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// Non-fatal: the counts stay zero and the rest of the summary is still
		// useful. Logged rather than swallowed so a real query failure is
		// distinguishable from "there genuinely are no integrations".
		log.Printf("health metrics: integration counts query failed, reporting zeros: %v", err)
	}

	// Query integrations by provider
	integrationProviderQuery := `
		SELECT provider, COUNT(*) as count
		FROM platform_integrations
		WHERE deleted_at IS NULL AND provider IN ('aws', 'azure', 'gcp')
		GROUP BY provider
	`
	rows, err = s.bypassDB.QueryContext(ctx, integrationProviderQuery)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var provider string
			var count int
			if err := rows.Scan(&provider, &count); err == nil {
				summary.IntegrationsByProvider[provider] = count
			}
		}
	}

	// Query job stats for last 24 hours
	jobQuery := `
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
			COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)::int, 0) as avg_duration_ms
		FROM device_jobs
		WHERE created_at >= NOW() - INTERVAL '24 hours'
	`
	err = s.bypassDB.QueryRowContext(ctx, jobQuery).Scan(
		&summary.JobsLast24h,
		&summary.SuccessfulJobsLast24h,
		&summary.FailedJobsLast24h,
		&summary.AverageJobDurationMs,
	)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query job stats: %w", err)
	}

	// Calculate success rate
	if summary.JobsLast24h > 0 {
		summary.SuccessRate = float64(summary.SuccessfulJobsLast24h) / float64(summary.JobsLast24h) * 100
	}

	return summary, nil
}

// GetDeviceHealthTimeline retrieves health timeline data for a device, scoped to
// tenantID (device_jobs is RLS-scoped).
func (s *HealthMetricsService) GetDeviceHealthTimeline(ctx context.Context, tenantID, deviceID uuid.UUID, hours int, intervalMinutes int) ([]HealthTimelinePoint, error) {
	if hours <= 0 {
		hours = 24
	}
	// intervalMinutes is accepted from the API but is NOT honoured: the query
	// below buckets with date_trunc('hour', ...), so the timeline is always
	// hourly. The previous `if intervalMinutes <= 0 { intervalMinutes = 60 }`
	// defaulting read as if the value mattered while nothing ever consumed it.
	// Left unused rather than silently defaulted; making the bucket width
	// configurable is a behaviour change, not lint cleanup.
	_ = intervalMinutes

	query := `
		SELECT 
			date_trunc('hour', created_at) as bucket,
			COUNT(CASE WHEN status = 'completed' THEN 1 END) as success_count,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failure_count,
			COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)::int, 0) as avg_duration_ms
		FROM device_jobs
		WHERE device_id = $1 
			AND created_at >= NOW() - INTERVAL '%d hours'
		GROUP BY bucket
		ORDER BY bucket
	`

	var timeline []HealthTimelinePoint
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, fmt.Sprintf(query, hours), deviceID)
		if e != nil {
			return fmt.Errorf("failed to query health timeline: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var point HealthTimelinePoint
			if scanErr := rows.Scan(
				&point.Timestamp,
				&point.SuccessCount,
				&point.FailureCount,
				&point.AverageDurationMs,
			); scanErr != nil {
				continue
			}
			timeline = append(timeline, point)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return timeline, nil
}

// RecordConnectionTest records a connection test result, scoped to tenantID
// (devices is RLS-scoped).
func (s *HealthMetricsService) RecordConnectionTest(ctx context.Context, tenantID, deviceID uuid.UUID, success bool, latencyMs int, errorMsg string) error {
	// Update device connection status
	status := "connected"
	if !success {
		status = "error"
	}

	query := `
		UPDATE devices
		SET connection_status = $1,
			last_interrogated_at = NOW(),
			interrogation_error = $2,
			updated_at = NOW()
		WHERE id = $3 AND tenant_id = $4
	`

	var errPtr *string
	if errorMsg != "" {
		errPtr = &errorMsg
	}

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, status, errPtr, deviceID, tenantID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to record connection test: %w", err)
	}

	return nil
}
