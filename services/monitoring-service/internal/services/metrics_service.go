package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type MetricsService struct {
	config     *config.Config
	db         *sql.DB
	bypassDB   *sql.DB
	httpClient *http.Client
	gatewayURL string
}

func NewMetricsService(cfg *config.Config) *MetricsService {
	// Initialize database connection
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	// Test database connection
	if err := db.Ping(); err != nil {
		panic(fmt.Sprintf("Failed to ping database: %v", err))
	}

	// Initialize the BYPASSRLS connection used by the cross-tenant, platform-wide
	// queries below. Under crypto_app these aggregates would fail closed, so they
	// must run on the crypto_bypass role (BYPASS_DATABASE_URL, falling back to
	// DATABASE_URL when the role split is not yet deployed).
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to bypass database: %v", err))
	}

	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://api-gateway:80" // Default gateway URL
	}

	return &MetricsService{
		config:   cfg,
		db:       db,
		bypassDB: bypassDB,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		gatewayURL: gatewayURL,
	}
}

func (s *MetricsService) GetPlatformMetrics() (models.SystemMetrics, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Platform-wide
	// aggregate across ALL tenants (counts users — an RLS-policied table — with no
	// tenant filter), so it must not be wrapped in WithTenantTx.
	// Query platform-wide metrics
	query := `
		SELECT 
			COUNT(DISTINCT t.id) as total_tenants,
			COUNT(DISTINCT CASE WHEN u.last_login_at > NOW() - INTERVAL '30 days' THEN t.id END) as active_tenants,
			COUNT(DISTINCT u.id) as total_users,
			COUNT(DISTINCT a.id) as total_assets
		FROM tenants t
		LEFT JOIN users u ON t.id = u.tenant_id
		LEFT JOIN assets a ON t.id = a.tenant_id
	`

	var metrics models.SystemMetrics
	err := s.bypassDB.QueryRow(query).Scan(
		&metrics.TotalTenants,
		&metrics.ActiveTenants,
		&metrics.TotalUsers,
		&metrics.TotalAssets,
	)
	if err != nil {
		return metrics, fmt.Errorf("failed to query platform metrics: %w", err)
	}

	return metrics, nil
}

func (s *MetricsService) GetTenantMetrics(tenantID string) (models.SystemMetrics, error) {
	// Query tenant-specific metrics
	query := `
		SELECT
			COUNT(DISTINCT u.id) as total_users,
			COUNT(DISTINCT a.id) as total_assets,
			COUNT(DISTINCT CASE WHEN u.last_login_at > NOW() - INTERVAL '7 days' THEN u.id END) as active_users
		FROM users u
		LEFT JOIN assets a ON u.tenant_id = a.tenant_id
		WHERE u.tenant_id = $1
	`

	// RLS-scoped: `users` carries a users_tenant_isolation policy, and this is a
	// single-tenant read (WHERE u.tenant_id = $1), so it runs inside WithTenantTx
	// (sets app.tenant_id). The explicit WHERE tenant_id is kept as the primary
	// control (belt-and-suspenders). This method takes a string tenantID and no
	// ctx, so we parse it and use context.Background() inside the repo method.
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return models.SystemMetrics{}, fmt.Errorf("invalid tenant id: %w", err)
	}

	var metrics models.SystemMetrics
	err = shareddatabase.WithTenantTx(context.Background(), s.db, tid, func(tx *sql.Tx) error {
		return tx.QueryRow(query, tenantID).Scan(
			&metrics.TotalUsers,
			&metrics.TotalAssets,
			&metrics.ActiveTenants, // Reusing field for active users
		)
	})
	if err != nil {
		return metrics, fmt.Errorf("failed to query tenant metrics: %w", err)
	}

	return metrics, nil
}

// StorePlatformMetricsSnapshot persists a metrics snapshot to the database
func (s *MetricsService) StorePlatformMetricsSnapshot(snapshot *models.PlatformMetricsSnapshot) error {
	// Generate ID if not set
	if snapshot.ID == uuid.Nil {
		snapshot.ID = uuid.New()
	}
	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now()
	}

	query := `
		INSERT INTO platform_metrics_snapshots (
			id, service_name, window_start, window_duration, 
			latency_p50, latency_p95, latency_p99, error_rate, 
			throughput, status, metadata, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	var metadataJSON interface{}
	if snapshot.Metadata != nil {
		metadataBytes, err := json.Marshal(snapshot.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = metadataBytes
	}

	_, err := s.db.Exec(query,
		snapshot.ID,
		snapshot.ServiceName,
		snapshot.WindowStart,
		snapshot.WindowDuration,
		snapshot.LatencyP50,
		snapshot.LatencyP95,
		snapshot.LatencyP99,
		snapshot.ErrorRate,
		snapshot.Throughput,
		snapshot.Status,
		metadataJSON,
		snapshot.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store platform metrics snapshot: %w", err)
	}

	return nil
}

// GetPlatformMetricsSummary returns aggregated platform metrics for a time range
func (s *MetricsService) GetPlatformMetricsSummary(start, end time.Time) (*models.PlatformMetricsSummary, error) {
	// Get metrics for the time range from platform_metrics_snapshots
	query := `
		SELECT 
			service_name,
			status,
			AVG(latency_p50) as avg_latency_p50,
			AVG(latency_p95) as avg_latency_p95,
			AVG(latency_p99) as avg_latency_p99,
			AVG(error_rate) as avg_error_rate,
			SUM(throughput) as total_throughput,
			COUNT(*) as sample_count,
			MAX(created_at) as last_updated
		FROM platform_metrics_snapshots
		WHERE window_start >= $1 AND window_start <= $2
		GROUP BY service_name, status
		ORDER BY service_name
	`

	rows, err := s.db.Query(query, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to query platform metrics: %w", err)
	}
	defer rows.Close()

	summary := &models.PlatformMetricsSummary{
		StartTime:     start,
		EndTime:       end,
		Services:      []models.ServiceMetricsSummary{},
		OverallStatus: "healthy",
		Timestamp:     time.Now(),
	}

	totalServices := 0
	healthyServices := 0
	degradedServices := 0
	downServices := 0
	var totalLatencyP95, totalErrorRate, totalThroughput float64
	var latencyCount, errorCount, throughputCount int

	for rows.Next() {
		var svc models.ServiceMetricsSummary
		var avgLatencyP50, avgLatencyP95, avgLatencyP99, avgErrorRate sql.NullFloat64
		var totalThroughputVal sql.NullFloat64

		err := rows.Scan(
			&svc.ServiceName,
			&svc.Status,
			&avgLatencyP50,
			&avgLatencyP95,
			&avgLatencyP99,
			&avgErrorRate,
			&totalThroughputVal,
			&svc.SampleCount,
			&svc.LastUpdated,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan service metrics: %w", err)
		}

		if avgLatencyP95.Valid {
			svc.LatencyP95 = &avgLatencyP95.Float64
			totalLatencyP95 += avgLatencyP95.Float64
			latencyCount++
		}
		if avgLatencyP50.Valid {
			svc.LatencyP50 = &avgLatencyP50.Float64
		}
		if avgLatencyP99.Valid {
			svc.LatencyP99 = &avgLatencyP99.Float64
		}
		if avgErrorRate.Valid {
			svc.ErrorRate = &avgErrorRate.Float64
			totalErrorRate += avgErrorRate.Float64
			errorCount++
		}
		if totalThroughputVal.Valid {
			svc.Throughput = &totalThroughputVal.Float64
			totalThroughput += totalThroughputVal.Float64
			throughputCount++
		}

		summary.Services = append(summary.Services, svc)
		totalServices++

		switch svc.Status {
		case "healthy":
			healthyServices++
		case "degraded":
			degradedServices++
		case "down":
			downServices++
		}
	}

	summary.TotalServices = totalServices
	summary.HealthyServices = healthyServices
	summary.DegradedServices = degradedServices
	summary.DownServices = downServices

	if latencyCount > 0 {
		summary.AverageLatencyP95 = totalLatencyP95 / float64(latencyCount)
	}
	if errorCount > 0 {
		summary.AverageErrorRate = totalErrorRate / float64(errorCount)
	}
	summary.TotalThroughput = totalThroughput

	// Determine overall status
	if downServices > 0 {
		summary.OverallStatus = "down"
	} else if degradedServices > 0 {
		summary.OverallStatus = "degraded"
	} else {
		summary.OverallStatus = "healthy"
	}

	return summary, nil
}

// GetServiceMetrics returns detailed metrics for a specific service
func (s *MetricsService) GetServiceMetrics(serviceName string, window time.Duration) (*models.ServiceMetrics, error) {
	// Determine window duration in seconds
	var windowDuration int
	var windowStr string
	if window == time.Minute {
		windowDuration = 60
		windowStr = "1m"
	} else if window == time.Hour {
		windowDuration = 3600
		windowStr = "1h"
	} else if window == 24*time.Hour {
		windowDuration = 86400
		windowStr = "1d"
	} else {
		return nil, fmt.Errorf("unsupported window duration: %v", window)
	}

	endTime := time.Now()
	startTime := endTime.Add(-window)

	// Get metrics snapshots for the time window
	query := `
		SELECT 
			id, service_name, window_start, window_duration,
			latency_p50, latency_p95, latency_p99, error_rate,
			throughput, status, metadata, created_at
		FROM platform_metrics_snapshots
		WHERE service_name = $1 
			AND window_duration = $2
			AND window_start >= $3 
			AND window_start <= $4
		ORDER BY window_start DESC
		LIMIT 100
	`

	rows, err := s.db.Query(query, serviceName, windowDuration, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query service metrics: %w", err)
	}
	defer rows.Close()

	metrics := &models.ServiceMetrics{
		ServiceName: serviceName,
		Window:      windowStr,
		StartTime:   startTime,
		EndTime:     endTime,
		Status:      "healthy",
		Trend:       []models.PlatformMetricsSnapshot{},
		LastUpdated: time.Now(),
	}

	for rows.Next() {
		var snapshot models.PlatformMetricsSnapshot
		var latencyP50, latencyP95, latencyP99, errorRate, throughput sql.NullFloat64
		var metadataJSON []byte

		err := rows.Scan(
			&snapshot.ID,
			&snapshot.ServiceName,
			&snapshot.WindowStart,
			&snapshot.WindowDuration,
			&latencyP50,
			&latencyP95,
			&latencyP99,
			&errorRate,
			&throughput,
			&snapshot.Status,
			&metadataJSON,
			&snapshot.CreatedAt,
		)
		if err != nil {
			continue
		}

		if latencyP50.Valid {
			snapshot.LatencyP50 = &latencyP50.Float64
		}
		if latencyP95.Valid {
			snapshot.LatencyP95 = &latencyP95.Float64
			if metrics.LatencyP95 == nil || *snapshot.LatencyP95 > *metrics.LatencyP95 {
				metrics.LatencyP95 = snapshot.LatencyP95
			}
		}
		if latencyP99.Valid {
			snapshot.LatencyP99 = &latencyP99.Float64
		}
		if errorRate.Valid {
			snapshot.ErrorRate = &errorRate.Float64
			if metrics.ErrorRate == nil || *snapshot.ErrorRate > *metrics.ErrorRate {
				metrics.ErrorRate = snapshot.ErrorRate
			}
		}
		if throughput.Valid {
			snapshot.Throughput = &throughput.Float64
		}

		// Parse metadata JSONB
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &snapshot.Metadata); err != nil {
				snapshot.Metadata = make(map[string]interface{})
			}
		} else {
			snapshot.Metadata = make(map[string]interface{})
		}

		metrics.Trend = append(metrics.Trend, snapshot)

		// Update overall status (worst status wins)
		if snapshot.Status == "down" {
			metrics.Status = "down"
		} else if snapshot.Status == "degraded" && metrics.Status != "down" {
			metrics.Status = "degraded"
		}
	}

	// Get recent health events
	healthEventsQuery := `
		SELECT 
			id, service_name, event_type, status, message, metadata, timestamp, created_at
		FROM service_health_events
		WHERE service_name = $1 
			AND timestamp >= $2
		ORDER BY timestamp DESC
		LIMIT 50
	`

	healthRows, err := s.db.Query(healthEventsQuery, serviceName, startTime)
	if err == nil {
		defer healthRows.Close()
		metrics.HealthEvents = []models.ServiceHealthEvent{}

		for healthRows.Next() {
			var event models.ServiceHealthEvent
			var message sql.NullString
			var metadataJSON []byte

			err := healthRows.Scan(
				&event.ID,
				&event.ServiceName,
				&event.EventType,
				&event.Status,
				&message,
				&metadataJSON,
				&event.Timestamp,
				&event.CreatedAt,
			)
			if err != nil {
				continue
			}

			if message.Valid {
				event.Message = &message.String
			}

			// Parse metadata JSONB
			if len(metadataJSON) > 0 {
				if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
					event.Metadata = make(map[string]interface{})
				}
			} else {
				event.Metadata = make(map[string]interface{})
			}

			metrics.HealthEvents = append(metrics.HealthEvents, event)
		}
	}

	return metrics, nil
}

// GetIncidentHistory returns recent incidents
func (s *MetricsService) GetIncidentHistory(limit int) ([]models.Incident, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT 
			id, service_name, status, message, metadata, timestamp, created_at
		FROM service_health_events
		WHERE event_type = 'incident'
			AND status IN ('degraded', 'down')
		ORDER BY timestamp DESC
		LIMIT $1
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query incident history: %w", err)
	}
	defer rows.Close()

	incidents := []models.Incident{}

	for rows.Next() {
		var incident models.Incident
		var metadataJSON []byte

		err := rows.Scan(
			&incident.ID,
			&incident.ServiceName,
			&incident.Status,
			&incident.Message,
			&metadataJSON,
			&incident.StartedAt,
			&incident.CreatedAt,
		)
		if err != nil {
			continue
		}

		incident.Severity = incident.Status // Map status to severity for now

		// Parse metadata JSONB
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &incident.Metadata); err != nil {
				incident.Metadata = make(map[string]interface{})
			}
		} else {
			incident.Metadata = make(map[string]interface{})
		}

		incidents = append(incidents, incident)
	}

	return incidents, nil
}

// GetUptimeStats calculates system uptime statistics
func (s *MetricsService) GetUptimeStats() (*models.UptimeStats, error) {
	// Default to 7 days for calculation
	calculationWindow := 7 * 24 * time.Hour
	startTime := time.Now().Add(-calculationWindow)

	// Get all services
	servicesQuery := `
		SELECT DISTINCT service_name 
		FROM service_health_events
		WHERE timestamp >= $1
	`

	serviceRows, err := s.db.Query(servicesQuery, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query services: %w", err)
	}
	defer serviceRows.Close()

	var serviceNames []string
	for serviceRows.Next() {
		var serviceName string
		if err := serviceRows.Scan(&serviceName); err != nil {
			continue
		}
		serviceNames = append(serviceNames, serviceName)
	}

	stats := &models.UptimeStats{
		SystemUptime:      100.0, // Start optimistic
		UptimeSeconds:     int64(calculationWindow.Seconds()),
		DowntimeSeconds:   0,
		ServiceUptimes:    make(map[string]float64),
		TotalIncidents:    0,
		CalculationWindow: calculationWindow,
		CalculatedAt:      time.Now(),
	}

	totalWindowSeconds := int64(calculationWindow.Seconds())
	var totalUptime, totalDowntime int64

	// Calculate uptime for each service
	for _, serviceName := range serviceNames {
		// Get healthy vs unhealthy time
		uptimeQuery := `
			SELECT 
				COUNT(*) FILTER (WHERE status = 'healthy') as healthy_count,
				COUNT(*) FILTER (WHERE status IN ('degraded', 'down')) as unhealthy_count
			FROM service_health_events
			WHERE service_name = $1 
				AND timestamp >= $2
		`

		var healthyCount, unhealthyCount int
		err := s.db.QueryRow(uptimeQuery, serviceName, startTime).Scan(&healthyCount, &unhealthyCount)
		if err != nil {
			continue
		}

		totalEvents := healthyCount + unhealthyCount
		if totalEvents == 0 {
			stats.ServiceUptimes[serviceName] = 100.0
			continue
		}

		// Assume events are roughly evenly distributed over the window
		// This is a simplified calculation - in production, calculate actual time durations
		uptimePercent := (float64(healthyCount) / float64(totalEvents)) * 100.0
		stats.ServiceUptimes[serviceName] = uptimePercent

		totalUptime += int64(float64(healthyCount) * float64(totalWindowSeconds) / float64(totalEvents))
		totalDowntime += int64(float64(unhealthyCount) * float64(totalWindowSeconds) / float64(totalEvents))
	}

	// Get last incident
	lastIncidentQuery := `
		SELECT MAX(timestamp)
		FROM service_health_events
		WHERE event_type = 'incident'
			AND status IN ('degraded', 'down')
	`

	var lastIncident sql.NullTime
	err = s.db.QueryRow(lastIncidentQuery).Scan(&lastIncident)
	if err == nil && lastIncident.Valid {
		stats.LastIncident = &lastIncident.Time
	}

	// Count total incidents
	incidentCountQuery := `
		SELECT COUNT(*)
		FROM service_health_events
		WHERE event_type = 'incident'
			AND status IN ('degraded', 'down')
			AND timestamp >= $1
	`

	err = s.db.QueryRow(incidentCountQuery, startTime).Scan(&stats.TotalIncidents)
	if err != nil {
		stats.TotalIncidents = 0
	}

	// Calculate overall system uptime
	if totalWindowSeconds > 0 {
		stats.SystemUptime = (float64(totalUptime) / float64(totalWindowSeconds)) * 100.0
		stats.UptimeSeconds = totalUptime
		stats.DowntimeSeconds = totalDowntime
	}

	return stats, nil
}

// StoreServiceHealthEvent persists a health event to the database
func (s *MetricsService) StoreServiceHealthEvent(event *models.ServiceHealthEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	query := `
		INSERT INTO service_health_events (
			id, service_name, event_type, status, message, metadata, timestamp, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	var messageStr interface{}
	if event.Message != nil {
		messageStr = *event.Message
	}

	var metadataJSON interface{}
	if event.Metadata != nil {
		metadataBytes, err := json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = metadataBytes
	}

	_, err := s.db.Exec(query,
		event.ID,
		event.ServiceName,
		event.EventType,
		event.Status,
		messageStr,
		metadataJSON,
		event.Timestamp,
		event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store service health event: %w", err)
	}

	return nil
}

// GetTenantPerformanceSummary returns performance metrics for a specific tenant
func (s *MetricsService) GetTenantPerformanceSummary(tenantID uuid.UUID) (*models.TenantPerformanceSummary, error) {
	summary := &models.TenantPerformanceSummary{
		TenantID:    tenantID,
		LastUpdated: time.Now(),
		Uptime:      99.9, // Default optimistic uptime
	}

	// Try to get resource usage from resource-tracker-service via gateway
	resourceURL := fmt.Sprintf("%s/api/v1/resource-tracker-service/tenants/%s?period=24h", s.gatewayURL, tenantID.String())
	req, err := http.NewRequest("GET", resourceURL, nil)
	if err != nil {
		// If we can't get resource data, return defaults
		return summary, nil
	}

	serviceauth.SignRequestFromEnv(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		// If resource-tracker is unavailable, return defaults
		return summary, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			var resourceData struct {
				TotalAPICalls  int     `json:"total_api_calls"`
				TotalDBQueries int     `json:"total_db_queries"`
				AvgCPUPercent  float64 `json:"avg_cpu_percent"`
				TotalCostUSD   float64 `json:"total_cost_usd"`
			}
			if err := json.Unmarshal(body, &resourceData); err == nil {
				// Estimate throughput from API calls (assuming 24h period)
				if resourceData.TotalAPICalls > 0 {
					// Convert to requests per second (24 hours = 86400 seconds)
					summary.Throughput = float64(resourceData.TotalAPICalls) / 86400.0
				}

				// Estimate response time based on CPU usage and API calls
				// Higher CPU or more API calls might indicate higher response times
				if resourceData.AvgCPUPercent > 0 && resourceData.TotalAPICalls > 0 {
					// Simple heuristic: response time increases with CPU usage
					baseResponseTime := 100.0 // Base 100ms
					cpuFactor := resourceData.AvgCPUPercent / 100.0
					summary.AvgResponseTime = baseResponseTime + (cpuFactor * 200.0) // Up to 300ms
				} else {
					summary.AvgResponseTime = 150.0 // Default estimate
				}

				// Estimate error rate (low by default, could be enhanced with actual error tracking)
				// For now, use a small error rate that might increase with high load
				if resourceData.AvgCPUPercent > 80 {
					summary.ErrorRate = 0.02 // 2% error rate if CPU is high
				} else {
					summary.ErrorRate = 0.005 // 0.5% default error rate
				}
			}
		}
	}

	// Get uptime from service health events for this tenant
	// For now, estimate based on overall system health.
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Despite the tenantID
	// argument, this query reads platform-wide service_health_events (a
	// non-tenant-scoped table with no RLS policy) and does NOT filter by tenant;
	// the tenantID only feeds the resource-tracker HTTP call and the response.
	uptimeQuery := `
		SELECT 
			COUNT(*) FILTER (WHERE status = 'healthy') as healthy_count,
			COUNT(*) FILTER (WHERE status IN ('degraded', 'down')) as unhealthy_count
		FROM service_health_events
		WHERE timestamp >= NOW() - INTERVAL '24 hours'
	`
	var healthyCount, unhealthyCount int
	if err := s.bypassDB.QueryRow(uptimeQuery).Scan(&healthyCount, &unhealthyCount); err == nil {
		totalEvents := healthyCount + unhealthyCount
		if totalEvents > 0 {
			summary.Uptime = (float64(healthyCount) / float64(totalEvents)) * 100.0
		}
	}

	return summary, nil
}

// RecordDiscoveryEvent records an asset discovery event as a metric for dashboard visibility.
//
// RLS: not wrapped — monitoring_events has no tenant_isolation policy (it is not
// in the RLS policy set in scripts/database/schema.sql), so there is no
// app.tenant_id context to satisfy. The tenant_id column is written as ordinary
// data. Left global per the playbook's reference-table rule.
func (s *MetricsService) RecordDiscoveryEvent(tenantID, assetID uuid.UUID, source string) {
	query := `
		INSERT INTO monitoring_events (id, tenant_id, event_type, source, resource_id, created_at)
		VALUES ($1, $2, 'asset_discovered', $3, $4, $5)
		ON CONFLICT DO NOTHING
	`
	_, err := s.db.Exec(query, uuid.New(), tenantID, source, assetID, time.Now())
	if err != nil {
		// Non-critical — log and continue
		fmt.Printf("[MetricsService] Failed to record discovery event: %v\n", err)
	}
}

func (s *MetricsService) Close() error {
	if s.bypassDB != nil {
		_ = s.bypassDB.Close()
	}
	return s.db.Close()
}
