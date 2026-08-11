package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/services"
)

// MetricsAggregator collects metrics from health checks and aggregates them into snapshots
type MetricsAggregator struct {
	config         *config.Config
	healthService  *services.HealthService
	metricsService *services.MetricsService
	db             *sql.DB
	interval       time.Duration
	logger         *log.Logger
}

// NewMetricsAggregator creates a new metrics aggregator
func NewMetricsAggregator(cfg *config.Config, healthService *services.HealthService, metricsService *services.MetricsService) *MetricsAggregator {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	// Test database connection
	if err := db.Ping(); err != nil {
		panic(fmt.Sprintf("Failed to ping database: %v", err))
	}

	interval := 1 * time.Minute // Default: aggregate every minute
	if intervalStr := os.Getenv("METRICS_AGGREGATION_INTERVAL"); intervalStr != "" {
		if parsed, err := time.ParseDuration(intervalStr); err == nil {
			interval = parsed
		}
	}

	return &MetricsAggregator{
		config:         cfg,
		healthService:  healthService,
		metricsService: metricsService,
		db:             db,
		interval:       interval,
		logger:         log.New(log.Writer(), "[MetricsAggregator] ", log.LstdFlags),
	}
}

// Start begins the metrics aggregation process
func (ma *MetricsAggregator) Start(ctx context.Context) {
	ma.logger.Printf("Starting metrics aggregator (interval: %v)", ma.interval)

	ticker := time.NewTicker(ma.interval)
	defer ticker.Stop()

	// Aggregate immediately on start
	ma.aggregateMetrics()

	for {
		select {
		case <-ctx.Done():
			ma.logger.Println("Metrics aggregator stopping")
			ma.db.Close()
			return
		case <-ticker.C:
			ma.aggregateMetrics()
		}
	}
}

// aggregateMetrics aggregates metrics from health checks into snapshots
func (ma *MetricsAggregator) aggregateMetrics() {
	// Get system status from health service
	status := ma.healthService.GetSystemStatus()

	// Process each service's metrics
	for _, service := range status.Services {
		ma.processServiceMetrics(service, status.Metrics)
	}

	// Store health events for services that are not healthy or have errors
	for _, service := range status.Services {
		if service.Status != "healthy" || service.Error != nil {
			ma.storeHealthEvent(service)
		}
	}
}

// processServiceMetrics processes metrics for a single service and creates a snapshot
func (ma *MetricsAggregator) processServiceMetrics(service models.ServiceStatus, systemMetrics models.SystemMetrics) {
	now := time.Now()
	windowStart := now.Truncate(time.Minute) // Round down to nearest minute

	// Determine status based on service health
	status := "healthy"
	if service.Status == "down" || service.Status == "unhealthy" {
		status = "down"
	} else if service.Status == "degraded" {
		status = "degraded"
	}

	// Calculate metrics (simplified - in production you'd track these over time)
	var latencyP50, latencyP95, latencyP99 *float64
	var errorRate *float64
	var throughput *float64

	// Use response time as latency metric (convert from milliseconds)
	if service.ResponseTime > 0 {
		latencyMs := float64(service.ResponseTime)
		// Estimate percentiles from response time (simplified approach)
		// In production, you'd track actual request latencies
		latencyP50 = &latencyMs
		p95Estimate := latencyMs * 1.5 // P95 typically higher
		latencyP95 = &p95Estimate
		p99Estimate := latencyMs * 2.0 // P99 typically much higher
		latencyP99 = &p99Estimate
	}

	// Calculate error rate (simplified - would track actual errors)
	if service.Error != nil || service.Status == "down" {
		errorRateVal := 1.0 // 100% error if error exists or down
		errorRate = &errorRateVal
	} else if service.Status == "degraded" {
		errorRateVal := 0.1 // 10% error rate for degraded
		errorRate = &errorRateVal
	} else {
		errorRateVal := 0.0
		errorRate = &errorRateVal
	}

	// Estimate throughput based on system metrics (simplified)
	if systemMetrics.TotalServices > 0 {
		// Rough estimate: distribute requests across services
		estimatedRPS := systemMetrics.AverageResponseTime / float64(systemMetrics.TotalServices)
		if estimatedRPS > 0 {
			throughput = &estimatedRPS
		}
	}

	// Create snapshot for 1-minute window
	snapshot := &models.PlatformMetricsSnapshot{
		ID:             uuid.New(),
		ServiceName:    service.Name,
		WindowStart:    windowStart,
		WindowDuration: 60, // 1 minute
		LatencyP50:     latencyP50,
		LatencyP95:     latencyP95,
		LatencyP99:     latencyP99,
		ErrorRate:      errorRate,
		Throughput:     throughput,
		Status:         status,
		Metadata: map[string]interface{}{
			"response_time_ms": service.ResponseTime,
			"last_check":       service.LastCheck,
			"message":          service.Message,
		},
		CreatedAt: now,
	}

	// Store snapshot
	if err := ma.metricsService.StorePlatformMetricsSnapshot(snapshot); err != nil {
		ma.logger.Printf("Failed to store metrics snapshot for %s: %v", service.Name, err)
	}

	// Also aggregate to 1-hour and 1-day windows (less frequently)
	ma.aggregateToHourly(snapshot)
	ma.aggregateToDaily(snapshot)
}

// aggregateToHourly aggregates minute snapshots into hourly snapshots
func (ma *MetricsAggregator) aggregateToHourly(minuteSnapshot *models.PlatformMetricsSnapshot) {
	// Only aggregate at the start of each hour
	now := time.Now()
	if now.Minute() != 0 {
		return
	}

	hourStart := now.Truncate(time.Hour)
	windowStart := hourStart.Add(-time.Hour) // Previous hour

	ma.aggregateWindow(minuteSnapshot.ServiceName, windowStart, 3600) // 1 hour
}

// aggregateToDaily aggregates hourly snapshots into daily snapshots
func (ma *MetricsAggregator) aggregateToDaily(minuteSnapshot *models.PlatformMetricsSnapshot) {
	// Only aggregate at midnight
	now := time.Now()
	if now.Hour() != 0 || now.Minute() != 0 {
		return
	}

	dayStart := now.Truncate(24 * time.Hour)
	windowStart := dayStart.Add(-24 * time.Hour) // Previous day

	ma.aggregateWindow(minuteSnapshot.ServiceName, windowStart, 86400) // 1 day
}

// aggregateWindow aggregates snapshots for a given time window
func (ma *MetricsAggregator) aggregateWindow(serviceName string, windowStart time.Time, windowDuration int) {
	windowEnd := windowStart.Add(time.Duration(windowDuration) * time.Second)

	// Query aggregated metrics for the window
	// Aggregate from minute-level snapshots to create hourly/daily snapshots
	query := `
		SELECT 
			AVG(latency_p50) as avg_latency_p50,
			AVG(latency_p95) as avg_latency_p95,
			AVG(latency_p99) as avg_latency_p99,
			AVG(error_rate) as avg_error_rate,
			COALESCE(SUM(throughput), 0) as total_throughput,
			COUNT(*) as sample_count,
			CASE 
				WHEN COUNT(*) FILTER (WHERE status = 'down') > 0 THEN 'down'
				WHEN COUNT(*) FILTER (WHERE status = 'degraded') > 0 THEN 'degraded'
				ELSE 'healthy'
			END as worst_status
		FROM platform_metrics_snapshots
		WHERE service_name = $1
			AND window_duration = 60
			AND window_start >= $2
			AND window_start < $3
	`

	var avgLatencyP50, avgLatencyP95, avgLatencyP99, avgErrorRate sql.NullFloat64
	var totalThroughput sql.NullFloat64
	var sampleCount int
	var worstStatus sql.NullString

	err := ma.db.QueryRow(query, serviceName, windowStart, windowEnd).Scan(
		&avgLatencyP50,
		&avgLatencyP95,
		&avgLatencyP99,
		&avgErrorRate,
		&totalThroughput,
		&sampleCount,
		&worstStatus,
	)

	if err == sql.ErrNoRows {
		return // No data to aggregate
	}

	if err != nil {
		ma.logger.Printf("Failed to aggregate metrics for %s: %v", serviceName, err)
		return
	}

	// Determine status (worst status wins)
	status := "healthy"
	if worstStatus.Valid {
		if worstStatus.String == "down" {
			status = "down"
		} else if worstStatus.String == "degraded" && status != "down" {
			status = "degraded"
		}
	}

	// Create aggregated snapshot
	snapshot := &models.PlatformMetricsSnapshot{
		ID:             uuid.New(),
		ServiceName:    serviceName,
		WindowStart:    windowStart,
		WindowDuration: windowDuration,
		Status:         status,
		Metadata: map[string]interface{}{
			"sample_count":    sampleCount,
			"aggregated_from": "minute_snapshots",
		},
		CreatedAt: time.Now(),
	}

	if avgLatencyP50.Valid {
		snapshot.LatencyP50 = &avgLatencyP50.Float64
	}
	if avgLatencyP95.Valid {
		snapshot.LatencyP95 = &avgLatencyP95.Float64
	}
	if avgLatencyP99.Valid {
		snapshot.LatencyP99 = &avgLatencyP99.Float64
	}
	if avgErrorRate.Valid {
		snapshot.ErrorRate = &avgErrorRate.Float64
	}
	if totalThroughput.Valid {
		snapshot.Throughput = &totalThroughput.Float64
	}

	// Store aggregated snapshot
	if err := ma.metricsService.StorePlatformMetricsSnapshot(snapshot); err != nil {
		ma.logger.Printf("Failed to store aggregated snapshot for %s: %v", serviceName, err)
	}
}

// storeHealthEvent stores a health event for a service
func (ma *MetricsAggregator) storeHealthEvent(service models.ServiceStatus) {
	// Only store events for degraded/down status or errors
	// Skip if healthy to reduce noise
	if service.Status == "healthy" && service.Error == nil {
		return
	}

	// Skip "disabled" services (e.g. Grafana when GRAFANA_URL is not set).
	// "disabled" is not a valid health event status per the DB constraint.
	if service.Status == "disabled" {
		return
	}

	eventType := "heartbeat"
	if service.Status == "down" {
		eventType = "incident"
	}

	event := &models.ServiceHealthEvent{
		ID:          uuid.New(),
		ServiceName: service.Name,
		EventType:   eventType,
		Status:      service.Status,
		Timestamp:   service.LastChecked,
		CreatedAt:   time.Now(),
	}

	if service.Message != "" {
		event.Message = &service.Message
	} else if service.Error != nil {
		event.Message = service.Error
	}

	// Add metadata
	event.Metadata = map[string]interface{}{
		"response_time_ms": service.ResponseTime,
		"last_check":       service.LastCheck,
		"last_checked":     service.LastChecked,
	}

	if service.Error != nil {
		event.Metadata["error"] = *service.Error
	}

	// Store event (best effort - don't block on errors)
	if err := ma.metricsService.StoreServiceHealthEvent(event); err != nil {
		ma.logger.Printf("Failed to store health event for %s: %v", service.Name, err)
	}
}

// CleanupOldMetrics removes metrics older than the retention period
func (ma *MetricsAggregator) CleanupOldMetrics() error {
	retentionDays := 90 // Default: 90 days
	if retentionStr := os.Getenv("METRICS_RETENTION_DAYS"); retentionStr != "" {
		if parsed, err := strconv.Atoi(retentionStr); err == nil && parsed > 0 {
			retentionDays = parsed
		}
	}

	retentionTime := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)

	// Delete old snapshots
	snapshotQuery := `
		DELETE FROM platform_metrics_snapshots
		WHERE created_at < $1
			AND window_duration = 60 -- Only delete minute-level snapshots
	`
	result, err := ma.db.Exec(snapshotQuery, retentionTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup old snapshots: %w", err)
	}

	deleted, _ := result.RowsAffected()
	ma.logger.Printf("Cleaned up %d old metric snapshots", deleted)

	// Delete old health events (keep for shorter period)
	eventRetentionDays := 30
	if eventRetentionStr := os.Getenv("HEALTH_EVENTS_RETENTION_DAYS"); eventRetentionStr != "" {
		if parsed, err := strconv.Atoi(eventRetentionStr); err == nil && parsed > 0 {
			eventRetentionDays = parsed
		}
	}

	eventRetentionTime := time.Now().Add(-time.Duration(eventRetentionDays) * 24 * time.Hour)

	eventQuery := `
		DELETE FROM service_health_events
		WHERE created_at < $1
			AND event_type != 'incident' -- Keep incidents longer
	`
	result, err = ma.db.Exec(eventQuery, eventRetentionTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup old health events: %w", err)
	}

	deletedEvents, _ := result.RowsAffected()
	ma.logger.Printf("Cleaned up %d old health events", deletedEvents)

	return nil
}
