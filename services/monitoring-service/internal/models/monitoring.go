package models

import (
	"time"

	"github.com/google/uuid"
)

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	ServiceName  string    `json:"service_name"`
	Status       string    `json:"status"` // "healthy", "unhealthy", "degraded"
	Message      string    `json:"message"`
	Timestamp    time.Time `json:"timestamp"`
	ResponseTime int64     `json:"response_time_ms"`
	Error        *string   `json:"error,omitempty"`
}

// SystemStatusResponse represents the overall system status
type SystemStatusResponse struct {
	Status        string          `json:"status"`
	OverallStatus string          `json:"overall_status"`
	Services      []ServiceStatus `json:"services"`
	Metrics       SystemMetrics   `json:"metrics"`
	Timestamp     time.Time       `json:"timestamp"`
}

// ServiceStatus represents the status of a single service
type ServiceStatus struct {
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	Message      string    `json:"message"`
	ResponseTime int64     `json:"response_time_ms"`
	LastCheck    time.Time `json:"last_check"`
	LastChecked  time.Time `json:"last_checked"`
	Error        *string   `json:"error,omitempty"`
}

// SystemMetrics represents system-wide metrics
type SystemMetrics struct {
	CPUUsage            float64   `json:"cpu_usage"`
	MemoryUsage         float64   `json:"memory_usage"`
	DiskUsage           float64   `json:"disk_usage"`
	NetworkIO           int64     `json:"network_io"`
	Uptime              int64     `json:"uptime_seconds"`
	TotalServices       int       `json:"total_services"`
	HealthyServices     int       `json:"healthy_services"`
	DegradedServices    int       `json:"degraded_services"`
	DownServices        int       `json:"down_services"`
	AverageResponseTime float64   `json:"average_response_time"`
	TotalTenants        int       `json:"total_tenants"`
	ActiveTenants       int       `json:"active_tenants"`
	TotalUsers          int       `json:"total_users"`
	TotalAssets         int       `json:"total_assets"`
	LastUpdated         time.Time `json:"last_updated"`
}

// TenantStatus represents the status of a tenant
type TenantStatus struct {
	TenantID     string          `json:"tenant_id"`
	TenantName   string          `json:"tenant_name"`
	Status       string          `json:"status"`
	LastActivity time.Time       `json:"last_activity"`
	UserCount    int             `json:"user_count"`
	AssetCount   int             `json:"asset_count"`
	Services     []ServiceStatus `json:"services"`
}

// PlatformMetricsSnapshot represents a stored metrics snapshot
type PlatformMetricsSnapshot struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	ServiceName    string                 `json:"service_name" db:"service_name"`
	WindowStart    time.Time              `json:"window_start" db:"window_start"`
	WindowDuration int                    `json:"window_duration" db:"window_duration"`
	LatencyP50     *float64               `json:"latency_p50,omitempty" db:"latency_p50"`
	LatencyP95     *float64               `json:"latency_p95,omitempty" db:"latency_p95"`
	LatencyP99     *float64               `json:"latency_p99,omitempty" db:"latency_p99"`
	ErrorRate      *float64               `json:"error_rate,omitempty" db:"error_rate"`
	Throughput     *float64               `json:"throughput,omitempty" db:"throughput"`
	Status         string                 `json:"status" db:"status"`
	Metadata       map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
}

// ServiceHealthEvent represents a health event for a service
type ServiceHealthEvent struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	ServiceName string                 `json:"service_name" db:"service_name"`
	EventType   string                 `json:"event_type" db:"event_type"`
	Status      string                 `json:"status" db:"status"`
	Message     *string                `json:"message,omitempty" db:"message"`
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
	Timestamp   time.Time              `json:"timestamp" db:"timestamp"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
}

// PlatformMetricsSummary represents aggregated platform metrics
type PlatformMetricsSummary struct {
	StartTime         time.Time               `json:"start_time"`
	EndTime           time.Time               `json:"end_time"`
	Services          []ServiceMetricsSummary `json:"services"`
	OverallStatus     string                  `json:"overall_status"`
	TotalServices     int                     `json:"total_services"`
	HealthyServices   int                     `json:"healthy_services"`
	DegradedServices  int                     `json:"degraded_services"`
	DownServices      int                     `json:"down_services"`
	AverageLatencyP95 float64                 `json:"average_latency_p95"`
	AverageErrorRate  float64                 `json:"average_error_rate"`
	TotalThroughput   float64                 `json:"total_throughput"`
	Timestamp         time.Time               `json:"timestamp"`
}

// ServiceMetricsSummary represents metrics for a single service
type ServiceMetricsSummary struct {
	ServiceName string    `json:"service_name"`
	Status      string    `json:"status"`
	LatencyP50  *float64  `json:"latency_p50,omitempty"`
	LatencyP95  *float64  `json:"latency_p95,omitempty"`
	LatencyP99  *float64  `json:"latency_p99,omitempty"`
	ErrorRate   *float64  `json:"error_rate,omitempty"`
	Throughput  *float64  `json:"throughput,omitempty"`
	SampleCount int       `json:"sample_count"`
	LastUpdated time.Time `json:"last_updated"`
}

// ServiceMetrics represents detailed metrics for a service over a time window
type ServiceMetrics struct {
	ServiceName  string                    `json:"service_name"`
	Window       string                    `json:"window"` // "1m", "1h", "1d"
	StartTime    time.Time                 `json:"start_time"`
	EndTime      time.Time                 `json:"end_time"`
	LatencyP50   *float64                  `json:"latency_p50,omitempty"`
	LatencyP95   *float64                  `json:"latency_p95,omitempty"`
	LatencyP99   *float64                  `json:"latency_p99,omitempty"`
	ErrorRate    *float64                  `json:"error_rate,omitempty"`
	Throughput   *float64                  `json:"throughput,omitempty"`
	Status       string                    `json:"status"`
	HealthEvents []ServiceHealthEvent      `json:"health_events,omitempty"`
	Trend        []PlatformMetricsSnapshot `json:"trend,omitempty"`
	LastUpdated  time.Time                 `json:"last_updated"`
}

// Incident represents a service incident
type Incident struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	ServiceName string                 `json:"service_name" db:"service_name"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status" db:"status"`
	Message     string                 `json:"message" db:"message"`
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
	StartedAt   time.Time              `json:"started_at" db:"timestamp"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty" db:"resolved_at"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
}

// UptimeStats represents system uptime statistics
type UptimeStats struct {
	SystemUptime      float64            `json:"system_uptime_percent"`
	UptimeSeconds     int64              `json:"uptime_seconds"`
	DowntimeSeconds   int64              `json:"downtime_seconds"`
	ServiceUptimes    map[string]float64 `json:"service_uptimes"` // service_name -> uptime_percent
	LastIncident      *time.Time         `json:"last_incident,omitempty"`
	TotalIncidents    int                `json:"total_incidents"`
	CalculationWindow time.Duration      `json:"calculation_window"`
	CalculatedAt      time.Time          `json:"calculated_at"`
}

// TenantPerformanceSummary represents performance metrics for a specific tenant
type TenantPerformanceSummary struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	AvgResponseTime float64   `json:"avg_response_time_ms"` // Average response time in milliseconds
	ErrorRate       float64   `json:"error_rate"`           // Error rate as decimal (0.0 - 1.0)
	Throughput      float64   `json:"throughput_rps"`       // Requests per second
	Uptime          float64   `json:"uptime_percent"`       // Uptime percentage (0.0 - 100.0)
	LastUpdated     time.Time `json:"last_updated"`
}

// SystemHealthOverview represents an aggregated overview of system health for the dashboard
type SystemHealthOverview struct {
	OverallStatus OverallStatusType             `json:"overall_status"`
	Sensors       SystemHealthOverviewSensors   `json:"sensors"`
	Services      []SystemHealthOverviewService `json:"services"`
	Database      SystemHealthOverviewDatabase  `json:"database"`
	LastUpdated   string                        `json:"last_updated"`
}

// OverallStatusType defines the overall health status
type OverallStatusType string

const (
	OverallStatusHealthy  OverallStatusType = "healthy"
	OverallStatusDegraded OverallStatusType = "degraded"
	OverallStatusDown     OverallStatusType = "down"
)

// SystemHealthOverviewSensors represents sensor health summary
type SystemHealthOverviewSensors struct {
	Active int `json:"active"`
	Total  int `json:"total"`
}

// SystemHealthOverviewService represents a single service's health in the overview
type SystemHealthOverviewService struct {
	Name           string            `json:"name"`
	Status         ServiceStatusType `json:"status"`
	ResponseTimeMs int64             `json:"response_time_ms"`
	LastChecked    string            `json:"last_checked"`
}

// ServiceStatusType defines the status of a service
type ServiceStatusType string

const (
	ServiceStatusHealthy  ServiceStatusType = "healthy"
	ServiceStatusDegraded ServiceStatusType = "degraded"
	ServiceStatusDown     ServiceStatusType = "down"
	ServiceStatusUnknown  ServiceStatusType = "unknown"
)

// SystemHealthOverviewDatabase represents database health summary
type SystemHealthOverviewDatabase struct {
	Status  ServiceStatusType `json:"status"`
	Message string            `json:"message,omitempty"`
}
