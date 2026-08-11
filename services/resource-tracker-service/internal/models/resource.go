package models

import (
	"time"

	"github.com/google/uuid"
)

// ResourceUsage represents resource consumption for a tenant
type ResourceUsage struct {
	ID              uuid.UUID `json:"id" db:"id"`
	TenantID        uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Timestamp       time.Time `json:"timestamp" db:"timestamp"`
	APICalls        int       `json:"api_calls" db:"api_calls"`
	DatabaseQueries int       `json:"database_queries" db:"database_queries"`
	MemoryUsageMB   int       `json:"memory_usage_mb" db:"memory_usage_mb"`
	CPUUsagePercent float64   `json:"cpu_usage_percent" db:"cpu_usage_percent"`
	StorageUsedMB   int       `json:"storage_used_mb" db:"storage_used_mb"`
	NetworkBytes    int64     `json:"network_bytes" db:"network_bytes"`
	CostUSD         float64   `json:"cost_usd" db:"cost_usd"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// CostAnalysis represents cost analysis for a tenant over a period
type CostAnalysis struct {
	ID                      uuid.UUID                `json:"id" db:"id"`
	TenantID                uuid.UUID                `json:"tenant_id" db:"tenant_id"`
	PeriodStart             time.Time                `json:"period_start" db:"period_start"`
	PeriodEnd               time.Time                `json:"period_end" db:"period_end"`
	TotalCostUSD            float64                  `json:"total_cost_usd" db:"total_cost_usd"`
	ResourceBreakdown       ResourceBreakdown        `json:"resource_breakdown" db:"resource_breakdown"`
	OptimizationSuggestions []OptimizationSuggestion `json:"optimization_suggestions" db:"optimization_suggestions"`
	CreatedAt               time.Time                `json:"created_at" db:"created_at"`
}

// ResourceBreakdown provides detailed cost breakdown
type ResourceBreakdown struct {
	APICost      float64 `json:"api_cost"`
	DatabaseCost float64 `json:"database_cost"`
	StorageCost  float64 `json:"storage_cost"`
	ComputeCost  float64 `json:"compute_cost"`
	NetworkCost  float64 `json:"network_cost"`
	TotalCost    float64 `json:"total_cost"`
}

// OptimizationSuggestion provides cost optimization recommendations
type OptimizationSuggestion struct {
	Type             string  `json:"type"` // "api", "database", "storage", "compute"
	Description      string  `json:"description"`
	PotentialSavings float64 `json:"potential_savings"`
	Priority         string  `json:"priority"` // "high", "medium", "low"
}

// ResourceAlert represents alerts for resource usage thresholds
type ResourceAlert struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	TenantID     uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	AlertType    string     `json:"alert_type" db:"alert_type"` // "cost", "usage", "performance"
	Metric       string     `json:"metric" db:"metric"`         // "api_calls", "memory_usage", etc.
	Threshold    float64    `json:"threshold" db:"threshold"`
	CurrentValue float64    `json:"current_value" db:"current_value"`
	Message      string     `json:"message" db:"message"`
	Severity     string     `json:"severity" db:"severity"` // "critical", "warning", "info"
	IsActive     bool       `json:"is_active" db:"is_active"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	ResolvedAt   *time.Time `json:"resolved_at" db:"resolved_at"`
}

// ResourceMetricsRequest represents a request to record resource metrics
type ResourceMetricsRequest struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	APICalls        int       `json:"api_calls,omitempty"`
	DatabaseQueries int       `json:"database_queries,omitempty"`
	MemoryUsageMB   int       `json:"memory_usage_mb,omitempty"`
	CPUUsagePercent float64   `json:"cpu_usage_percent,omitempty"`
	StorageUsedMB   int       `json:"storage_used_mb,omitempty"`
	NetworkBytes    int64     `json:"network_bytes,omitempty"`
}

// ResourceUsageResponse represents aggregated resource usage data
type ResourceUsageResponse struct {
	TenantID       uuid.UUID         `json:"tenant_id"`
	Period         string            `json:"period"` // "1h", "24h", "7d", "30d"
	TotalAPICalls  int               `json:"total_api_calls"`
	TotalDBQueries int               `json:"total_db_queries"`
	AvgMemoryMB    float64           `json:"avg_memory_mb"`
	AvgCPUPercent  float64           `json:"avg_cpu_percent"`
	TotalStorageMB int               `json:"total_storage_mb"`
	TotalNetworkMB float64           `json:"total_network_mb"`
	TotalCostUSD   float64           `json:"total_cost_usd"`
	CostBreakdown  ResourceBreakdown `json:"cost_breakdown"`
	Alerts         []ResourceAlert   `json:"alerts"`
}

// TenantResourceSummary provides a summary of resource usage for a tenant
type TenantResourceSummary struct {
	TenantID          uuid.UUID             `json:"tenant_id"`
	TenantName        string                `json:"tenant_name"`
	CurrentUsage      ResourceUsageResponse `json:"current_usage"`
	CostTrend         []CostDataPoint       `json:"cost_trend"`
	ResourceTrend     []ResourceDataPoint   `json:"resource_trend"`
	OptimizationScore float64               `json:"optimization_score"` // 0-100, higher is better
}

// CostDataPoint represents a single cost data point for trending
type CostDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	CostUSD   float64   `json:"cost_usd"`
}

// ResourceDataPoint represents a single resource usage data point
type ResourceDataPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	APICalls        int       `json:"api_calls"`
	DatabaseQueries int       `json:"database_queries"`
	MemoryUsageMB   int       `json:"memory_usage_mb"`
	CPUUsagePercent float64   `json:"cpu_usage_percent"`
}

// TenantResourceHealthSummary represents resource health metrics for a tenant (for tenant health service)
type TenantResourceHealthSummary struct {
	TenantID                uuid.UUID `json:"tenant_id"`
	TotalAPICalls           int       `json:"total_api_calls"`           // Total API calls in last 24h
	TotalDBQueries          int       `json:"total_db_queries"`          // Total database queries in last 24h
	AvgCPUPercent           float64   `json:"avg_cpu_percent"`           // Average CPU usage percentage
	AvgMemoryMB             float64   `json:"avg_memory_mb"`             // Average memory usage in MB
	TotalCostUSD            float64   `json:"total_cost_usd"`            // Total cost in USD for last 24h
	ResourceEfficiencyScore float64   `json:"resource_efficiency_score"` // Efficiency score (0-100)
	LastUpdated             time.Time `json:"last_updated"`
}
