package resourcetracking

import (
	"time"

	"github.com/google/uuid"
)

// ResourceMetrics represents a single resource usage measurement
type ResourceMetrics struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	ServiceName     string    `json:"service_name"`
	Timestamp       time.Time `json:"timestamp"`
	APICalls        int       `json:"api_calls"`
	DatabaseQueries int       `json:"database_queries"`
	MemoryUsageMB   int       `json:"memory_usage_mb"`
	CPUUsagePercent float64   `json:"cpu_usage_percent"`
	StorageUsedMB   int       `json:"storage_used_mb"`
	NetworkBytes    int64     `json:"network_bytes"`
	ResponseTimeMs  int64     `json:"response_time_ms"`
	StatusCode      int       `json:"status_code"`
	Endpoint        string    `json:"endpoint"`
	Method          string    `json:"method"`
}

// BatchRequest represents a batch of metrics to send to the tracker service
type BatchRequest struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	APICalls        int       `json:"api_calls,omitempty"`
	DatabaseQueries int       `json:"database_queries,omitempty"`
	MemoryUsageMB   int       `json:"memory_usage_mb,omitempty"`
	CPUUsagePercent float64   `json:"cpu_usage_percent,omitempty"`
	StorageUsedMB   int       `json:"storage_used_mb,omitempty"`
	NetworkBytes    int64     `json:"network_bytes,omitempty"`
}

// BatchResponse represents the response from the tracker service
type BatchResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Count   int    `json:"count"`
}

// CircuitBreakerState tracks the state of the circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

// CircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
	State             CircuitBreakerState
	FailureCount      int
	LastFailureTime   time.Time
	Threshold         int
	Timeout           time.Duration
	SuccessCount      int
	HalfOpenThreshold int
}
