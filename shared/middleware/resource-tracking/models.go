package resourcetracking

import (
	"time"

	"github.com/google/uuid"
)

// ResourceMetrics represents a single resource usage measurement.
//
// DatabaseQueries is a pointer because nil means "nothing counted them", which
// is different from "there were none". CPU, memory and storage are absent
// entirely: this middleware runs inside shared service pods and cannot observe
// any of the three per tenant. Carrying them as zero-valued fields is what let
// unmeasured components be priced downstream as measured zeroes.
type ResourceMetrics struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	ServiceName     string    `json:"service_name"`
	Timestamp       time.Time `json:"timestamp"`
	APICalls        int64     `json:"api_calls"`
	DatabaseQueries *int64    `json:"database_queries,omitempty"`
	NetworkBytes    int64     `json:"network_bytes"`
	ResponseTimeMs  int64     `json:"response_time_ms"`
	StatusCode      int       `json:"status_code"`
	Endpoint        string    `json:"endpoint"`
	Method          string    `json:"method"`
}

// BatchRequest represents a batch of metrics to send to the tracker service.
// An omitted field means not measured; see ResourceMetrics.
type BatchRequest struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	APICalls        int64     `json:"api_calls"`
	DatabaseQueries *int64    `json:"database_queries,omitempty"`
	NetworkBytes    int64     `json:"network_bytes"`
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
