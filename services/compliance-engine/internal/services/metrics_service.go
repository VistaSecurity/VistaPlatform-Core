package services

import (
	"strings"
	"sync"
	"time"
)

// EventMetrics tracks metrics for event processing
type EventMetrics struct {
	// Event publish metrics
	EventsPublished       int64            `json:"events_published"`
	EventsPublishedByType map[string]int64 `json:"events_published_by_type"`

	// Event processing metrics
	EventsProcessed        int64            `json:"events_processed"`
	EventsProcessedByType  map[string]int64 `json:"events_processed_by_type"`
	EventsProcessedSuccess int64            `json:"events_processed_success"`
	EventsProcessedError   int64            `json:"events_processed_error"`

	// Latency metrics (in milliseconds)
	ProcessingLatencySum   int64 `json:"processing_latency_sum_ms"`
	ProcessingLatencyCount int64 `json:"processing_latency_count"`
	ProcessingLatencyMax   int64 `json:"processing_latency_max_ms"`

	// Finding metrics
	FindingsUpserted       int64 `json:"findings_upserted"`
	FindingsCreated        int64 `json:"findings_created"`
	FindingsUpdated        int64 `json:"findings_updated"`
	FindingsMarkedInactive int64 `json:"findings_marked_inactive"`

	// Control-assessment metrics. A control that could not be assessed
	// is excluded from the compliance score rather than counted as a pass — that
	// is only defensible while the omission is visible, so it is counted here and
	// surfaced on /metrics. MeasurementExtractionErrors is the specific signal
	// that used to be discarded by a bare `continue` in the rule evaluator.
	ControlsNotAssessed         map[string]int64 `json:"controls_not_assessed_by_reason"`
	MeasurementExtractionErrors int64            `json:"measurement_extraction_errors"`

	// State transition metrics
	StateTransitions   map[string]int64 `json:"state_transitions"` // "ACTIVE->INACTIVE", "INACTIVE->ACTIVE", etc.
	ResurfacedFindings int64            `json:"resurfaced_findings"`

	// Error metrics
	ProcessingErrors int64            `json:"processing_errors"`
	ErrorByType      map[string]int64 `json:"error_by_type"`

	// NATS connection metrics
	NATSConnectionStatus string `json:"nats_connection_status"` // "connected", "disconnected", "reconnecting"
	NATSReconnectCount   int64  `json:"nats_reconnect_count"`

	// Timestamps
	LastEventProcessedAt *time.Time `json:"last_event_processed_at"`
	LastErrorAt          *time.Time `json:"last_error_at"`
}

// MetricsService provides thread-safe access to event processing metrics.
// The lock lives here (not on EventMetrics) so GetMetrics can return a snapshot
// by value without copying a mutex, and so Reset can atomically swap the
// underlying metrics struct under a stable lock.
type MetricsService struct {
	mu      sync.RWMutex
	metrics *EventMetrics
}

// NewMetricsService creates a new metrics service
func NewMetricsService() *MetricsService {
	return &MetricsService{
		metrics: &EventMetrics{
			EventsPublishedByType: make(map[string]int64),
			EventsProcessedByType: make(map[string]int64),
			StateTransitions:      make(map[string]int64),
			ErrorByType:           make(map[string]int64),
			ControlsNotAssessed:   make(map[string]int64),
			NATSConnectionStatus:  "disconnected",
		},
	}
}

// RecordEventPublished records that an event was published
func (s *MetricsService) RecordEventPublished(eventType string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics.EventsPublished++
	s.metrics.EventsPublishedByType[eventType]++
}

// RecordEventProcessed records that an event was processed
func (s *MetricsService) RecordEventProcessed(eventType string, success bool, latencyMs int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.metrics.EventsProcessed++
	s.metrics.EventsProcessedByType[eventType]++
	s.metrics.LastEventProcessedAt = &now

	if success {
		s.metrics.EventsProcessedSuccess++
	} else {
		s.metrics.EventsProcessedError++
		s.metrics.ProcessingErrors++
		if err != nil {
			errorType := getErrorType(err)
			s.metrics.ErrorByType[errorType]++
		}
		s.metrics.LastErrorAt = &now
	}

	// Update latency metrics
	s.metrics.ProcessingLatencySum += latencyMs
	s.metrics.ProcessingLatencyCount++
	if latencyMs > s.metrics.ProcessingLatencyMax {
		s.metrics.ProcessingLatencyMax = latencyMs
	}
}

// RecordFindingUpserted records that a finding was upserted
func (s *MetricsService) RecordFindingUpserted(isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics.FindingsUpserted++
	if isNew {
		s.metrics.FindingsCreated++
	} else {
		s.metrics.FindingsUpdated++
	}
}

// RecordControlNotAssessed records that a control could not be assessed, keyed
// by reason (no_measurements / nothing_in_scope / check_error).
func (s *MetricsService) RecordControlNotAssessed(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.metrics.ControlsNotAssessed == nil {
		s.metrics.ControlsNotAssessed = make(map[string]int64)
	}
	s.metrics.ControlsNotAssessed[reason]++
}

// RecordMeasurementExtractionError records a measurement check that failed to run.
func (s *MetricsService) RecordMeasurementExtractionError() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics.MeasurementExtractionErrors++
}

// RecordFindingMarkedInactive records that a finding was marked inactive
func (s *MetricsService) RecordFindingMarkedInactive() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics.FindingsMarkedInactive++
}

// RecordStateTransition records a finding state transition
func (s *MetricsService) RecordStateTransition(fromState, toState string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	transition := fromState + "->" + toState
	s.metrics.StateTransitions[transition]++

	// Track resurfaced findings
	if fromState == "INACTIVE" && toState == "ACTIVE" {
		s.metrics.ResurfacedFindings++
	}
}

// RecordNATSConnectionStatus updates NATS connection status
func (s *MetricsService) RecordNATSConnectionStatus(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if status == "reconnected" && s.metrics.NATSConnectionStatus == "disconnected" {
		s.metrics.NATSReconnectCount++
	}
	s.metrics.NATSConnectionStatus = status
}

// GetMetrics returns a snapshot of current metrics
func (s *MetricsService) GetMetrics() EventMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a deep copy
	metrics := EventMetrics{
		EventsPublished:             s.metrics.EventsPublished,
		EventsPublishedByType:       make(map[string]int64),
		EventsProcessed:             s.metrics.EventsProcessed,
		EventsProcessedByType:       make(map[string]int64),
		EventsProcessedSuccess:      s.metrics.EventsProcessedSuccess,
		EventsProcessedError:        s.metrics.EventsProcessedError,
		ProcessingLatencySum:        s.metrics.ProcessingLatencySum,
		ProcessingLatencyCount:      s.metrics.ProcessingLatencyCount,
		ProcessingLatencyMax:        s.metrics.ProcessingLatencyMax,
		FindingsUpserted:            s.metrics.FindingsUpserted,
		FindingsCreated:             s.metrics.FindingsCreated,
		FindingsUpdated:             s.metrics.FindingsUpdated,
		FindingsMarkedInactive:      s.metrics.FindingsMarkedInactive,
		StateTransitions:            make(map[string]int64),
		ControlsNotAssessed:         make(map[string]int64),
		MeasurementExtractionErrors: s.metrics.MeasurementExtractionErrors,
		ResurfacedFindings:          s.metrics.ResurfacedFindings,
		ProcessingErrors:            s.metrics.ProcessingErrors,
		ErrorByType:                 make(map[string]int64),
		NATSConnectionStatus:        s.metrics.NATSConnectionStatus,
		NATSReconnectCount:          s.metrics.NATSReconnectCount,
	}

	// Copy maps
	for k, v := range s.metrics.EventsPublishedByType {
		metrics.EventsPublishedByType[k] = v
	}
	for k, v := range s.metrics.EventsProcessedByType {
		metrics.EventsProcessedByType[k] = v
	}
	for k, v := range s.metrics.StateTransitions {
		metrics.StateTransitions[k] = v
	}
	for k, v := range s.metrics.ErrorByType {
		metrics.ErrorByType[k] = v
	}
	for k, v := range s.metrics.ControlsNotAssessed {
		metrics.ControlsNotAssessed[k] = v
	}

	// Copy timestamps
	if s.metrics.LastEventProcessedAt != nil {
		t := *s.metrics.LastEventProcessedAt
		metrics.LastEventProcessedAt = &t
	}
	if s.metrics.LastErrorAt != nil {
		t := *s.metrics.LastErrorAt
		metrics.LastErrorAt = &t
	}

	return metrics
}

// GetAverageLatency returns the average processing latency in milliseconds
func (s *MetricsService) GetAverageLatency() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.metrics.ProcessingLatencyCount == 0 {
		return 0
	}
	return float64(s.metrics.ProcessingLatencySum) / float64(s.metrics.ProcessingLatencyCount)
}

// GetErrorRate returns the error rate as a percentage (0-100)
func (s *MetricsService) GetErrorRate() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.metrics.EventsProcessed == 0 {
		return 0
	}
	return (float64(s.metrics.EventsProcessedError) / float64(s.metrics.EventsProcessed)) * 100
}

// Reset resets all metrics (useful for testing)
func (s *MetricsService) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics = &EventMetrics{
		EventsPublishedByType: make(map[string]int64),
		EventsProcessedByType: make(map[string]int64),
		ControlsNotAssessed:   make(map[string]int64),
		StateTransitions:      make(map[string]int64),
		ErrorByType:           make(map[string]int64),
		NATSConnectionStatus:  "disconnected",
	}
}

// getErrorType categorizes errors for metrics
func getErrorType(err error) string {
	if err == nil {
		return "unknown"
	}
	errStr := strings.ToLower(err.Error())

	// Categorize common error types
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
		return "timeout"
	}
	if strings.Contains(errStr, "connection") || strings.Contains(errStr, "connect") {
		return "connection"
	}
	if strings.Contains(errStr, "database") || strings.Contains(errStr, "sql") || strings.Contains(errStr, "postgres") {
		return "database"
	}
	if strings.Contains(errStr, "nats") {
		return "nats"
	}
	if strings.Contains(errStr, "not found") || strings.Contains(errStr, "no rows") {
		return "not_found"
	}
	return "other"
}
