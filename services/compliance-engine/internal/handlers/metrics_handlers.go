package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// MetricsHandlers handles metrics-related endpoints
type MetricsHandlers struct {
	metricsService *services.MetricsService
}

// NewMetricsHandlers creates a new metrics handler
func NewMetricsHandlers(metricsService *services.MetricsService) *MetricsHandlers {
	return &MetricsHandlers{
		metricsService: metricsService,
	}
}

// GetMetrics returns current event processing metrics
// This endpoint is used by monitoring-service to scrape metrics
func (h *MetricsHandlers) GetMetrics(c *gin.Context) {
	metrics := h.metricsService.GetMetrics()

	// Calculate derived metrics
	avgLatency := h.metricsService.GetAverageLatency()
	errorRate := h.metricsService.GetErrorRate()

	// Format response in a way that's easy for monitoring-service to consume
	response := gin.H{
		"service":   "compliance-engine",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"metrics": gin.H{
			// Event metrics
			"events_published":         metrics.EventsPublished,
			"events_published_by_type": metrics.EventsPublishedByType,
			"events_processed":         metrics.EventsProcessed,
			"events_processed_by_type": metrics.EventsProcessedByType,
			"events_processed_success": metrics.EventsProcessedSuccess,
			"events_processed_error":   metrics.EventsProcessedError,

			// Latency metrics
			"processing_latency_avg_ms": avgLatency,
			"processing_latency_max_ms": metrics.ProcessingLatencyMax,
			"processing_latency_sum_ms": metrics.ProcessingLatencySum,
			"processing_latency_count":  metrics.ProcessingLatencyCount,

			// Finding metrics
			"findings_upserted":        metrics.FindingsUpserted,
			"findings_created":         metrics.FindingsCreated,
			"findings_updated":         metrics.FindingsUpdated,
			"findings_marked_inactive": metrics.FindingsMarkedInactive,

			// State transition metrics
			"state_transitions":   metrics.StateTransitions,
			"resurfaced_findings": metrics.ResurfacedFindings,

			// Error metrics
			"processing_errors":  metrics.ProcessingErrors,
			"error_rate_percent": errorRate,
			"error_by_type":      metrics.ErrorByType,

			// NATS connection metrics
			"nats_connection_status": metrics.NATSConnectionStatus,
			"nats_reconnect_count":   metrics.NATSReconnectCount,

			// Timestamps
			"last_event_processed_at": nil,
			"last_error_at":           nil,
		},
	}

	// Add timestamps if available
	if metrics.LastEventProcessedAt != nil {
		response["metrics"].(gin.H)["last_event_processed_at"] = metrics.LastEventProcessedAt.UTC().Format(time.RFC3339)
	}
	if metrics.LastErrorAt != nil {
		response["metrics"].(gin.H)["last_error_at"] = metrics.LastErrorAt.UTC().Format(time.RFC3339)
	}

	c.JSON(http.StatusOK, response)
}

// GetMetricsHealth returns a simplified health check based on metrics
// Used for quick health assessment
func (h *MetricsHandlers) GetMetricsHealth(c *gin.Context) {
	metrics := h.metricsService.GetMetrics()
	errorRate := h.metricsService.GetErrorRate()
	avgLatency := h.metricsService.GetAverageLatency()

	// Determine health status
	status := "healthy"
	issues := []string{}

	// Check error rate
	if errorRate > 1.0 {
		status = "degraded"
		issues = append(issues, "High error rate")
	}

	// Check latency
	if avgLatency > 5000 { // 5 seconds
		status = "degraded"
		issues = append(issues, "High processing latency")
	}

	// Check NATS connection
	if metrics.NATSConnectionStatus != "connected" {
		status = "unhealthy"
		issues = append(issues, "NATS connection issue")
	}

	// Check if no events processed recently (might indicate a problem)
	if metrics.LastEventProcessedAt != nil {
		timeSinceLastEvent := time.Since(*metrics.LastEventProcessedAt)
		if timeSinceLastEvent > 10*time.Minute && metrics.EventsProcessed > 0 {
			status = "degraded"
			issues = append(issues, "No events processed recently")
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":             status,
		"issues":             issues,
		"error_rate_percent": errorRate,
		"avg_latency_ms":     avgLatency,
		"nats_status":        metrics.NATSConnectionStatus,
	})
}
