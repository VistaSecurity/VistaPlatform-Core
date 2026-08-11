package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// GetHistoricalTrends handles GET /api/v1/monitoring-service/trends
// Returns historical metrics for trend analysis
func (s *Server) GetHistoricalTrends(c *gin.Context) {
	serviceName := c.Query("service_name")
	metricType := c.DefaultQuery("metric_type", "latency_p95") // latency_p50, latency_p95, latency_p99, error_rate, throughput
	windowStr := c.DefaultQuery("window", "1h")                // 1m, 1h, 1d
	startStr := c.Query("start")
	endStr := c.Query("end")

	// Parse time window
	var windowDuration int
	switch windowStr {
	case "1m":
		windowDuration = 60
	case "1h":
		windowDuration = 3600
	case "1d":
		windowDuration = 86400
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid window parameter. Must be '1m', '1h', or '1d'",
		})
		return
	}

	// Parse time range (default to last 24 hours)
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	if startStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startStr); err == nil {
			startTime = parsed
		}
	}
	if endStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endStr); err == nil {
			endTime = parsed
		}
	}

	// Validate metric type
	validMetrics := map[string]bool{
		"latency_p50": true,
		"latency_p95": true,
		"latency_p99": true,
		"error_rate":  true,
		"throughput":  true,
	}
	if !validMetrics[metricType] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid metric_type. Must be 'latency_p50', 'latency_p95', 'latency_p99', 'error_rate', or 'throughput'",
		})
		return
	}

	trends, err := s.metricsService.GetHistoricalTrends(serviceName, metricType, windowDuration, startTime, endTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to query historical trends",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"service_name": serviceName,
		"metric_type":  metricType,
		"window":       windowStr,
		"start_time":   startTime,
		"end_time":     endTime,
		"trends":       trends,
		"count":        len(trends),
	})
}
