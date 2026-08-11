package resourcetracking

import (
	"bytes"
	"io"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ResponseWriter wraps gin.ResponseWriter to capture response size
type ResponseWriter struct {
	gin.ResponseWriter
	size int
}

// Write captures the size of written data
func (w *ResponseWriter) Write(data []byte) (int, error) {
	size, err := w.ResponseWriter.Write(data)
	w.size += size
	return size, err
}

// WriteString captures the size of written string data
func (w *ResponseWriter) WriteString(s string) (int, error) {
	size, err := w.ResponseWriter.WriteString(s)
	w.size += size
	return size, err
}

// Size returns the total size of data written
func (w *ResponseWriter) Size() int {
	return w.size
}

// Tracker holds the batch processor and configuration
type Tracker struct {
	processor *BatchProcessor
	config    *Config
	logger    *logrus.Logger
}

// NewTracker creates a new resource tracker
func NewTracker(config *Config, logger *logrus.Logger) *Tracker {
	if logger == nil {
		logger = logrus.New()
	}

	return &Tracker{
		processor: NewBatchProcessor(config, logger),
		config:    config,
		logger:    logger,
	}
}

// Middleware returns a Gin middleware function for resource tracking
func (t *Tracker) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !t.config.Enabled {
			c.Next()
			return
		}

		// Skip health check endpoints and lightweight SSO endpoints
		if c.Request.URL.Path == "/health" ||
			c.Request.URL.Path == "/api/v1/health" ||
			c.Request.URL.Path == "/api/v1/auth-service/auth/sso/providers" ||
			c.Request.URL.Path == "/auth/sso/providers" {
			c.Next()
			return
		}

		start := time.Now()

		// Wrap the response writer to capture response size
		writer := &ResponseWriter{
			ResponseWriter: c.Writer,
			size:           0,
		}
		c.Writer = writer

		// Capture request body size
		requestSize := int64(0)
		if c.Request.Body != nil {
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err == nil {
				requestSize = int64(len(bodyBytes))
				// Restore the request body
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		// Process the request
		c.Next()

		// Calculate metrics
		duration := time.Since(start)
		responseSize := int64(writer.Size())
		totalNetworkBytes := requestSize + responseSize

		// Extract tenant ID from context or JWT
		tenantID := t.extractTenantID(c)
		if tenantID == uuid.Nil {
			// No tenant context (unauthenticated / internal-system request).
			// Skip recording rather than attributing usage to a placeholder
			// tenant — misattributed usage pollutes per-tenant usage
			// monitoring and entitlement enforcement.
			return
		}

		// Create resource metrics
		metric := ResourceMetrics{
			TenantID:        tenantID,
			ServiceName:     t.config.ServiceName,
			Timestamp:       start,
			APICalls:        1,                           // Each request is one API call
			DatabaseQueries: t.extractDatabaseQueries(c), // This would need to be implemented per service
			MemoryUsageMB:   t.estimateMemoryUsage(c),    // Rough estimate
			CPUUsagePercent: 0,                           // Would need system metrics
			StorageUsedMB:   0,                           // Would need storage metrics
			NetworkBytes:    totalNetworkBytes,
			ResponseTimeMs:  duration.Milliseconds(),
			StatusCode:      c.Writer.Status(),
			Endpoint:        c.Request.URL.Path,
			Method:          c.Request.Method,
		}

		// Add metric to batch processor
		t.processor.AddMetric(metric)

		// Log the request for debugging
		t.logger.WithFields(logrus.Fields{
			"tenant_id":     tenantID,
			"service":       t.config.ServiceName,
			"method":        c.Request.Method,
			"endpoint":      c.Request.URL.Path,
			"status_code":   c.Writer.Status(),
			"response_time": duration.Milliseconds(),
			"network_bytes": totalNetworkBytes,
		}).Info("Resource metric recorded")
	}
}

// extractTenantID extracts tenant ID from various sources
func (t *Tracker) extractTenantID(c *gin.Context) uuid.UUID {
	// Try to get from context. The shared auth middleware sets the tenant under
	// CtxKeyTenantID ("tenantID", camelCase) — reading "tenant_id" here never
	// matched, so every authenticated request silently fell through to the
	// fallback below.
	if tenantID, exists := c.Get("tenantID"); exists {
		if id, ok := tenantID.(uuid.UUID); ok {
			return id
		}
		if idStr, ok := tenantID.(string); ok {
			if id, err := uuid.Parse(idStr); err == nil {
				return id
			}
		}
	}

	// Try to get from JWT claims
	if claims, exists := c.Get("jwt_claims"); exists {
		if claimsMap, ok := claims.(map[string]interface{}); ok {
			if tenantIDStr, exists := claimsMap["tenant_id"]; exists {
				if idStr, ok := tenantIDStr.(string); ok {
					if id, err := uuid.Parse(idStr); err == nil {
						return id
					}
				}
			}
		}
	}

	// Try to get from header
	if tenantIDHeader := c.GetHeader("X-Tenant-ID"); tenantIDHeader != "" {
		if id, err := uuid.Parse(tenantIDHeader); err == nil {
			return id
		}
	}

	// Try to get from query parameter
	if tenantIDQuery := c.Query("tenant_id"); tenantIDQuery != "" {
		if id, err := uuid.Parse(tenantIDQuery); err == nil {
			return id
		}
	}

	// No tenant context found. Return uuid.Nil so the caller skips recording.
	// NEVER fall back to a hardcoded tenant: it silently misattributes every
	// unauthenticated/system request, and the previous hardcoded demo-corp UUID
	// was stale after a re-seed (the tenant no longer existed), which surfaced as
	// a phantom tenant_id in logs and metrics.
	return uuid.Nil
}

// extractDatabaseQueries attempts to extract database query count from context
// This would need to be implemented per service based on their database usage patterns
func (t *Tracker) extractDatabaseQueries(c *gin.Context) int {
	// Try to get from context (services can set this)
	if queryCount, exists := c.Get("db_queries"); exists {
		if count, ok := queryCount.(int); ok {
			return count
		}
		if countStr, ok := queryCount.(string); ok {
			if count, err := strconv.Atoi(countStr); err == nil {
				return count
			}
		}
	}

	// Default estimate based on endpoint patterns
	endpoint := c.Request.URL.Path
	method := c.Request.Method

	// Rough estimates based on typical patterns
	switch {
	case method == "GET" && len(endpoint) > 10:
		return 1 // Most GET requests do 1 query
	case method == "POST" || method == "PUT" || method == "PATCH":
		return 2 // Write operations typically do 2+ queries
	case method == "DELETE":
		return 1 // Delete operations typically do 1 query
	default:
		return 1
	}
}

// estimateMemoryUsage provides a rough estimate of memory usage
func (t *Tracker) estimateMemoryUsage(c *gin.Context) int {
	// This is a very rough estimate
	// In a real implementation, you'd want to use actual memory metrics

	// Base memory usage
	baseMemory := 10 // MB

	// Add based on request size
	requestSize := c.Request.ContentLength
	if requestSize > 0 {
		baseMemory += int(requestSize / (1024 * 1024)) // Convert to MB
	}

	// Add based on response size
	responseSize := c.Writer.Size()
	if responseSize > 0 {
		baseMemory += responseSize / (1024 * 1024) // Convert to MB
	}

	// Add based on endpoint complexity
	endpoint := c.Request.URL.Path
	switch {
	case len(endpoint) > 50: // Complex endpoints
		baseMemory += 5
	case len(endpoint) > 20: // Medium complexity
		baseMemory += 2
	default: // Simple endpoints
		baseMemory += 1
	}

	return baseMemory
}

// Stop stops the tracker and flushes any remaining metrics
func (t *Tracker) Stop() {
	t.processor.Stop()
}

// Middleware is a convenience function that creates a new tracker and returns its middleware
func Middleware(config *Config) gin.HandlerFunc {
	tracker := NewTracker(config, nil)
	return tracker.Middleware()
}
