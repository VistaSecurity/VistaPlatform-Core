package resourcetracking

import (
	"io"
	"strconv"
	"sync/atomic"
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

		// Count the request body as the HANDLER reads it. Do not read it here.
		//
		// This used to io.ReadAll the body and hand the handler a NopCloser
		// over the buffer. It runs as a global r.Use() ahead of every handler
		// in six services — auth, admin, cbom, compliance-engine,
		// inventory-service and sensor-manager — so every downstream
		// http.MaxBytesReader was already too late: the SBOM upload's 32 MiB
		// cap, the catalogue bundle's, /ask's and draft-controls' were all
		// applied to a body that was already resident, and the real bound was
		// the edge's 100 MiB per concurrent request.
		//
		// The audit middleware had the identical bug and the identical excuse
		// ("capture the request body if needed"); fixing only that one left
		// this one holding the door open, which is the shape of a fix that
		// compiles, passes its test and does nothing in production.
		//
		// A counting wrapper measures the same quantity without holding it: the
		// handler's own MaxBytesReader wraps THIS, so a refused upload is
		// counted as the few bytes it actually cost rather than as the whole
		// body somebody offered — which is also the more honest number for a
		// usage meter.
		counter := &countingBody{rc: c.Request.Body}
		if c.Request.Body != nil {
			c.Request.Body = counter
		}

		// Process the request
		c.Next()

		requestSize := counter.count()

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

		// Create resource metrics.
		//
		// Only two things here are actually measured per tenant: the request
		// itself, and the bytes of its payload. CPU, memory and storage are
		// left nil — not zero — because this process is a SHARED pod serving
		// every tenant and none of its resource use is attributable to the one
		// that happened to send this request. The fields previously carried
		// 0 for CPU and storage (read downstream as a measurement of zero) and
		// a memory figure synthesised from the length of the URL path.
		metric := ResourceMetrics{
			TenantID:        tenantID,
			ServiceName:     t.config.ServiceName,
			Timestamp:       start,
			APICalls:        1, // Each request is one API call
			DatabaseQueries: t.extractDatabaseQueries(c),
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

// extractDatabaseQueries returns the number of database queries a request made,
// or nil if nothing counted them.
//
// A service opts in by setting "db_queries" on the gin context. No service does
// today, so this returns nil for every request and database cost is reported as
// not measured — which is the truth.
//
// It used to guess instead, from the HTTP method and the LENGTH OF THE URL
// PATH: any GET to a path longer than ten characters "was" one query, any write
// "was" two. Every database_queries value the platform has ever stored came
// from that guess, and it was priced per query as though counted.
func (t *Tracker) extractDatabaseQueries(c *gin.Context) *int64 {
	queryCount, exists := c.Get("db_queries")
	if !exists {
		return nil
	}
	switch v := queryCount.(type) {
	case int:
		n := int64(v)
		return &n
	case int64:
		return &v
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return &n
		}
	}
	return nil
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

// countingBody tallies the bytes something pulls out of a request body without
// holding any of them.
//
// It is deliberately transparent: Read and Close forward to the wrapped
// ReadCloser and return its errors unchanged, so an http.MaxBytesReader a
// handler wraps around this still trips at exactly its own cap, and a client
// disconnect still surfaces as the error it is. A nil wrapped body counts zero
// and reads EOF, which is what a GET has.
//
// count is read after c.Next() returns, but the tally is atomic anyway: a
// handler is free to hand the body to a goroutine of its own, and a racing read
// of a plain int64 is a race whether or not anyone has written one yet.
type countingBody struct {
	rc io.ReadCloser
	n  int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.rc == nil {
		return 0, io.EOF
	}
	n, err := b.rc.Read(p)
	if n > 0 {
		atomic.AddInt64(&b.n, int64(n))
	}
	return n, err
}

func (b *countingBody) Close() error {
	if b.rc == nil {
		return nil
	}
	return b.rc.Close()
}

func (b *countingBody) count() int64 { return atomic.LoadInt64(&b.n) }
