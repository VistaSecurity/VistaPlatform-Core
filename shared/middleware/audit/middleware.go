package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Middleware provides audit logging functionality
type Middleware struct {
	config     *Config
	client     *Client
	natsClient *events.NATSClient
	batch      []*ActivityLogRequest
	batchMutex sync.Mutex
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// NewMiddleware creates a new audit logging middleware
func NewMiddleware(config *Config) *Middleware {
	if config == nil {
		config = DefaultConfig()
	}

	// Create HMAC signer for internal service auth
	var signer *serviceauth.Signer
	if secret := os.Getenv("INTERNAL_AUTH_SECRET"); secret != "" {
		signer = serviceauth.NewSigner(secret)
	}

	// Transport selection (mTLS vs plaintext, and the matching peer URL) is
	// shared with NewJobLogger — see NewClientForEnv.
	client := NewClientForEnv(
		config.AuditServiceURL,
		config.Timeout,
		config.RetryAttempts,
		signer,
		config.UseMTLS,
		config.ClientCertPath,
		config.ClientKeyPath,
		config.PlatformCACertPath,
	)

	mw := &Middleware{
		config:   config,
		client:   client,
		batch:    make([]*ActivityLogRequest, 0, config.BatchSize),
		stopChan: make(chan struct{}),
	}

	// Initialize NATS client for audit log publishing
	if config.UseNATS || os.Getenv("AUDIT_USE_NATS") == "true" {
		natsClient, err := events.NewNATSClient("")
		if err != nil {
			log.Printf("[AuditMiddleware] Warning: NATS unavailable, falling back to HTTP: %v", err)
		} else {
			mw.natsClient = natsClient
			log.Printf("[AuditMiddleware] NATS transport enabled for audit logs")
		}
	}

	// Start background batch processor
	if config.Enabled {
		mw.wg.Add(1)
		go mw.batchProcessor()
	}

	return mw
}

// LogRequest returns a Gin middleware function for automatic request logging
func (m *Middleware) LogRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.Enabled {
			c.Next()
			return
		}

		// Skip paths that shouldn't be audited
		for _, skipPath := range m.config.SkipPaths {
			if strings.HasPrefix(c.Request.URL.Path, skipPath) {
				c.Next()
				return
			}
		}

		startTime := time.Now()

		// The request body is deliberately NOT read here.
		//
		// This middleware used to io.ReadAll it and hand the handler a
		// NopCloser over the buffer, "to capture the request body if needed" —
		// and then never looked at the bytes. Nothing below reads them; the
		// record is built from the method, the path, the status, the query
		// string and the caller's identity. So the read bought nothing and cost
		// two things, both of which matter.
		//
		// It DEFEATED EVERY UPLOAD CAP IN THE CODEBASE. This runs as a global
		// r.Use() ahead of every handler, so by the time
		// sbom_handlers.go or device-interrogation's host-inventory intake gets
		// to wrap c.Request.Body in an http.MaxBytesReader, the whole body is
		// already resident. Those caps are derived, argued for and documented
		// (32 MiB, sized off the collector's own ceilings) and an attacker
		// paying no attention to them could still make the process hold
		// whatever the edge allows — 100 MiB, per concurrent request — before a
		// single handler line ran.
		//
		// And it made every request allocate its own size in heap whether or
		// not anything downstream wanted the body at all.
		//
		// No handler can depend on the buffering, because it only happened when
		// audit logging was enabled: the Enabled check above returns early, so a
		// deployment with AUDIT_LOGGING_ENABLED=false already had the original
		// body. A handler that needs to re-read its own body buffers it itself.
		c.Next()

		// Extract user context
		userID, _ := c.Get("userID")
		tenantID, _ := c.Get("tenantID")
		email, _ := c.Get("email")
		role, _ := c.Get("role")

		// Determine user type
		userType := "tenant"
		if role != nil {
			roleStr := role.(string)
			if strings.Contains(roleStr, "platform") || strings.Contains(roleStr, "admin") {
				userType = "platform"
			}
		}

		// Extract request ID if available
		requestID, _ := c.Get("request_id")
		var requestIDStr *string
		if requestID != nil {
			reqID := requestID.(string)
			requestIDStr = &reqID
		}

		// Determine event type and category
		eventType, eventCategory, action := m.determineEventType(c.Request.Method, c.Request.URL.Path)

		// Get IP address
		ipAddress := c.ClientIP()
		if ipAddress == "" {
			ipAddress = c.Request.RemoteAddr
		}

		// Build activity log
		logEntry := &ActivityLogRequest{
			TenantID:       m.getUUIDPtr(tenantID),
			UserID:         m.getUUIDPtr(userID),
			UserType:       userType,
			UserEmail:      m.getStringPtr(email),
			EventType:      eventType,
			EventCategory:  eventCategory,
			Action:         action,
			IPAddress:      &ipAddress,
			UserAgent:      m.getStringPtr(c.Request.UserAgent()),
			RequestID:      requestIDStr,
			Success:        c.Writer.Status() < 400,
			OccurredAt:     startTime,
			ComplianceTags: []string{}, // Will be assigned by audit-service
		}

		// Add error information if request failed
		if c.Writer.Status() >= 400 {
			errorMsg := http.StatusText(c.Writer.Status())
			logEntry.ErrorMessage = &errorMsg
			errorCode := fmt.Sprintf("HTTP_%d", c.Writer.Status())
			logEntry.ErrorCode = &errorCode
		}

		// Add metadata with enhanced data access tracking
		metadata := map[string]interface{}{
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"status_code": c.Writer.Status(),
			"duration_ms": time.Since(startTime).Milliseconds(),
		}

		// Add trace context for log correlation with distributed traces
		if traceID, exists := c.Get("trace_id"); exists {
			if tid, ok := traceID.(string); ok && tid != "" {
				metadata["trace_id"] = tid
			}
		}
		if spanID, exists := c.Get("span_id"); exists {
			if sid, ok := spanID.(string); ok && sid != "" {
				metadata["span_id"] = sid
			}
		}

		// Detect search operations
		if c.Request.URL.Query().Get("search") != "" || c.Request.URL.Query().Get("q") != "" {
			metadata["operation_type"] = "search"
			// Sanitize search query (don't log full query to avoid PII)
			searchQuery := c.Request.URL.Query().Get("search")
			if searchQuery == "" {
				searchQuery = c.Request.URL.Query().Get("q")
			}
			if len(searchQuery) > 50 {
				searchQuery = searchQuery[:50] + "..."
			}
			metadata["search_query_preview"] = searchQuery
		}

		// Detect export operations
		if strings.Contains(c.Request.URL.Path, "/export") || c.Request.URL.Query().Get("format") != "" {
			metadata["operation_type"] = "export"
			if format := c.Request.URL.Query().Get("format"); format != "" {
				metadata["export_format"] = format
			}
		}

		// Detect bulk operations (multiple IDs in body or query)
		if len(c.Request.URL.Query()["ids"]) > 1 || (c.Request.Method == "POST" && strings.Contains(c.Request.URL.Path, "/bulk")) {
			metadata["operation_type"] = "bulk_operation"
			if ids := c.Request.URL.Query()["ids"]; len(ids) > 0 {
				metadata["item_count"] = len(ids)
			}
		}

		// Check for impersonation and add actor context
		if isImpersonation, _ := c.Get("is_impersonation"); isImpersonation == true {
			impersonationInfo := map[string]interface{}{
				"is_impersonated": true,
			}
			if actorSub, exists := c.Get("act.sub"); exists {
				impersonationInfo["acting_admin_id"] = actorSub
			}
			if actorEmail, exists := c.Get("act.email"); exists {
				impersonationInfo["acting_admin_email"] = actorEmail
			}
			if actorReason, exists := c.Get("act.reason"); exists {
				impersonationInfo["impersonation_reason"] = actorReason
			}
			if actorIP, exists := c.Get("act.ip"); exists {
				impersonationInfo["actor_ip"] = actorIP
			}
			metadata["impersonation"] = impersonationInfo

			// Add tags for impersonated actions
			logEntry.Tags = append(logEntry.Tags, "impersonated_action")
			logEntry.ComplianceTags = append(logEntry.ComplianceTags, "admin_impersonation")

			// Mark as requiring attention for audit purposes
			logEntry.RequiresAttention = true
		}

		logEntry.Metadata = metadata

		// Add to batch (async, non-blocking)
		m.addToBatch(logEntry)
	}
}

// LogActivity allows explicit logging from handlers
func (m *Middleware) LogActivity(ctx context.Context, logEntry *ActivityLogRequest) error {
	if !m.config.Enabled {
		return nil
	}

	// An unstorable category is refused HERE, loudly, rather than three hops
	// away inside a batch flush nobody is watching.
	//
	// `event_category` has a CHECK in schema.sql, so a category outside the set
	// is rejected by Postgres with SQLSTATE 23514 — and every caller of this
	// method discards the returned error, so the whole failure was one line in
	// audit-service's log. Three of the asset-inventory build's own audit
	// events were written that way and never landed: the auto-accepted merge
	// ("data_modification") and both tenant settings handlers
	// ("configuration"). Each looked audited, and each wrote nothing.
	//
	// The log line is the point. Returning the error alone would change
	// nothing, because nobody reads it; LogConsumerEvent made the same check
	// and for the same stated reason.
	if !ValidEventCategory(logEntry.EventCategory) {
		err := fmt.Errorf("audit: event_category %q is not one of %v — audit.activity_logs would reject it",
			logEntry.EventCategory, EventCategories())
		log.Printf("[AuditMiddleware] DISCARDING %s: %v", logEntry.EventType, err)
		return err
	}

	// Set occurred_at if not set
	if logEntry.OccurredAt.IsZero() {
		logEntry.OccurredAt = time.Now()
	}

	// Add to batch (async, non-blocking)
	m.addToBatch(logEntry)
	return nil
}

// determineEventType derives the event type, category and action LogRequest
// records for a request. A custom EventTypeMap entry wins; otherwise the action
// comes from the method and the category from the service segment of the path
// (request_category.go), with the event type naming the resource —
// asset.assets.create — so a row says what it was about without its metadata.
func (m *Middleware) determineEventType(method, path string) (eventType, eventCategory, action string) {
	// Check custom mapping first
	key := method + ":" + path
	if eventType, ok := m.config.EventTypeMap[key]; ok {
		// Parse custom event type (format: "category.action" or "category.resource.action")
		parts := strings.Split(eventType, ".")
		if len(parts) >= 2 {
			eventCategory = parts[0]
			action = parts[len(parts)-1]
			return eventType, eventCategory, action
		}
	}

	// Default mapping based on HTTP method
	switch method {
	case "GET":
		action = "read"
	case "POST":
		action = "create"
	case "PUT", "PATCH":
		action = "update"
	case "DELETE":
		action = "delete"
	default:
		action = "unknown"
	}

	// Category from the path: decided by the service segment, with the resource
	// overrides in request_category.go. The event type names the resource.
	service, resource := splitServicePath(path)
	eventCategory = categoryForRequest(service, resource)
	if resource != "" {
		eventType = fmt.Sprintf("%s.%s.%s", eventCategory, resource, action)
	} else {
		eventType = fmt.Sprintf("%s.%s", eventCategory, action)
	}

	return eventType, eventCategory, action
}

// addToBatch adds a log entry to the batch (thread-safe)
func (m *Middleware) addToBatch(logEntry *ActivityLogRequest) {
	m.batchMutex.Lock()
	defer m.batchMutex.Unlock()

	m.batch = append(m.batch, logEntry)

	// Flush if batch is full
	if len(m.batch) >= m.config.BatchSize {
		go m.flushBatch()
	}
}

// flushBatch sends all batched logs via NATS (preferred) or HTTP (fallback)
func (m *Middleware) flushBatch() {
	m.batchMutex.Lock()
	if len(m.batch) == 0 {
		m.batchMutex.Unlock()
		return
	}

	// Copy batch and clear
	batch := make([]*ActivityLogRequest, len(m.batch))
	copy(batch, m.batch)
	m.batch = m.batch[:0]
	m.batchMutex.Unlock()

	// Publish via NATS if available
	if m.natsClient != nil && m.natsClient.IsConnected() {
		batchEvent := events.AuditBatchEvent{
			EventID:   uuid.New(),
			Count:     len(batch),
			Source:    m.config.ServiceName,
			Timestamp: time.Now(),
		}

		// Convert ActivityLogRequests to AuditEvents
		for _, entry := range batch {
			batchEvent.Entries = append(batchEvent.Entries, toAuditEvent(entry))
		}

		data, err := json.Marshal(batchEvent)
		if err == nil {
			pubErr := m.natsClient.Publish(events.SubjectAuditActivityLogs, data, batchEvent.EventID.String())
			if pubErr == nil {
				return // Success via NATS
			}
			log.Printf("[AuditMiddleware] NATS publish failed, falling back to HTTP: %v", pubErr)
		}
	}

	// Fallback: send via HTTP
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	for _, logEntry := range batch {
		_ = m.client.LogActivity(ctx, logEntry)
	}
}

// toAuditEvent converts an ActivityLogRequest into the NATS AuditEvent shape,
// preserving user_type so the audit-service subscriber can satisfy the
// activity_logs valid_user_type CHECK constraint ('tenant' or 'platform').
func toAuditEvent(entry *ActivityLogRequest) events.AuditEvent {
	success := entry.Success
	auditEvt := events.AuditEvent{
		EventID:       uuid.New(),
		UserType:      entry.UserType,
		Action:        entry.Action,
		Timestamp:     entry.OccurredAt,
		EventType:     entry.EventType,
		EventCategory: entry.EventCategory,
		Success:       &success,
	}
	if entry.TenantID != nil {
		auditEvt.TenantID = *entry.TenantID
	}
	if entry.UserID != nil {
		auditEvt.UserID = entry.UserID.String()
	}
	auditEvt.Resource = entry.EventCategory
	if entry.IPAddress != nil {
		auditEvt.IPAddress = *entry.IPAddress
	}
	if entry.UserAgent != nil {
		auditEvt.UserAgent = *entry.UserAgent
	}
	if entry.Metadata != nil {
		auditEvt.Metadata = entry.Metadata
		if sc, ok := entry.Metadata["status_code"]; ok {
			if code, ok := sc.(int); ok {
				auditEvt.StatusCode = code
			}
		}
		if dur, ok := entry.Metadata["duration_ms"]; ok {
			if d, ok := dur.(int64); ok {
				auditEvt.Duration = d
			}
		}
	}
	return auditEvt
}

// batchProcessor periodically flushes the batch
func (m *Middleware) batchProcessor() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.flushBatch()
		case <-m.stopChan:
			// Final flush on shutdown
			m.flushBatch()
			return
		}
	}
}

// Stop stops the middleware and flushes remaining logs
func (m *Middleware) Stop() {
	close(m.stopChan)
	m.wg.Wait()
	if m.natsClient != nil {
		m.natsClient.Close()
	}
}

// Helper functions
func (m *Middleware) getUUIDPtr(value interface{}) *uuid.UUID {
	if value == nil {
		return nil
	}
	if id, ok := value.(uuid.UUID); ok {
		return &id
	}
	if idStr, ok := value.(string); ok {
		if id, err := uuid.Parse(idStr); err == nil {
			return &id
		}
	}
	return nil
}

func (m *Middleware) getStringPtr(value interface{}) *string {
	if value == nil {
		return nil
	}
	if str, ok := value.(string); ok && str != "" {
		return &str
	}
	return nil
}
