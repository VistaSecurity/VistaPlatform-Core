package handlers

import (
	"context"
	"log"
	"strings"
	"time"

	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// platformAuditor is the package-level emitter used by the platform RBAC
// handlers to record high-value security events (role and platform-user
// mutations). It is wired once from NewServer via InitializePlatformAuditor.
// When it is nil (e.g. in unit tests that don't initialize it) the recording
// helpers are safe no-ops.
var platformAuditor *PlatformAuditEmitter

// PlatformAuditEmitter records platform-admin actions in audit-service's
// audit.activity_logs. Platform actions carry no tenant: they are written with
// user_type="platform" and a NULL tenant_id.
//
// It posts over the proven HTTP ingest path
// (POST /api/v1/audit-service/activity-logs), HMAC-signed for internal service
// auth, and deliberately does NOT use the NATS transport. The NATS audit path
// (shared/middleware/audit.flushBatch → audit-service subscriber) drops the
// user_type field during the ActivityLogRequest→AuditEvent conversion and the
// subscriber then defaults it to an invalid value, so platform events published
// that way fail the activity_logs valid_user_type CHECK ('tenant'|'platform')
// and never persist. The direct HTTP client preserves user_type..
type PlatformAuditEmitter struct {
	client  *audit.Client
	enabled bool
}

// AuditEmitterConfig carries the bits NewPlatformAuditEmitter needs from the
// service configuration. AuditServiceURL is the plaintext peer URL
// (e.g. http://audit-service:8080); when UseMTLS is set the emitter rewrites it
// to https/8443 and attaches the platform client certificate, mirroring
// shared/middleware/audit.NewMiddleware.
type AuditEmitterConfig struct {
	AuditServiceURL    string
	InternalAuthSecret string
	UseMTLS            bool
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
	Enabled            bool
}

// PlatformAuditEntry describes a single platform-admin action to record.
type PlatformAuditEntry struct {
	EventType     string                 // dotted type, e.g. "platform_role.created"
	Action        string                 // verb, e.g. "create"
	EventCategory string                 // must satisfy valid_event_category (e.g. "system", "user")
	ResourceType  string                 // e.g. "platform_role", "platform_user"
	ResourceID    string                 // affected resource UUID (string); parsed best-effort
	Metadata      map[string]interface{} // optional extra context (permission_ids, etc.)
}

// InitializePlatformAuditor constructs the package-level platform audit emitter.
// Call once from NewServer.
func InitializePlatformAuditor(cfg AuditEmitterConfig) {
	platformAuditor = NewPlatformAuditEmitter(cfg)
}

// NewPlatformAuditEmitter builds an emitter, replicating the mTLS/URL handling
// of shared/middleware/audit.NewMiddleware so it reaches audit-service the same
// way the request-logging middleware does.
func NewPlatformAuditEmitter(cfg AuditEmitterConfig) *PlatformAuditEmitter {
	var signer *serviceauth.Signer
	if cfg.InternalAuthSecret != "" {
		signer = serviceauth.NewSigner(cfg.InternalAuthSecret)
	}

	url := cfg.AuditServiceURL
	if cfg.UseMTLS {
		url = strings.Replace(url, "http://", "https://", 1)
		url = strings.Replace(url, ":8080", ":8443", 1)
	}

	const timeout = 5 * time.Second
	const retries = 2

	var client *audit.Client
	if cfg.UseMTLS && cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" && cfg.PlatformCACertPath != "" {
		httpClient, err := sharedhttp.NewMTLSClient(cfg.ClientCertPath, cfg.ClientKeyPath, cfg.PlatformCACertPath)
		if err != nil {
			log.Printf("[platform-audit] mTLS client setup failed, using plain HTTP: %v", err)
			client = audit.NewClientWithSigner(url, timeout, retries, signer)
		} else {
			httpClient.Timeout = timeout
			client = audit.NewClientWithHTTPClientAndSigner(url, httpClient, retries, signer)
		}
	} else {
		client = audit.NewClientWithSigner(url, timeout, retries, signer)
	}

	return &PlatformAuditEmitter{client: client, enabled: cfg.Enabled}
}

// Emit records a platform-admin mutation. It is non-blocking: the audit POST
// runs in a background goroutine and a failure is logged, never surfaced to the
// caller — an audit hiccup must not fail an admin operation. Call it AFTER the
// mutation has succeeded. The actor (platform user id + email) and request
// metadata are read from the gin context, so all context access happens
// synchronously before the goroutine starts.
func (e *PlatformAuditEmitter) Emit(c *gin.Context, entry PlatformAuditEntry) {
	if e == nil || !e.enabled || e.client == nil {
		return
	}

	req := &audit.ActivityLogRequest{
		UserType:      "platform",
		EventType:     entry.EventType,
		EventCategory: entry.EventCategory,
		Action:        entry.Action,
		Success:       true,
		OccurredAt:    time.Now(),
		Metadata:      entry.Metadata,
	}

	// Actor: the authenticated platform user. AuthMiddleware + StringifyUserID
	// place the id under "userID" and the email under "email".
	if actorID := c.GetString("userID"); actorID != "" && actorID != "system" {
		if uid, err := uuid.Parse(actorID); err == nil {
			req.UserID = &uid
		}
	}
	if email := c.GetString("email"); email != "" {
		req.UserEmail = &email
	}

	if entry.ResourceType != "" {
		rt := entry.ResourceType
		req.ResourceType = &rt
	}
	if entry.ResourceID != "" {
		if rid, err := uuid.Parse(entry.ResourceID); err == nil {
			req.ResourceID = &rid
		}
	}
	if ip := c.ClientIP(); ip != "" {
		req.IPAddress = &ip
	}
	if ua := c.Request.UserAgent(); ua != "" {
		req.UserAgent = &ua
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := e.client.LogActivity(ctx, req); err != nil {
			log.Printf("[platform-audit] failed to record %q: %v", entry.EventType, err)
		}
	}()
}

// recordPlatformAudit is a nil-safe convenience wrapper around the package-level
// emitter so handlers can record an action in a single line.
func recordPlatformAudit(c *gin.Context, entry PlatformAuditEntry) {
	platformAuditor.Emit(c, entry)
}

// RecordPlatformAudit is the exported form of recordPlatformAudit, for handlers
// that live outside this package. The emitter is package-level state wired once
// from NewServer, so out-of-package callers cannot hold their own — they go
// through here. Used by the Enterprise billing handlers (ee/billingapi) to
// record support-granted plan changes.
func RecordPlatformAudit(c *gin.Context, entry PlatformAuditEntry) {
	recordPlatformAudit(c, entry)
}
