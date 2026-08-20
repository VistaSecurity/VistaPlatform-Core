package events

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// EventType represents the type of event
type EventType string

const (
	EventTypeAssetChanged       EventType = "asset.changed"
	EventTypeAssetDeleted       EventType = "asset.deleted"
	EventTypeCertificateChanged EventType = "certificate.changed"
	EventTypeBulkAssetChanged   EventType = "bulk.asset.changed"
)

// ChangeType represents the type of change
type ChangeType string

const (
	ChangeTypeCreated ChangeType = "created"
	ChangeTypeUpdated ChangeType = "updated"
	ChangeTypeDeleted ChangeType = "deleted"
)

// --- Compliance / Asset Events ---

// AssetChangedEvent represents an asset creation or update event
type AssetChangedEvent struct {
	EventID    uuid.UUID              `json:"event_id"`
	EventType  EventType              `json:"event_type"`
	TenantID   uuid.UUID              `json:"tenant_id"`
	AssetID    uuid.UUID              `json:"asset_id"`
	ChangeType ChangeType             `json:"change_type"`
	Timestamp  time.Time              `json:"timestamp"`
	Source     string                 `json:"source"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// AssetDeletedEvent represents an asset deletion event
type AssetDeletedEvent struct {
	EventID   uuid.UUID              `json:"event_id"`
	EventType EventType              `json:"event_type"`
	TenantID  uuid.UUID              `json:"tenant_id"`
	AssetID   uuid.UUID              `json:"asset_id"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// CertificateChangedEvent represents a certificate creation, update, or expiration event
type CertificateChangedEvent struct {
	EventID       uuid.UUID              `json:"event_id"`
	EventType     EventType              `json:"event_type"`
	TenantID      uuid.UUID              `json:"tenant_id"`
	CertificateID uuid.UUID              `json:"certificate_id"`
	AssetID       *uuid.UUID             `json:"asset_id,omitempty"`
	ChangeType    ChangeType             `json:"change_type"`
	Timestamp     time.Time              `json:"timestamp"`
	Source        string                 `json:"source"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// BulkAssetChangedEvent represents multiple asset changes (for agent batches)
type BulkAssetChangedEvent struct {
	EventID    uuid.UUID              `json:"event_id"`
	EventType  EventType              `json:"event_type"`
	TenantID   uuid.UUID              `json:"tenant_id"`
	AssetIDs   []uuid.UUID            `json:"asset_ids"`
	ChangeType ChangeType             `json:"change_type"`
	Timestamp  time.Time              `json:"timestamp"`
	Source     string                 `json:"source"`
	Count      int                    `json:"count"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// --- Audit Events ---

// AuditEvent represents an activity log entry published to NATS
type AuditEvent struct {
	EventID    uuid.UUID              `json:"event_id"`
	TenantID   uuid.UUID              `json:"tenant_id"`
	UserID     string                 `json:"user_id,omitempty"`
	UserType   string                 `json:"user_type,omitempty"` // "tenant" or "platform" (activity_logs CHECK constraint)
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	StatusCode int                    `json:"status_code"`
	Duration   int64                  `json:"duration_ms"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`

	// EventType/EventCategory/Success carry the fields an explicitly-authored
	// audit entry sets, which the envelope previously dropped: the consumer then
	// rebuilt event_type from Action and re-derived success from StatusCode.
	// For a hand-logged event that carries no HTTP status, StatusCode is 0, so
	// "success = StatusCode < 400" turned every explicitly-failed entry (a failed
	// login, most of all) into a SUCCESS on the way through NATS — and lost the
	// event type any detection rule matches on. All three are omitempty, so an
	// older publisher's payload decodes unchanged and the consumer falls back to
	// the derived values.
	EventType     string `json:"event_type,omitempty"`
	EventCategory string `json:"event_category,omitempty"`
	Success       *bool  `json:"success,omitempty"`
}

// AuditBatchEvent wraps multiple audit entries for batch publishing
type AuditBatchEvent struct {
	EventID   uuid.UUID    `json:"event_id"`
	Entries   []AuditEvent `json:"entries"`
	Count     int          `json:"count"`
	Source    string       `json:"source"`
	Timestamp time.Time    `json:"timestamp"`
}

// --- Notification Events ---

// NotificationEvent represents a notification request published to NATS
type NotificationEvent struct {
	EventID     uuid.UUID              `json:"event_id"`
	TenantID    uuid.UUID              `json:"tenant_id"`
	AlertSource string                 `json:"alert_source"`
	AlertType   string                 `json:"alert_type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PlatformAlertTenantID is the reserved sentinel tenant that owns
// platform-track stateful alerts (service_down, metric_threshold,
// tenant_health_degraded, …). Platform-track alerts are not tenant-scoped, but
// the alerts table's tenant_id is NOT NULL and RLS-isolated, so platform
// detectors raise under this well-known sentinel and platform-admin reads scope
// to it. There is intentionally NO tenants row for this id (alerts.tenant_id has
// no FK) — it exists only as an RLS partition key. Do not change this value once
// alerts have been written under it.
//
// It lives here, beside AlertRaiseEvent, because producers of the alerts.raise
// rail live in several services (monitoring-service publishes platform-track
// raises) and cannot import compliance-engine's internal packages.
var PlatformAlertTenantID = uuid.MustParse("11111111-1111-1111-1111-111111111111")

// AlertRaiseEvent opens or escalates a stateful alert (subject alerts.raise).
// The alert engine dedupes on (tenant_id, alert_type, subject_id): no open
// alert → opened at Severity; open alert at lower severity → escalated; open
// alert at same/higher severity → last-seen touch only (no notification).
type AlertRaiseEvent struct {
	EventID      uuid.UUID              `json:"event_id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	AlertType    string                 `json:"alert_type"`
	Source       string                 `json:"source"`
	SubjectType  string                 `json:"subject_type,omitempty"`
	SubjectID    *uuid.UUID             `json:"subject_id,omitempty"`
	SubjectLabel string                 `json:"subject_label,omitempty"`
	Severity     string                 `json:"severity"`
	Title        string                 `json:"title"`
	Message      string                 `json:"message"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// AlertResolveEvent auto-resolves an open alert (subject alerts.resolve).
// Observation is the system's evidence the condition cleared — it becomes the
// resolved event's details and the alert's resolution_observation.
type AlertResolveEvent struct {
	EventID     uuid.UUID              `json:"event_id"`
	TenantID    uuid.UUID              `json:"tenant_id"`
	AlertType   string                 `json:"alert_type"`
	SubjectID   *uuid.UUID             `json:"subject_id,omitempty"`
	Observation map[string]interface{} `json:"observation,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// --- Job Events ---

// DiscoveryJobEvent represents a discovery job published to NATS
type DiscoveryJobEvent struct {
	EventID   uuid.UUID `json:"event_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	JobID     string    `json:"job_id"`
	JobType   string    `json:"job_type,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ReportJobEvent represents a report generation job published to NATS
type ReportJobEvent struct {
	EventID    uuid.UUID              `json:"event_id"`
	TenantID   uuid.UUID              `json:"tenant_id"`
	ReportID   string                 `json:"report_id"`
	ReportType string                 `json:"report_type"`
	Format     string                 `json:"format"`
	Timestamp  time.Time              `json:"timestamp"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// DeviceJobEvent represents a device interrogation job published to NATS
type DeviceJobEvent struct {
	EventID   uuid.UUID `json:"event_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	JobID     string    `json:"job_id"`
	JobType   string    `json:"job_type"`
	Timestamp time.Time `json:"timestamp"`
}

// WebhookJobEvent represents a webhook delivery job published to NATS
type WebhookJobEvent struct {
	EventID        uuid.UUID `json:"event_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	EventType      string    `json:"event_type"`
	BillingEventID string    `json:"billing_event_id"`
	Timestamp      time.Time `json:"timestamp"`
}

// --- PCAP Job Events ---

// PcapJobEvent represents a PCAP file processing job published to NATS
type PcapJobEvent struct {
	EventID          uuid.UUID `json:"event_id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	JobID            uuid.UUID `json:"job_id"`
	FilePath         string    `json:"file_path"`
	OriginalFilename string    `json:"original_filename"`
	FileSizeBytes    int64     `json:"file_size_bytes"`
	Timestamp        time.Time `json:"timestamp"`
}

// NewPcapJobEvent creates a new PCAP processing job event
func NewPcapJobEvent(tenantID, jobID uuid.UUID, filePath, originalFilename string, fileSizeBytes int64) *PcapJobEvent {
	return &PcapJobEvent{
		EventID:          uuid.New(),
		TenantID:         tenantID,
		JobID:            jobID,
		FilePath:         filePath,
		OriginalFilename: originalFilename,
		FileSizeBytes:    fileSizeBytes,
		Timestamp:        time.Now(),
	}
}

// --- Metrics Events ---

// MetricsEvent represents a system metrics snapshot published to NATS
type MetricsEvent struct {
	EventID   uuid.UUID              `json:"event_id"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Metrics   map[string]interface{} `json:"metrics"`
}

// --- Inventory Lifecycle Events ---

// LifecycleEnvelope is the standard envelope for inventory lifecycle events.
// Mirrors the Envelope defined in inventory-service/internal/events.
type LifecycleEnvelope struct {
	EventID   uuid.UUID       `json:"event_id"`
	EventType string          `json:"event_type"`
	TenantID  uuid.UUID       `json:"tenant_id"`
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

// AssetDiscoveredPayload is the payload for asset.discovered events.
type AssetDiscoveredPayload struct {
	AssetID   uuid.UUID `json:"asset_id"`
	Hostname  *string   `json:"hostname,omitempty"`
	IPAddress *string   `json:"ip_address,omitempty"`
	Port      *int      `json:"port,omitempty"`
	Source    string    `json:"source"`
}

// AssetEnrichedPayload is the payload for asset.enriched events.
type AssetEnrichedPayload struct {
	AssetID          uuid.UUID  `json:"asset_id"`
	LocationID       *uuid.UUID `json:"location_id,omitempty"`
	SegmentID        *uuid.UUID `json:"segment_id,omitempty"`
	Environment      *string    `json:"environment,omitempty"`
	ServiceName      *string    `json:"service_name,omitempty"`
	EnrichmentSource string     `json:"enrichment_source,omitempty"`
}

// AssetRiskChangedPayload is the payload for asset.risk_changed events.
type AssetRiskChangedPayload struct {
	AssetID      uuid.UUID `json:"asset_id"`
	RiskLevel    string    `json:"risk_level"`
	RiskScore    int       `json:"risk_score"`
	ChangeSource string    `json:"change_source,omitempty"`
}

// CryptoConfigurationAddedPayload is the payload for crypto.configuration_added events.
type CryptoConfigurationAddedPayload struct {
	AssetID                uuid.UUID `json:"asset_id"`
	CryptoImplementationID uuid.UUID `json:"crypto_implementation_id"`
	Protocol               string    `json:"protocol"`
	ProtocolVersion        *string   `json:"protocol_version,omitempty"`
	RiskScore              int       `json:"risk_score"`
}

// CertificateExpiringPayload is the payload for certificate.expiring events.
type CertificateExpiringPayload struct {
	CertificateID uuid.UUID `json:"certificate_id"`
	AssetID       uuid.UUID `json:"asset_id"`
	CommonName    *string   `json:"common_name,omitempty"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
}

// --- NATS Subjects ---

const (
	// Audit subjects. Job-execution logging is HTTP-only (audit-service's
	// /job-execution-logs API) — there is deliberately no subject for it: the
	// audit.job-execution rail was published to for years with no subscriber.
	SubjectAuditActivityLogs = "audit.activity-logs"

	// Notification subjects
	SubjectNotificationsSend = "notifications.send"

	// Alert lifecycle subjects (). Any service raises/escalates a
	// stateful alert by publishing alerts.raise; the alert engine
	// (compliance-engine) dedupes to one open alert per (tenant, type,
	// subject), appends evidence events, and fans out notifications through
	// the normal rails on open + severity increase. alerts.resolve carries the
	// system's observation that a condition cleared (auto-resolve).
	SubjectAlertsRaise   = "alerts.raise"
	SubjectAlertsResolve = "alerts.resolve"

	// Compliance subjects (ADR-0014 evaluation engine). Captured by the COMPLIANCE
	// stream's "compliance.>" subject. Carries a per-tenant reconcile job.
	SubjectComplianceReconcileTenant = "compliance.reconcile.tenant"

	// Job subjects
	SubjectDiscoveryJobsSubmit = "discovery.jobs.submit"
	SubjectReportJobsSubmit    = "report.jobs.submit"
	SubjectDeviceJobsSubmit    = "device.jobs.submit"
	SubjectWebhookJobsSubmit   = "webhooks.submit"
	SubjectPcapJobsProcess     = "pcap.jobs.process"

	// Metrics subjects
	SubjectMetricsSystem = "metrics.system"

	// Inventory lifecycle subjects
	SubjectLifecycleAssetDiscovered     = "inventory.lifecycle.asset.discovered"
	SubjectLifecycleAssetEnriched       = "inventory.lifecycle.asset.enriched"
	SubjectLifecycleAssetRiskChanged    = "inventory.lifecycle.asset.risk_changed"
	SubjectLifecycleCryptoConfigAdded   = "inventory.lifecycle.crypto.configuration_added"
	SubjectLifecycleCertificateExpiring = "inventory.lifecycle.certificate.expiring"
)

// --- Factory Functions ---

// NewAssetChangedEvent creates a new asset changed event
func NewAssetChangedEvent(tenantID, assetID uuid.UUID, changeType ChangeType, source string) *AssetChangedEvent {
	return &AssetChangedEvent{
		EventID:    uuid.New(),
		EventType:  EventTypeAssetChanged,
		TenantID:   tenantID,
		AssetID:    assetID,
		ChangeType: changeType,
		Timestamp:  time.Now(),
		Source:     source,
		Metadata:   make(map[string]interface{}),
	}
}

// NewAssetDeletedEvent creates a new asset deleted event
func NewAssetDeletedEvent(tenantID, assetID uuid.UUID, source string) *AssetDeletedEvent {
	return &AssetDeletedEvent{
		EventID:   uuid.New(),
		EventType: EventTypeAssetDeleted,
		TenantID:  tenantID,
		AssetID:   assetID,
		Timestamp: time.Now(),
		Source:    source,
		Metadata:  make(map[string]interface{}),
	}
}

// NewCertificateChangedEvent creates a new certificate changed event
func NewCertificateChangedEvent(tenantID, certificateID uuid.UUID, changeType ChangeType, source string) *CertificateChangedEvent {
	return &CertificateChangedEvent{
		EventID:       uuid.New(),
		EventType:     EventTypeCertificateChanged,
		TenantID:      tenantID,
		CertificateID: certificateID,
		ChangeType:    changeType,
		Timestamp:     time.Now(),
		Source:        source,
		Metadata:      make(map[string]interface{}),
	}
}

// NewBulkAssetChangedEvent creates a new bulk asset changed event
func NewBulkAssetChangedEvent(tenantID uuid.UUID, assetIDs []uuid.UUID, changeType ChangeType, source string) *BulkAssetChangedEvent {
	return &BulkAssetChangedEvent{
		EventID:    uuid.New(),
		EventType:  EventTypeBulkAssetChanged,
		TenantID:   tenantID,
		AssetIDs:   assetIDs,
		ChangeType: changeType,
		Timestamp:  time.Now(),
		Source:     source,
		Count:      len(assetIDs),
		Metadata:   make(map[string]interface{}),
	}
}
