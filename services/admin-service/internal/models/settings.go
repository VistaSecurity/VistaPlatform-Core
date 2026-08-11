package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantAdminSettings represents tenant admin configuration
type TenantAdminSettings struct {
	TenantID  uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Config    map[string]interface{} `json:"config" db:"config"`
	Version   int                    `json:"version" db:"version"`
	UpdatedBy uuid.UUID              `json:"updated_by" db:"updated_by"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

// TenantSettingsConfig represents the structure of tenant settings JSON
type TenantSettingsConfig struct {
	FrameworkID               string                   `json:"frameworkId,omitempty"`
	EmailVerificationRequired *bool                    `json:"email_verification_required,omitempty"` // nil = use platform default
	OnboardingRequired        *bool                    `json:"onboarding_required,omitempty"`         // nil = use platform default (true)
	NotificationPrefs         *NotificationPreferences `json:"notification_preferences,omitempty"`
	ComplianceSettings        map[string]interface{}   `json:"compliance_settings,omitempty"`
	FeatureFlags              map[string]bool          `json:"feature_flags,omitempty"`
	CapabilityPolicy          *CapabilityPolicy        `json:"capability_policy,omitempty"`
}

// CapabilityPolicy controls which scanning and agent capabilities are allowed
// for a tenant. When nil or when a specific field is nil, the platform default
// (enabled) is used. Tenant admins set these to restrict capabilities across
// all users in the tenant. The design is extensible — new capabilities are
// added as new fields with *bool so nil = platform default.
type CapabilityPolicy struct {
	// ActiveScanning controls whether active probing (TLS handshakes, SSH kex,
	// port scanning) is allowed. When false, discovery jobs are restricted to
	// passive monitoring only.
	ActiveScanning *bool `json:"active_scanning,omitempty"`
	// ActiveScanningSegments lists network segment IDs where active scanning
	// is allowed. When nil or empty and ActiveScanning is true, all segments
	// are allowed. When populated, only listed segments permit active scanning.
	ActiveScanningSegments []string `json:"active_scanning_segments,omitempty"`
	// TLSVersionEnumeration controls whether the sensor enumerates all supported
	// TLS versions per port (additional handshakes per version).
	TLSVersionEnumeration *bool `json:"tls_version_enumeration,omitempty"`
	// SSHProbing controls whether SSH key exchange probing is allowed.
	SSHProbing *bool `json:"ssh_probing,omitempty"`
}

// NotificationPreferences represents notification preferences
type NotificationPreferences struct {
	EmailEnabled    bool     `json:"email_enabled"`
	SMSEnabled      bool     `json:"sms_enabled"`
	AlertLevels     []string `json:"alert_levels"` // e.g., ["critical", "high"]
	DigestEnabled   bool     `json:"digest_enabled"`
	DigestFrequency string   `json:"digest_frequency"` // "daily", "weekly"
}

// TenantSettingsAuditEntry represents an audit entry for settings changes
type TenantSettingsAuditEntry struct {
	ID            uuid.UUID              `json:"id" db:"id"`
	TenantID      uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ConfigBefore  map[string]interface{} `json:"config_before,omitempty" db:"config_before"`
	ConfigAfter   map[string]interface{} `json:"config_after" db:"config_after"`
	VersionBefore int                    `json:"version_before" db:"version_before"`
	VersionAfter  int                    `json:"version_after" db:"version_after"`
	ChangedBy     uuid.UUID              `json:"changed_by" db:"changed_by"`
	ChangeReason  *string                `json:"change_reason,omitempty" db:"change_reason"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
}
