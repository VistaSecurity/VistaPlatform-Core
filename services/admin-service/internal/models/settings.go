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

// TenantSettingsConfig is the typed projection of the keys the MSP tenant-settings
// handler owns inside the shared tenant_admin_settings.config jsonb document.
//
// It is deliberately NOT the whole document: discovery_auto_scan, drift,
// identity, ai and network_spaces are other services' keys in the same blob and
// are never named here, so they can never be serialised (and therefore never
// clobbered) by a settings save.
//
// `FrameworkID` was removed with the consumerless frameworkId field — see the
// TenantSettings doc comment in services/admin-service/ee/msp/tenant_settings.go.
type TenantSettingsConfig struct {
	EmailVerificationRequired *bool                    `json:"email_verification_required,omitempty"` // nil = use platform default
	OnboardingRequired        *bool                    `json:"onboarding_required,omitempty"`         // nil = use platform default (true)
	NotificationPrefs         *NotificationPreferences `json:"notification_preferences,omitempty"`
	ComplianceSettings        map[string]interface{}   `json:"compliance_settings,omitempty"`
	FeatureFlags              map[string]bool          `json:"feature_flags,omitempty"`
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
