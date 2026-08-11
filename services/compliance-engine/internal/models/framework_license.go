package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantFrameworkLicense represents a licensed platform framework for a tenant
type TenantFrameworkLicense struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	TenantID            uuid.UUID `json:"tenant_id" db:"tenant_id"`
	PlatformFrameworkID uuid.UUID `json:"platform_framework_id" db:"platform_framework_id"`
	IsDefault           bool      `json:"is_default" db:"is_default"`
	PurchasedAt         time.Time `json:"purchased_at" db:"purchased_at"`
	PurchasePriceCents  *int      `json:"purchase_price_cents,omitempty" db:"purchase_price_cents"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`

	// Subscription fields (replace legacy lock mechanism)
	SubscriptionStatus    string     `json:"subscription_status" db:"subscription_status"` // "active", "expired", "cancelled"
	SubscriptionStartedAt *time.Time `json:"subscription_started_at" db:"subscription_started_at"`
	SubscriptionExpiresAt *time.Time `json:"subscription_expires_at,omitempty" db:"subscription_expires_at"` // nil = perpetual
	ProvisionedBy         string     `json:"provisioned_by" db:"provisioned_by"`                             // "admin", "self_service", "auto"

	// Legacy lock fields (kept for backward compat during migration, not used in new code)
	IsLocked bool       `json:"is_locked" db:"is_locked"`
	LockedAt *time.Time `json:"locked_at,omitempty" db:"locked_at"`
	LockedBy *uuid.UUID `json:"locked_by,omitempty" db:"locked_by"`

	// Joined fields (not in DB)
	PlatformFramework *PlatformFramework `json:"platform_framework,omitempty" db:"-"`
}

// IsSubscriptionActive returns true if the subscription is active (not expired or cancelled)
func (l *TenantFrameworkLicense) IsSubscriptionActive() bool {
	if l.SubscriptionStatus != "active" {
		return false
	}
	if l.SubscriptionExpiresAt != nil && l.SubscriptionExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}

// FrameworkLicenseInput represents input for subscribing to frameworks
type FrameworkLicenseInput struct {
	FrameworkIDs       []string `json:"framework_ids" binding:"required"`
	DefaultFrameworkID string   `json:"default_framework_id" binding:"required"`
}

// ProvisionFrameworkInput represents input for provisioning a single framework license
type ProvisionFrameworkInput struct {
	FrameworkID   string  `json:"framework_id" binding:"required"`
	ProvisionedBy string  `json:"provisioned_by"` // "admin", "self_service", "auto"
	ExpiresAt     *string `json:"expires_at,omitempty"`
	PriceCents    *int    `json:"price_cents,omitempty"`
	SetAsDefault  bool    `json:"set_as_default,omitempty"`
}

// LicensedFrameworkResponse represents a licensed framework with platform framework details
type LicensedFrameworkResponse struct {
	ID                    string             `json:"id"`
	TenantID              string             `json:"tenant_id"`
	PlatformFrameworkID   string             `json:"platform_framework_id"`
	IsDefault             bool               `json:"is_default"`
	SubscriptionStatus    string             `json:"subscription_status"`
	SubscriptionStartedAt *string            `json:"subscription_started_at,omitempty"`
	SubscriptionExpiresAt *string            `json:"subscription_expires_at,omitempty"`
	ProvisionedBy         string             `json:"provisioned_by"`
	PurchasedAt           string             `json:"purchased_at"`
	PurchasePriceCents    *int               `json:"purchase_price_cents,omitempty"`
	CreatedAt             string             `json:"created_at"`
	UpdatedAt             string             `json:"updated_at"`
	PlatformFramework     *PlatformFramework `json:"platform_framework,omitempty"`
}

// AvailableFrameworkResponse represents an available framework for selection.
// For unlicensed frameworks, only summary info is included (not full controls).
//
// PreviewScore / ControlsPassing / ControlsFailing come from the materialized
// tenant_framework_scores rollup (ADR-0014) and are present for EVERY published
// framework — activated or not — so a card can show a preview score before the
// tenant activates. They are nil until the evaluation engine has produced a rollup.
type AvailableFrameworkResponse struct {
	PlatformFramework *PlatformFramework `json:"platform_framework"`
	IsLicensed        bool               `json:"is_licensed"`
	IsPlatformDefault bool               `json:"is_platform_default"`
	PreviewScore      *int               `json:"preview_score,omitempty"`
	ControlsPassing   *int               `json:"controls_passing,omitempty"`
	ControlsFailing   *int               `json:"controls_failing,omitempty"`
}

// DefaultFrameworkResponse represents the tenant's default framework
type DefaultFrameworkResponse struct {
	FrameworkID        string             `json:"framework_id"`
	FrameworkType      string             `json:"framework_type"` // "licensed" or "platform_default"
	Framework          *PlatformFramework `json:"framework,omitempty"`
	SubscriptionStatus string             `json:"subscription_status,omitempty"`
}
