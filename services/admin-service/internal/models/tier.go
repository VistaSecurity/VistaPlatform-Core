package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SubscriptionTier represents a subscription tier with limits and pricing
type SubscriptionTier struct {
	ID               uuid.UUID `json:"id" db:"id"`
	Name             string    `json:"name" db:"name"`
	DisplayName      string    `json:"display_name" db:"display_name"`
	MaxSensors       *int      `json:"max_sensors" db:"max_sensors"` // nil = unlimited (-1 in DB)
	MaxAssets        *int      `json:"max_assets" db:"max_assets"`   // nil = unlimited (-1 in DB)
	MaxUsers         *int      `json:"max_users" db:"max_users"`     // nil = unlimited (-1 in DB)
	RetentionDays    int       `json:"retention_days" db:"retention_days"`
	PriceCents       int       `json:"price_cents" db:"price_cents"`
	AnnualPriceCents *int      `json:"annual_price_cents" db:"annual_price_cents"`
	BillingInterval  string    `json:"billing_interval" db:"billing_interval"`
	// BillingMethod is how the plan is collected: "stripe" (card via Stripe)
	// or "invoice" (record-only / offline; no Stripe subscription created).
	BillingMethod       string                 `json:"billing_method" db:"billing_method"`
	StripePriceID       *string                `json:"stripe_price_id" db:"stripe_price_id"`
	StripePriceIDAnnual *string                `json:"stripe_price_id_annual" db:"stripe_price_id_annual"`
	Features            map[string]interface{} `json:"features" db:"features"`
	Limits              map[string]interface{} `json:"limits" db:"limits"`
	AddonPricing        map[string]interface{} `json:"addon_pricing" db:"addon_pricing"`
	Metadata            map[string]interface{} `json:"metadata" db:"metadata"`
	IsActive            bool                   `json:"is_active" db:"is_active"`
	IsCustom            bool                   `json:"is_custom" db:"is_custom"`
	// OwnerTenantID scopes a custom plan to one tenant (nil = global/standard,
	// shown on public signup; non-nil = private to that tenant only).
	OwnerTenantID *uuid.UUID `json:"owner_tenant_id" db:"owner_tenant_id"`
	DisplayOrder  int        `json:"display_order" db:"display_order"`
	DeprecatedAt  *time.Time `json:"deprecated_at" db:"deprecated_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// TierEntitlementInput is one cell of the unified plan modal's billable-item
// matrix. Item is identified by stable key. Mirrors services.TierEntitlementInput
// (defined in models to avoid a models→services import cycle). The tier's
// current composition is read back via GET /tiers/:id/entitlements.
type TierEntitlementInput struct {
	ItemKey           string          `json:"item_key"`
	IncludedValue     json.RawMessage `json:"included_value"`
	OveragePriceCents *int            `json:"overage_price_cents,omitempty"`
	OverageUnitSize   *int            `json:"overage_unit_size,omitempty"`
}

// TierCreateRequest represents a request to create a new tier
type TierCreateRequest struct {
	Name             string `json:"name" binding:"required"`
	DisplayName      string `json:"display_name" binding:"required"`
	MaxSensors       *int   `json:"max_sensors"`
	MaxAssets        *int   `json:"max_assets"`
	MaxUsers         *int   `json:"max_users"`
	RetentionDays    int    `json:"retention_days"`
	PriceCents       int    `json:"price_cents"`
	AnnualPriceCents *int   `json:"annual_price_cents"`
	BillingInterval  string `json:"billing_interval" binding:"required"`
	// BillingMethod: "stripe" (default) or "invoice". Empty defaults to "stripe".
	BillingMethod string                 `json:"billing_method"`
	Features      map[string]interface{} `json:"features"`
	Limits        map[string]interface{} `json:"limits"`
	AddonPricing  map[string]interface{} `json:"addon_pricing"`
	Metadata      map[string]interface{} `json:"metadata"`
	IsCustom      bool                   `json:"is_custom"`
	// OwnerTenantID scopes a custom plan to one tenant (set with IsCustom=true).
	OwnerTenantID *uuid.UUID `json:"owner_tenant_id"`
	DisplayOrder  int        `json:"display_order"`
	// Entitlements is the full billable-item composition written to
	// tier_entitlements (the enforced layer). When non-empty it is the
	// source of truth for what the plan grants.
	Entitlements []TierEntitlementInput `json:"entitlements"`
}

// TierUpdateRequest represents a request to update a tier
type TierUpdateRequest struct {
	DisplayName      *string                `json:"display_name"`
	MaxSensors       *int                   `json:"max_sensors"`
	MaxAssets        *int                   `json:"max_assets"`
	MaxUsers         *int                   `json:"max_users"`
	RetentionDays    *int                   `json:"retention_days"`
	PriceCents       *int                   `json:"price_cents"`
	AnnualPriceCents *int                   `json:"annual_price_cents"`
	BillingInterval  *string                `json:"billing_interval"`
	BillingMethod    *string                `json:"billing_method"`
	Features         map[string]interface{} `json:"features"`
	Limits           map[string]interface{} `json:"limits"`
	AddonPricing     map[string]interface{} `json:"addon_pricing"`
	Metadata         map[string]interface{} `json:"metadata"`
	IsActive         *bool                  `json:"is_active"`
	IsCustom         *bool                  `json:"is_custom"`
	OwnerTenantID    *uuid.UUID             `json:"owner_tenant_id"`
	DisplayOrder     *int                   `json:"display_order"`
	// Entitlements, when non-nil, bulk-replaces the tier's composition in
	// tier_entitlements (the enforced layer).
	Entitlements []TierEntitlementInput `json:"entitlements"`
}

// EffectiveLimits represents the effective limits for a tenant (tier + overrides)
type EffectiveLimits struct {
	TenantID             uuid.UUID              `json:"tenant_id"`
	TierID               uuid.UUID              `json:"tier_id"`
	TierName             string                 `json:"tier_name"`
	MaxSensors           *int                   `json:"max_sensors"`
	MaxAssets            *int                   `json:"max_assets"`
	MaxUsers             *int                   `json:"max_users"`
	RetentionDays        int                    `json:"retention_days"`
	ComplianceFrameworks *int                   `json:"compliance_frameworks"`
	MaxIntegrations      *int                   `json:"max_integrations"`
	Features             map[string]interface{} `json:"features"`
	HasOverrides         bool                   `json:"has_overrides"`
	Overrides            []LimitOverride        `json:"overrides,omitempty"`
}

// LimitOverride represents a single limit override
type LimitOverride struct {
	ID           uuid.UUID   `json:"id"`
	OverrideType string      `json:"override_type"`
	LimitName    string      `json:"limit_name"`
	Value        interface{} `json:"value"`
	IsPermanent  bool        `json:"is_permanent"`
	ExpiresAt    *time.Time  `json:"expires_at"`
	Reason       string      `json:"reason"`
}

// TierHistory represents a change in tier configuration
type TierHistory struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	TierID     uuid.UUID              `json:"tier_id" db:"tier_id"`
	ChangeType string                 `json:"change_type" db:"change_type"`
	Changes    map[string]interface{} `json:"changes" db:"changes_json"`
	ChangedBy  *uuid.UUID             `json:"changed_by" db:"changed_by"`
	ChangedAt  time.Time              `json:"changed_at" db:"changed_at"`
	Notes      *string                `json:"notes" db:"notes"`
}

// Scan implements sql.Scanner for JSONB fields
func (t *SubscriptionTier) ScanFeatures(value interface{}) error {
	if value == nil {
		t.Features = make(map[string]interface{})
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, &t.Features)
}

func (t *SubscriptionTier) ScanLimits(value interface{}) error {
	if value == nil {
		t.Limits = make(map[string]interface{})
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, &t.Limits)
}

func (t *SubscriptionTier) ScanAddonPricing(value interface{}) error {
	if value == nil {
		t.AddonPricing = make(map[string]interface{})
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, &t.AddonPricing)
}

func (t *SubscriptionTier) ScanMetadata(value interface{}) error {
	if value == nil {
		t.Metadata = make(map[string]interface{})
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, &t.Metadata)
}
