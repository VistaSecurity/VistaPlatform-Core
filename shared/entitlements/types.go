package entitlements

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Kind enumerates the value shapes the catalog supports. It mirrors the
// billable_items.kind CHECK constraint.
type Kind string

const (
	KindBoolean        Kind = "boolean"
	KindNumericCap     Kind = "numeric_cap"
	KindNumericMetered Kind = "numeric_metered"
	KindEnumChoice     Kind = "enum_choice"
)

// Source records which layer of the resolution stack provided the value.
type Source string

const (
	// SourceOverride means an active tenant_entitlements row supplied the value.
	SourceOverride Source = "override"
	// SourceTier means tier_entitlements supplied the value via the tenant's tier.
	SourceTier Source = "tier"
	// SourceDefault means neither tier nor override matched; billable_items.default_value
	// was used. This is the fall-through case — usually conservative.
	SourceDefault Source = "default"
)

// BillableItem is the catalog row a resolved entitlement points at.
type BillableItem struct {
	ID       uuid.UUID
	Key      string
	Kind     Kind
	Category string
	Unit     *string
}

// EffectiveEntitlement is what the resolver returns: the merged value plus
// enough provenance for callers to decide whether to gate, charge, or warn.
type EffectiveEntitlement struct {
	Item   BillableItem
	Value  json.RawMessage
	Source Source

	// OveragePriceCents and OverageUnitSize are populated for numeric_metered
	// items resolved via tier_entitlements. Catalog metadata only — the
	// overage-billing pipeline was removed 2026-07 (billing is flat
	// per-tier); nothing bills from these. Capability/cap items leave
	// these nil.
	OveragePriceCents *int
	OverageUnitSize   *int

	// ExpiresAt is the override's expires_at when SourceOverride; nil for
	// permanent overrides and for tier/default sources. Callers that surface
	// "trial ends X" copy read this.
	ExpiresAt *time.Time
}

// BooleanValue parses {"enabled": true|false}. Returns (false, false) when
// the value is malformed — the boolean ok flag lets callers distinguish
// "explicitly disabled" from "couldn't tell".
func (e *EffectiveEntitlement) BooleanValue() (enabled, ok bool) {
	var v struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(e.Value, &v); err != nil || v.Enabled == nil {
		return false, false
	}
	return *v.Enabled, true
}

// QuantityValue parses {"quantity": N|null}. A nil result means the catalog
// row set quantity to JSON null, conventionally "unlimited". The boolean ok
// flag distinguishes that from a malformed value.
func (e *EffectiveEntitlement) QuantityValue() (qty *int, ok bool) {
	var v struct {
		Quantity *int `json:"quantity"`
	}
	if err := json.Unmarshal(e.Value, &v); err != nil {
		return nil, false
	}
	return v.Quantity, true
}

// EnumValue parses {"value": "..."}.
func (e *EffectiveEntitlement) EnumValue() (value string, ok bool) {
	var v struct {
		Value *string `json:"value"`
	}
	if err := json.Unmarshal(e.Value, &v); err != nil || v.Value == nil {
		return "", false
	}
	return *v.Value, true
}

// CapCheck is the structured result of checking a numeric cap.
type CapCheck struct {
	Allowed bool
	Current int
	// Limit is nil when the resolved entitlement is unlimited.
	Limit  *int
	Source Source
	// Reason is a short human-facing message: "Sensor limit: 3/10", etc.
	Reason string
	// UpgradePrompt is non-empty when Allowed=false and there's a tier-up path.
	UpgradePrompt string
}
