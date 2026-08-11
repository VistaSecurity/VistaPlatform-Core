package entitlements

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// IsEnabled is the canonical boolean gate. Returns false (deny) when the
// entitlement is malformed, unknown, or resolves to enabled=false. Callers
// that need to distinguish "explicitly disabled" from "couldn't resolve"
// should use Resolve directly and inspect the error.
//
// On ErrUnknownItem the policy is "deny + log": an unknown key in code is
// almost always a typo or a stale reference, and silently allowing access
// would mask it.
func IsEnabled(ctx context.Context, r Resolver, tenantID uuid.UUID, itemKey string) (bool, error) {
	ent, err := r.Resolve(ctx, tenantID, itemKey)
	if errors.Is(err, ErrUnknownItem) {
		return false, err
	}
	if err != nil {
		return false, err
	}
	if ent.Item.Kind != KindBoolean {
		return false, fmt.Errorf("entitlements: item %s is %s, expected boolean", itemKey, ent.Item.Kind)
	}
	enabled, _ := ent.BooleanValue()
	return enabled, nil
}

// GetQuantity returns the included quantity for a numeric_cap or
// numeric_metered item. A nil result means unlimited (catalog quantity:
// null). Returns 0 with a non-nil error when the item is the wrong kind
// or unresolvable.
func GetQuantity(ctx context.Context, r Resolver, tenantID uuid.UUID, itemKey string) (*int, error) {
	ent, err := r.Resolve(ctx, tenantID, itemKey)
	if err != nil {
		return nil, err
	}
	if ent.Item.Kind != KindNumericCap && ent.Item.Kind != KindNumericMetered {
		return nil, fmt.Errorf("entitlements: item %s is %s, expected numeric_cap or numeric_metered", itemKey, ent.Item.Kind)
	}
	qty, ok := ent.QuantityValue()
	if !ok {
		return nil, fmt.Errorf("entitlements: item %s has malformed quantity value", itemKey)
	}
	return qty, nil
}

// CheckCap is the canonical "can I add another N?" gate for numeric caps.
// It composes Resolve + a current-count comparison and returns a structured
// CapCheck suitable for surfacing to UI ("Sensor limit: 3/10") or for
// middleware to emit 402/403.
//
// current is the count the tenant already holds. additional is how many
// they want to add (0 for a pure read of the cap).
//
// upgradePrompt is the copy to show when the request is denied AND there's
// a tier-up path. Caller-provided so the message reflects the resource
// being gated (sensors, assets, etc.).
func CheckCap(
	ctx context.Context,
	r Resolver,
	tenantID uuid.UUID,
	itemKey string,
	current, additional int,
	upgradePrompt string,
) (*CapCheck, error) {
	ent, err := r.Resolve(ctx, tenantID, itemKey)
	if err != nil {
		return nil, err
	}
	if ent.Item.Kind != KindNumericCap && ent.Item.Kind != KindNumericMetered {
		return nil, fmt.Errorf("entitlements: item %s is %s, expected numeric_cap or numeric_metered", itemKey, ent.Item.Kind)
	}
	qty, ok := ent.QuantityValue()
	if !ok {
		return nil, fmt.Errorf("entitlements: item %s has malformed quantity value", itemKey)
	}

	result := &CapCheck{
		Current: current,
		Limit:   qty,
		Source:  ent.Source,
	}
	if qty == nil {
		// Unlimited.
		result.Allowed = true
		result.Reason = fmt.Sprintf("%s: unlimited", ent.Item.Key)
		return result, nil
	}
	newTotal := current + additional
	if newTotal <= *qty {
		result.Allowed = true
		if additional == 0 {
			result.Reason = fmt.Sprintf("%s: %d/%d", ent.Item.Key, current, *qty)
		} else {
			result.Reason = fmt.Sprintf("%s: %d/%d (adding %d)", ent.Item.Key, current, *qty, additional)
		}
		return result, nil
	}
	result.Allowed = false
	if additional == 0 {
		result.Reason = fmt.Sprintf("%s limit exceeded: %d/%d", ent.Item.Key, current, *qty)
	} else {
		result.Reason = fmt.Sprintf("%s limit would be exceeded: %d + %d = %d (limit: %d)",
			ent.Item.Key, current, additional, newTotal, *qty)
	}
	result.UpgradePrompt = upgradePrompt
	return result, nil
}

// GetEnum returns the resolved enum_choice value (e.g. "premium" for the
// support tier). Empty string with a non-nil error when malformed.
func GetEnum(ctx context.Context, r Resolver, tenantID uuid.UUID, itemKey string) (string, error) {
	ent, err := r.Resolve(ctx, tenantID, itemKey)
	if err != nil {
		return "", err
	}
	if ent.Item.Kind != KindEnumChoice {
		return "", fmt.Errorf("entitlements: item %s is %s, expected enum_choice", itemKey, ent.Item.Kind)
	}
	v, ok := ent.EnumValue()
	if !ok {
		return "", fmt.Errorf("entitlements: item %s has malformed enum value", itemKey)
	}
	return v, nil
}
