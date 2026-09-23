package services

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

type fakeEntitlementResolver struct {
	ent    *entitlements.EffectiveEntitlement
	err    error
	called bool
}

func (r *fakeEntitlementResolver) Resolve(context.Context, uuid.UUID, string) (*entitlements.EffectiveEntitlement, error) {
	r.called = true
	return r.ent, r.err
}

func (r *fakeEntitlementResolver) ResolveMany(context.Context, uuid.UUID, []string) (map[string]*entitlements.EffectiveEntitlement, error) {
	panic("ResolveMany is not used by CheckFeatureAccess")
}

func boolEntitlement(key string, source entitlements.Source, enabled bool) *entitlements.EffectiveEntitlement {
	value, _ := json.Marshal(map[string]bool{"enabled": enabled})
	return &entitlements.EffectiveEntitlement{
		Item: entitlements.BillableItem{
			ID:   uuid.New(),
			Key:  key,
			Kind: entitlements.KindBoolean,
		},
		Value:  value,
		Source: source,
	}
}

// checkFeatureAccess must take the resolver's answer for an edition-gated item
// whatever layer it came from. The resolver's licence step is the edition
// boundary; a second rule here — the old "a gated item counts only from an
// override" — is exactly what stopped an MSP plan (a tier) from granting a paid
// capability, and re-adding it turns the "tier grant" row red.
func TestCheckFeatureAccess_ResolverDecidesGatedItems(t *testing.T) {
	tenantID := uuid.New()

	tests := []struct {
		name         string
		feature      string
		hasTier      bool
		ent          *entitlements.EffectiveEntitlement
		err          error
		want         bool
		wantResolved bool
	}{
		{
			name:         "tier grant (an MSP plan) unlocks a gated feature",
			feature:      "custom_policies",
			hasTier:      true,
			ent:          boolEntitlement("custom_policies", entitlements.SourceTier, true),
			want:         true,
			wantResolved: true,
		},
		{
			name:         "edition grant (an Enterprise licence) unlocks a gated feature",
			feature:      "custom_policies",
			hasTier:      true,
			ent:          boolEntitlement("custom_policies", entitlements.SourceEdition, true),
			want:         true,
			wantResolved: true,
		},
		{
			name:         "edition denial (no licence) stays denied",
			feature:      "custom_policies",
			hasTier:      true,
			ent:          boolEntitlement("custom_policies", entitlements.SourceEdition, false),
			want:         false,
			wantResolved: true,
		},
		{
			name:         "disabled override stays denied",
			feature:      "custom_policies",
			hasTier:      true,
			ent:          boolEntitlement("custom_policies", entitlements.SourceOverride, false),
			want:         false,
			wantResolved: true,
		},
		{
			name:         "unknown gated feature stays denied",
			feature:      "custom_policies",
			hasTier:      true,
			err:          entitlements.ErrUnknownItem,
			want:         false,
			wantResolved: true,
		},
		{
			// The onboarding carve-out must NOT reach gated items: it answers
			// without the resolver, and so without the licence step.
			name:         "gated feature with no tier still asks the resolver",
			feature:      "custom_policies",
			hasTier:      false,
			ent:          boolEntitlement("custom_policies", entitlements.SourceEdition, false),
			want:         false,
			wantResolved: true,
		},
		{
			name:         "ungated onboarding carve out still avoids resolver",
			feature:      "core_feature",
			hasTier:      false,
			ent:          nil,
			want:         true,
			wantResolved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeEntitlementResolver{ent: tt.ent, err: tt.err}
			got, err := checkFeatureAccess(context.Background(), resolver, tenantID, tt.feature, tt.hasTier)
			if err != nil {
				t.Fatalf("checkFeatureAccess returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("checkFeatureAccess() = %v, want %v", got, tt.want)
			}
			if resolver.called != tt.wantResolved {
				t.Fatalf("resolver called = %v, want %v", resolver.called, tt.wantResolved)
			}
		})
	}
}
