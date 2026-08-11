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

func TestCheckFeatureAccess_EditionGatedRequiresOverride(t *testing.T) {
	tenantID := uuid.New()

	tests := []struct {
		name    string
		feature string
		hasTier bool
		ent     *entitlements.EffectiveEntitlement
		err     error
		want    bool
	}{
		{
			name:    "tier alone cannot unlock edition gated feature",
			feature: "custom_policies",
			hasTier: true,
			ent:     boolEntitlement("custom_policies", entitlements.SourceTier, true),
			want:    false,
		},
		{
			name:    "active override unlocks edition gated feature",
			feature: "custom_policies",
			hasTier: true,
			ent:     boolEntitlement("custom_policies", entitlements.SourceOverride, true),
			want:    true,
		},
		{
			name:    "disabled override stays denied",
			feature: "custom_policies",
			hasTier: true,
			ent:     boolEntitlement("custom_policies", entitlements.SourceOverride, false),
			want:    false,
		},
		{
			name:    "unknown gated feature stays denied",
			feature: "custom_policies",
			hasTier: true,
			err:     entitlements.ErrUnknownItem,
			want:    false,
		},
		{
			name:    "ungated onboarding carve out still avoids resolver",
			feature: "core_feature",
			hasTier: false,
			ent:     nil,
			want:    true,
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
			if tt.feature == "core_feature" && resolver.called {
				t.Fatal("ungated no-tier carve-out should not call the resolver")
			}
		})
	}
}
