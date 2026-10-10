package services

import (
	"testing"

	"github.com/google/uuid"
)

// hostConnectionSourceAssetID is the one reader of an external connection's
// source asset now that discovery-processor's external-connections writer is
// gone ( WP3); its own sourceAssetIDFromMetadata test moved here with
// the behaviour. Only the host-inventory connection projection may name the
// source asset: anything else carrying source_asset_id is a payload choosing
// whose connection it is.
func TestRouteHostConnectionSourceAssetID_UsesOnlyAValidExplicitUUID(t *testing.T) {
	want := uuid.New()
	got := hostConnectionSourceAssetID(map[string]interface{}{
		"discovery_type": "host_connection", "discovery_method": "host_inventory", "source_asset_id": want.String(),
	})
	if got == nil || *got != want {
		t.Fatalf("source asset = %v, want %s", got, want)
	}
	for _, raw := range []map[string]interface{}{
		nil,
		{},
		{"discovery_type": "host_connection", "discovery_method": "host_inventory", "source_asset_id": "not-a-uuid"},
		{"discovery_type": "passive", "discovery_method": "sensor", "source_asset_id": want.String()},
	} {
		if got := hostConnectionSourceAssetID(raw); got != nil {
			t.Errorf("%v produced %v", raw, got)
		}
	}
}
