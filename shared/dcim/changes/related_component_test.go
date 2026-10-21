package changes

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// A component that lives on an asset — a virtual device context here, but the
// same holds for the port components — relates its change to that asset, so
// the asset's Changes tab lists it. An asset's own change relates to nothing.
func TestDeriveRelated_ComponentWithAssetIDRelatesToTheAsset(t *testing.T) {
	asset := uuid.New()
	img, _ := json.Marshal(map[string]any{"name": "vsys2", "asset_id": asset.String()})
	k, id, ok := DeriveRelated(context.Background(), nil, Row{Kind: dcim.ObjectKindVirtualDeviceContext, PostchangeData: img})
	if !ok || k != dcim.ObjectKindAsset || id != asset {
		t.Fatalf("virtual device context: got (%q, %s, %v), want the asset", k, id, ok)
	}
	k, id, ok = DeriveRelated(context.Background(), nil, Row{Kind: dcim.ObjectKindPowerPort, PrechangeData: img})
	if !ok || k != dcim.ObjectKindAsset || id != asset {
		t.Fatalf("power port: got (%q, %s, %v), want the asset", k, id, ok)
	}
	if _, _, ok := DeriveRelated(context.Background(), nil, Row{Kind: dcim.ObjectKindAsset, PostchangeData: img}); ok {
		t.Fatal("an asset's own change must not relate to itself")
	}
}
