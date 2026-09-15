package xbom

// Class → CycloneDX component type, for the classes the GENERATED registry does
// not carry.
//
// A tenant may add leaf subclasses at runtime (ADR-0002 D2) — the NetBox
// connector creates one per device role — and `assetclass.Get` deliberately
// knows only the fixed top of the taxonomy. The resolver used to stop there and
// fall through to `device`, so every tenant subclass was typed as a CycloneDX
// device AND admitted to the HBOM as hardware, whatever the tenant had actually
// declared it to be. That is a false statement about a customer's estate in a
// document they hand to an auditor, and the function's own comment claimed an
// ancestry walk that would have prevented it and that the code never performed.

import (
	"testing"

	"github.com/google/uuid"
)

// tenantSubclassAsset builds an asset in a class the generated registry has
// never heard of, carrying whatever `asset_classes.cyclonedx_type` says.
func tenantSubclassAsset(id uuid.UUID, classKey, cdxType, name string) Asset {
	return Asset{
		ID:             id,
		ClassKey:       classKey,
		ClassPath:      classKey, // what classPathForKey stores for a subclass it cannot read
		CycloneDXType:  cdxType,
		DisplayName:    name,
		AssetStatus:    "monitoring",
		AssetOwnership: "internal",
		Tags:           map[string]string{},
	}
}

var (
	subclassApp     = uuid.MustParse("e0000000-0000-4000-8000-000000000001")
	subclassDevice  = uuid.MustParse("e0000000-0000-4000-8000-000000000002")
	subclassService = uuid.MustParse("e0000000-0000-4000-8000-000000000003")
	subclassUnknown = uuid.MustParse("e0000000-0000-4000-8000-000000000004")
)

func tenantSubclassSnapshot() *Snapshot {
	return &Snapshot{
		Assets: []Asset{
			tenantSubclassAsset(subclassApp, "acme_payment_app", "application", "Payments"),
			tenantSubclassAsset(subclassDevice, "acme_edge_appliance", "device", "Edge 1"),
			tenantSubclassAsset(subclassService, "acme_customer_journey", "service", "Checkout journey"),
			// No registry row at all — the class key was written by something
			// that could not read `asset_classes`.
			tenantSubclassAsset(subclassUnknown, "acme_mystery", "", "Mystery"),
		},
	}
}

func componentType(t *testing.T, snap *Snapshot, id uuid.UUID) (string, bool) {
	t.Helper()
	doc, err := BuildDocument("inventory", snap, fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument(inventory): %v", err)
	}
	for _, c := range doc.Components {
		if c.BOMRef == refAsset+id.String() {
			return c.Type, true
		}
	}
	return "", false
}

// TestInventory_TenantSubclassTakesTheRegistrysType is the positive half.
func TestInventory_TenantSubclassTakesTheRegistrysType(t *testing.T) {
	snap := tenantSubclassSnapshot()

	if got, ok := componentType(t, snap, subclassApp); !ok || got != "application" {
		t.Errorf("a tenant subclass declared `application` was emitted as %q (found=%v), want application", got, ok)
	}
	if got, ok := componentType(t, snap, subclassDevice); !ok || got != "device" {
		t.Errorf("a tenant subclass declared `device` was emitted as %q (found=%v), want device", got, ok)
	}

	// `service` is not a CycloneDX component type: the class registry documents
	// that such a class goes into the services array. That has to hold for a
	// tenant subclass too, or the split the taxonomy dictates stops at the edge
	// of the generated file.
	doc, err := BuildDocument("inventory", snap, fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	if _, ok := componentType(t, snap, subclassService); ok {
		t.Error("a tenant subclass declared `service` was emitted as a component")
	}
	found := false
	for _, s := range doc.Services {
		if s.BOMRef == refAsset+subclassService.String() {
			found = true
		}
	}
	if !found {
		t.Error("a tenant subclass declared `service` is missing from the services array")
	}
}

// TestInventory_UnresolvableClassStillAppears.
//
// SOMETHING must be emitted for every in-scope asset — an inventory artifact
// that silently dropped an asset because its class could not be resolved would
// under-report the boundary it claims to cover. CycloneDX 1.7 has no "unknown"
// component type, so `device` is the fallback, and the class key travels
// verbatim in `vista:asset:class` so the reader is not misled about what we
// actually know.
func TestInventory_UnresolvableClassStillAppears(t *testing.T) {
	snap := tenantSubclassSnapshot()
	got, ok := componentType(t, snap, subclassUnknown)
	if !ok {
		t.Fatal("an asset whose class could not be resolved was dropped from the inventory")
	}
	if got != "device" {
		t.Errorf("unresolvable class emitted as %q, want the documented `device` fallback", got)
	}

	doc, err := BuildDocument("inventory", snap, fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	for _, c := range doc.Components {
		if c.BOMRef != refAsset+subclassUnknown.String() {
			continue
		}
		if propertyValue(c.Properties, propAssetClass) != "acme_mystery" {
			t.Error("the unresolved class key is not carried in vista:asset:class — the reader has no way to see what we actually know")
		}
	}
}

// TestHBOM_TenantSubclassMembershipFollowsTheRegistry is the one that was
// wrong: an HBOM is the single document whose entire content is the claim
// "these are your hardware assets", and it listed every tenant subclass.
func TestHBOM_TenantSubclassMembershipFollowsTheRegistry(t *testing.T) {
	doc, err := BuildDocument("hbom", tenantSubclassSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument(hbom): %v", err)
	}

	in := map[string]bool{}
	for _, c := range doc.Components {
		in[c.BOMRef] = true
	}

	// Positive half. Without it, a build that emitted an empty HBOM would pass
	// every assertion below.
	if !in[refAsset+subclassDevice.String()] {
		t.Error("a tenant subclass declared `device` is missing from the HBOM")
	}
	for _, absent := range []struct {
		id  uuid.UUID
		why string
	}{
		{subclassApp, "declared `application`"},
		{subclassService, "declared `service`"},
		{subclassUnknown, "has no registry row, so it is not PROVABLY hardware"},
	} {
		if in[refAsset+absent.id.String()] {
			t.Errorf("the HBOM lists an asset that %s — over-listing is a false statement a reader cannot see", absent.why)
		}
	}
}

// TestResolveCycloneDXType_GeneratedRegistryWins.
//
// The fixed top of the taxonomy is generated from standards/asset-classes.yaml
// and is not editable per tenant. A row in `asset_classes` claiming a fixed
// class is something else must not move it — otherwise a tenant could retype
// `server` and change what their own HBOM asserts.
func TestResolveCycloneDXType_GeneratedRegistryWins(t *testing.T) {
	a := Asset{ClassKey: "server", CycloneDXType: "data"}
	got, ok := resolveCycloneDXType(a)
	if !ok || got != "device" {
		t.Errorf("resolveCycloneDXType(server overridden to data) = %q,%v; want device,true", got, ok)
	}
}
