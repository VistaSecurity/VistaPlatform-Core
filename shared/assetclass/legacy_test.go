package assetclass_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

func TestFromLegacyAssetTypeCoversEveryEnumValue(t *testing.T) {
	// The four values of the retired public.asset_type enum. Every one of them
	// arrives from some intake path (a sensor finding, an import column, a CMDB
	// ci_type mapping), so a value with no mapping is a class hint silently lost.
	for _, legacy := range assetclass.LegacyAssetTypes {
		key, ok := assetclass.FromLegacyAssetType(legacy)
		if !ok {
			t.Errorf("%q has no class mapping", legacy)
			continue
		}
		if _, known := assetclass.Get(key); !known {
			t.Errorf("%q maps to %q, which is not a class in the registry", legacy, key)
		}
	}
}

func TestFromLegacyAssetTypeRefusesToGuess(t *testing.T) {
	// "No opinion" must not become `server`. The old ingest defaulted every
	// finding that did not state a type to `server`, which is how a wall of
	// printers, switches and OT devices came to be inventoried as servers.
	for _, in := range []string{"", "   ", "unknown", "workstation", "nonsense"} {
		if key, ok := assetclass.FromLegacyAssetType(in); ok {
			t.Errorf("FromLegacyAssetType(%q) = %q, true — want no mapping; an unrecognised "+
				"value must leave the class hint empty so the engine falls back to "+
				"unknown_host/external per ADR-0002 D1", in, key)
		}
	}
}

func TestFromLegacyAssetTypeIsCaseAndSpaceInsensitive(t *testing.T) {
	// Import columns and vendor payloads arrive spelled however the source felt
	// like spelling them.
	for _, in := range []string{"Server", "SERVER", " server "} {
		key, ok := assetclass.FromLegacyAssetType(in)
		if !ok || key != assetclass.KeyServer {
			t.Errorf("FromLegacyAssetType(%q) = %q, %v; want server, true", in, key, ok)
		}
	}
}

func TestFromLegacyAssetTypeNeverPicksAMoreSpecificClassThanTheValueCarried(t *testing.T) {
	// "appliance" covered firewalls, switches, printers and PLCs. Mapping it to
	// any one of those would be a guess wearing the authority of an import,
	// which ADR-0002 D4 ranks above a measurement for the class of a declared
	// asset — so the guess would stick.
	key, ok := assetclass.FromLegacyAssetType("appliance")
	if !ok {
		t.Fatal("appliance has no mapping")
	}
	c, _ := assetclass.Get(key)
	if c.Parent != "" {
		t.Errorf("appliance maps to %q, whose parent is %q — the legacy value did not "+
			"distinguish between that class and its siblings, so the mapping must stop at "+
			"the covering ancestor", key, c.Parent)
	}
}
