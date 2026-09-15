package connectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// The claim `status: live` makes is "something in this tree dispatches on this
// key". These tests are what turns that from a comment into an assertion.
//
// Mutation test, both directions:
//
//   - flip `github` (or any of the four `registered` keys) to `live` in
//     standards/connectors.yaml, run `make generate` →
//     TestEveryLiveConnectorHasAnImplementation fails.
//   - add an entry here for a `registered` key →
//     TestOnlyLiveConnectorsClaimAnImplementation fails.
//   - rename a package named here →
//     TestEveryImplementationPathExists fails.

func TestEveryLiveConnectorHasAnImplementation(t *testing.T) {
	for _, c := range All {
		if c.Status != StatusLive {
			continue
		}
		if _, ok := ImplementationFor(c.Key); !ok {
			t.Errorf("%s: live but has no entry in implementations.go — either add the package that "+
				"dispatches on it, or set its status to `registered` (the schema accepts the key, "+
				"nothing implements it)", c.Key)
		}
	}
}

func TestOnlyLiveConnectorsClaimAnImplementation(t *testing.T) {
	for _, c := range All {
		if c.Status == StatusLive {
			continue
		}
		if impl, ok := ImplementationFor(c.Key); ok {
			t.Errorf("%s: status is %q but implementations.go claims code at %s — an entry there is the "+
				"claim that something dispatches, so promote it to live or drop the entry",
				c.Key, c.Status, impl.Package)
		}
	}
}

// The path a registry entry names must be real. A renamed or deleted package
// otherwise leaves the registry asserting something that stopped being true,
// which is the exact failure mode the four stale `live` keys had.
func TestEveryImplementationPathExists(t *testing.T) {
	root := repoRoot(t)
	// An open-source Core checkout has no services/*/ee tree at all, so an
	// Enterprise path is legitimately absent there. Detect that ONCE rather
	// than per-entry: "this file is missing" and "this whole tree is missing"
	// are different facts, and skipping per-entry would let a genuinely
	// deleted Enterprise package pass in the private repo too.
	_, eeErr := os.Stat(filepath.Join(root, "services", "inventory-service", "ee"))
	coreTree := os.IsNotExist(eeErr)

	checked := 0
	for _, key := range ImplementedKeys() {
		impl, _ := ImplementationFor(key)
		if impl.Package == "" {
			t.Errorf("%s: implementation entry names no package", key)
			continue
		}
		if impl.Enterprise && coreTree {
			continue
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(impl.Package)))
		if err != nil {
			t.Errorf("%s: implementations.go names %s, which does not exist (%v)", key, impl.Package, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s: implementations.go names %s, which is not a directory", key, impl.Package)
			continue
		}
		checked++
	}
	// Without this the test passes vacuously in a checkout where every path is
	// skipped — which is how a guard quietly stops guarding.
	if checked == 0 {
		t.Fatal("no implementation path was actually checked; this test would pass whatever the map said")
	}
}

// netbox is the workstream-2.7 connector and the first `network_source_of_truth`
// entry to go live. Named explicitly so its promotion to `live` cannot be
// reverted silently, and so the pull-only decision has a test that states it.
func TestNetBoxIsLiveAndPullOnly(t *testing.T) {
	c, ok := Get(ConnectorNetbox)
	if !ok {
		t.Fatal("netbox is missing from the registry")
	}
	if c.Status != StatusLive {
		t.Errorf("netbox status is %q, want live", c.Status)
	}
	if c.Kind != KindNetworkSourceOfTruth {
		t.Errorf("netbox kind is %q, want network_source_of_truth", c.Kind)
	}
	// v1 writes NOTHING back to NetBox. Drift is a read-only view. If this is
	// ever changed to `both`, the change must come with an actual writer.
	if c.Direction != DirectionPull {
		t.Errorf("netbox direction is %q, want pull — v1 makes no write to NetBox", c.Direction)
	}
	if c.SchemaSource != "connector_connections" {
		t.Errorf("netbox schema_source is %q, want connector_connections", c.SchemaSource)
	}
	if c.Feature != "connector_netbox" {
		t.Errorf("netbox feature is %q, want connector_netbox", c.Feature)
	}
}

// The four keys the platform_integrations CHECK accepts but nothing collects.
// Named so that "we shipped it" cannot be asserted by editing one word.
func TestDeclaredButUnimplementedConnectorsAreRegistered(t *testing.T) {
	for _, key := range []string{
		ConnectorHashicorpVault, ConnectorGithub, ConnectorGitlab, ConnectorBitbucket,
	} {
		c, ok := Get(key)
		if !ok {
			t.Errorf("%s is missing from the registry", key)
			continue
		}
		if c.Status != StatusRegistered {
			t.Errorf("%s: status is %q, want registered — no collector dispatches on it", key, c.Status)
		}
		// Still in a CHECK, which is exactly why `registered` and `planned` are
		// different statuses: a row carrying this key can already exist.
		if c.SchemaSource == "" {
			t.Errorf("%s: registered connectors carry the CHECK that accepts them", key)
		}
		if IsLive(key) {
			t.Errorf("%s: IsLive must not report a registered connector as dispatchable", key)
		}
		if !IsRegistered(key) {
			t.Errorf("%s: IsRegistered should report it", key)
		}
	}
}

// A connector's `feature` must be an entitlement key some edition actually
// gates, or the gate denies forever and the connector is unreachable in every
// edition — the silent outage RequireFeature warns about at wiring time.
func TestGatedConnectorsNameAnEditionGatedFeature(t *testing.T) {
	gated := 0
	for _, c := range All {
		if c.Feature == "" {
			continue
		}
		gated++
		if !entitlements.IsEditionGated(c.Feature) {
			t.Errorf("%s: feature %q is not edition-gated (shared/entitlements.editionByItem) — "+
				"RequireFeature on it would be reachable in Core, which is not what a paid connector wants",
				c.Key, c.Feature)
		}
	}
	if gated == 0 {
		t.Fatal("no connector declares a feature; this test would pass whatever the registry said")
	}
}
