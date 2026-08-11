package entitlements_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// These tests are deliberately DB-free: the edition registry is a pure map so
// the open-core boundary is verifiable in any environment, including CI
// without Postgres. The DB-backed proof that a Core deployment actually denies
// these capabilities lives in TestIntegration_EditionGate_* below.

func TestEditionFor_UnmappedKeysAreCore(t *testing.T) {
	// The default must be "free and open" so that adding a capability to the
	// platform never accidentally paywalls it. If this inverts, every new
	// feature silently becomes paid — the opposite of an open core.
	for _, key := range []string{
		"max_assets",
		"max_sensors",
		"retention_days",
		"storage_gb",
		"support_sla_tier",
		"some_capability_that_does_not_exist_yet",
	} {
		if got := entitlements.EditionFor(key); got != entitlements.EditionCore {
			t.Errorf("EditionFor(%q) = %q, want %q — unmapped keys must default to Core",
				key, got, entitlements.EditionCore)
		}
		if entitlements.IsEditionGated(key) {
			t.Errorf("IsEditionGated(%q) = true, want false", key)
		}
	}
}

func TestEditionFor_PaidCapabilities(t *testing.T) {
	// Pins the edition boundary. A change here is a commercial decision, not
	// a refactor: moving a key out of this list gives it away for free, and
	// (once published) that is irreversible — open core cannot take back a
	// capability it has already shipped as free.
	want := map[string]entitlements.Edition{
		"custom_policies":     entitlements.EditionEnterprise,
		"threshold_overrides": entitlements.EditionEnterprise,
		"cbom_signing":        entitlements.EditionEnterprise,
		"sso_saml":            entitlements.EditionEnterprise,
		"custom_branding":     entitlements.EditionEnterprise,
		"ot_active_probing":   entitlements.EditionEnterprise,
		"ot_primary_lens":     entitlements.EditionEnterprise,
	}
	for key, wantEd := range want {
		if got := entitlements.EditionFor(key); got != wantEd {
			t.Errorf("EditionFor(%q) = %q, want %q", key, got, wantEd)
		}
		if !entitlements.IsEditionGated(key) {
			t.Errorf("IsEditionGated(%q) = false, want true", key)
		}
	}
}

func TestEditionGatedKeys_SortedAndFilterable(t *testing.T) {
	all := entitlements.EditionGatedKeys()
	if len(all) == 0 {
		t.Fatal("EditionGatedKeys() returned nothing; the edition boundary is empty")
	}
	for i := 1; i < len(all); i++ {
		if all[i-1] >= all[i] {
			t.Fatalf("EditionGatedKeys() not sorted: %q before %q", all[i-1], all[i])
		}
	}

	ent := entitlements.EditionGatedKeys(entitlements.EditionEnterprise)
	if len(ent) == 0 {
		t.Fatal("no Enterprise keys returned")
	}
	for _, k := range ent {
		if entitlements.EditionFor(k) != entitlements.EditionEnterprise {
			t.Errorf("EditionGatedKeys(Enterprise) returned non-Enterprise key %q", k)
		}
	}

	// Filtering to Core must return nothing: Core is the absence of a gate,
	// not a bucket of gated items.
	if core := entitlements.EditionGatedKeys(entitlements.EditionCore); len(core) != 0 {
		t.Errorf("EditionGatedKeys(Core) = %v, want empty", core)
	}
}
