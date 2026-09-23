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
		// MSP-only (owner decision: billing is for a provider
		// billing its own customers; an Enterprise licence does not cover it.
		"billing_portal": entitlements.EditionMSP,
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

// EditionCovers is the licence half of the boundary: which items a licence of
// a given edition may unlock at all.
func TestEditionCovers(t *testing.T) {
	const (
		core       = entitlements.EditionCore
		enterprise = entitlements.EditionEnterprise
		msp        = entitlements.EditionMSP
	)
	cases := []struct {
		licence entitlements.Edition
		item    string
		want    bool
	}{
		// Core items are covered by every edition, Core included.
		{core, "max_sensors", true},
		{enterprise, "max_sensors", true},
		{msp, "max_sensors", true},
		// Enterprise items: Enterprise and MSP, never Core.
		{core, "sso_saml", false},
		{enterprise, "sso_saml", true},
		{msp, "sso_saml", true},
		// MSP items: MSP only.
		{core, "billing_portal", false},
		{enterprise, "billing_portal", false},
		{msp, "billing_portal", true},
		// An edition this build does not know covers no gated item.
		{"platinum", "sso_saml", false},
		{"", "sso_saml", false},
	}
	for _, c := range cases {
		if got := entitlements.EditionCovers(c.licence, c.item); got != c.want {
			t.Errorf("EditionCovers(%q, %q) = %v, want %v", c.licence, c.item, got, c.want)
		}
	}

	// MSP covers EVERY gated item: one MSP licence grants the whole product.
	for _, k := range entitlements.EditionGatedKeys() {
		if !entitlements.EditionCovers(msp, k) {
			t.Errorf("an MSP licence does not cover %q — MSP must cover every gated capability", k)
		}
	}
}
