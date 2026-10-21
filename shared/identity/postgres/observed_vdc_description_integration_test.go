package postgres_test

// A virtual device context's description is the operator's display name where
// the device gives one (a Palo Alto vsys's), written on a MEASURED row only.
//
// Mutations (each red, then restored green):
//   - drop the `description` column from the INSERT in createContext → the
//     first sighting leaves it empty;
//   - drop the `c.Description != ""` guard in refreshContext → an observation
//     without a display name clears the stored one;
//   - move the description assignment out of the `sourceKind == measured`
//     block in refreshContext → the declared context's description is
//     overwritten (or filled in);
//   - drop the `CASE WHEN $7` guard in the refresh UPDATE → every refresh
//     rewrites the description from the read taken earlier.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func TestIntegration_Identity_VirtualDeviceContextDescriptions(t *testing.T) {
	h := newIfaceHarness(t)
	h.at = time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	sighting := func(ctxs ...identity.ObservedVirtualDeviceContext) identity.Sighting {
		return identity.Sighting{
			TenantID: h.tenant, Channel: identity.ChannelAuthenticatedSession, ObservedAt: h.at,
			Source:                identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:vsys-names-it", Mode: identity.ModeActive},
			Identifiers:           []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "VSYS-IT-0001"}},
			VirtualDeviceContexts: ctxs,
		}
	}
	id := func(v int) *int { return &v }
	vsys := func(n int, desc string) identity.ObservedVirtualDeviceContext {
		return identity.ObservedVirtualDeviceContext{Name: "vsys" + string(rune('0'+n)), Identifier: id(n), Description: desc}
	}

	// 1. vsys2 is named by its operator, vsys1 is not.
	first := h.resolve(sighting(vsys(1, ""), vsys(2, "Tenant B Edge")))
	if first.Asset.Zero() {
		t.Fatalf("resolved to no asset (%s)", first.Outcome)
	}
	asset := first.Asset.ID
	desc := func() map[string]string {
		out := map[string]string{}
		for n, r := range readVDCs(t, h.db, h.tenant, asset) {
			out[n] = r.description
		}
		return out
	}
	check := func(when string, want map[string]string) {
		t.Helper()
		got := desc()
		for n, w := range want {
			if got[n] != w {
				t.Errorf("%s: %s description = %q, want %q", when, n, got[n], w)
			}
		}
	}
	check("first sighting", map[string]string{"vsys1": "", "vsys2": "Tenant B Edge"})

	// A person declares vsys3 with their own description, and an empty one for vsys4.
	for _, d := range []struct {
		name string
		id   int
		desc string
	}{{"vsys3", 3, "the person's words"}, {"vsys4", 4, ""}} {
		if _, err := h.db.Exec(`INSERT INTO virtual_device_contexts (tenant_id, asset_id, name, identifier, description, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $6)`, h.tenant, asset, d.name, d.id, d.desc, h.at); err != nil {
			t.Fatal(err)
		}
	}

	// 2. The operator renames vsys2 and names vsys1; the device calls the
	// person's contexts by other names, which must not reach them.
	h.at = h.at.AddDate(0, 0, 1)
	h.resolve(sighting(vsys(1, "Core"), vsys(2, "Tenant B Perimeter"), vsys(3, "the device's name"), vsys(4, "the device's other name")))
	check("renamed", map[string]string{
		"vsys1": "Core", "vsys2": "Tenant B Perimeter",
		"vsys3": "the person's words", "vsys4": "",
	})

	// 3. A later sighting that states no display name (the config read was
	// refused) leaves what is stored.
	h.at = h.at.AddDate(0, 0, 1)
	h.resolve(sighting(vsys(1, ""), vsys(2, "")))
	check("no name stated", map[string]string{"vsys1": "Core", "vsys2": "Tenant B Perimeter"})

	// 4. The change record names the description for the rename.
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'virtual_device_context'
		AND action = 'update' AND 'description' = ANY(changed_fields)`, h.tenant).Scan(&n); err != nil || n != 2 {
		t.Errorf("%d description changes recorded (%v), want 2 (vsys1 named, vsys2 renamed)", n, err)
	}
}
