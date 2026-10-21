package services

// The IP Addresses tab's server side over the real schema as the app role:
// the ip-addresses list's asset_id filter and per-asset flags, and
// PATCH primary-ips (family enforcement, held-by-asset rule, clearing, change
// record, tenant isolation).
//
// Mutations (each must turn a test red): drop the family check in
// checkAddress; drop the `held` check; drop assetHeldFilter's interface arm
// or its primary/oob arm; drop the Record call.

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type primaryIPFixture struct {
	*ipamFixture
	asset, other uuid.UUID
	ifc          uuid.UUID
}

func newPrimaryIPFixture(t *testing.T) *primaryIPFixture {
	t.Helper()
	f := &primaryIPFixture{ipamFixture: newIPAMFixture(t)}
	mk := func(name string) uuid.UUID {
		var id uuid.UUID
		if err := f.owner.QueryRow(`INSERT INTO assets (tenant_id, class_key, class_path, display_name)
			VALUES ($1, 'switch', 'hardware.network.switch', $2) RETURNING id`, f.tenant, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	f.asset, f.other = mk("sw-a"), mk("sw-b")
	if err := f.owner.QueryRow(`INSERT INTO interfaces (tenant_id, asset_id, name, type) VALUES ($1, $2, 'Vlan1', 'virtual') RETURNING id`,
		f.tenant, f.asset).Scan(&f.ifc); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *primaryIPFixture) addr(t *testing.T, address string, assigned *uuid.UUID) uuid.UUID {
	body := map[string]any{"address": address}
	if assigned != nil {
		body["assigned_kind"], body["assigned_id"] = "interface", assigned.String()
	}
	return idOf(f.create(t, "ip-addresses", body))
}

func (f *primaryIPFixture) listFor(t *testing.T, asset uuid.UUID) []map[string]any {
	t.Helper()
	rows, _, err := f.svc.List(f.ctx, f.tenant, "ip-addresses", IPAMListParams{Filters: map[string]string{"asset_id": asset.String()}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, r := range rows {
		var m map[string]any
		_ = json.Unmarshal(r, &m)
		out = append(out, m)
	}
	return out
}

func (f *primaryIPFixture) patch(asset uuid.UUID, body string) (*AssetPrimaryIPs, error) {
	var p AssetPrimaryIPsPatch
	_ = json.Unmarshal([]byte(body), &p)
	return NewAssetPrimaryIPService(f.app).Update(f.ctx, f.tenant, asset, p)
}

func TestIntegration_IpAddressesList_AssetFilter(t *testing.T) {
	f := newPrimaryIPFixture(t)
	viaIface := f.addr(t, "10.9.0.1/24", &f.ifc)
	ifaceOnly := f.addr(t, "10.9.0.4/24", &f.ifc) // held only through its interface (no column names it)
	bare := f.addr(t, "10.9.0.2/24", nil)         // held only as the asset's OOB address
	f.addr(t, "10.9.0.3/24", nil)                 // held by nobody
	if _, err := f.patch(f.asset, fmt.Sprintf(`{"primary_ip4_id":%q}`, viaIface)); err != nil {
		t.Fatal(err)
	}
	// An address that is only named in the OOB column is held too (the second arm).
	if _, err := f.owner.Exec(`UPDATE assets SET oob_ip_id = $1 WHERE id = $2`, bare, f.asset); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, r := range f.listFor(t, f.asset) {
		got[fmt.Sprint(r["id"])] = r
	}
	if len(got) != 3 || got[viaIface.String()] == nil || got[bare.String()] == nil || got[ifaceOnly.String()] == nil {
		t.Fatalf("asset_id filter returned %d rows, want the interface-held, the interface-only and the OOB-held address: %v", len(got), got)
	}
	a := got[viaIface.String()]["asset"].(map[string]any)
	if a["is_primary_ip4"] != true || a["is_primary_ip6"] != false || a["is_oob_ip"] != true && a["is_oob_ip"] != false {
		t.Fatalf("flags on the primary address: %v", a)
	}
	if o := got[bare.String()]["asset"].(map[string]any); o["is_oob_ip"] != true || o["is_primary_ip4"] != false {
		t.Fatalf("flags on the OOB address: %v", o)
	}
	if rows := f.listFor(t, f.other); len(rows) != 0 {
		t.Fatalf("another asset holds %d addresses, want 0", len(rows))
	}
	if _, _, err := f.svc.List(f.ctx, f.tenant, "ip-addresses", IPAMListParams{Filters: map[string]string{"asset_id": "nope"}, Limit: 10}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a malformed asset_id: %v, want ErrIPAMInvalid", err)
	}
}

func TestIntegration_AssetPrimaryIPs_Rules(t *testing.T) {
	f := newPrimaryIPFixture(t)
	v4 := f.addr(t, "10.9.1.1/24", &f.ifc)
	v6 := f.addr(t, "2001:db8:9::1/64", &f.ifc)
	foreign := f.addr(t, "10.9.1.9/24", nil)

	out, err := f.patch(f.asset, fmt.Sprintf(`{"primary_ip4_id":%q,"primary_ip6_id":%q,"oob_ip_id":%q}`, v4, v6, v4))
	if err != nil || out.PrimaryIP4ID == nil || *out.PrimaryIP4ID != v4 || *out.PrimaryIP6ID != v6 || *out.OOBIPID != v4 {
		t.Fatalf("set all three: %+v, %v", out, err)
	}
	for name, body := range map[string]string{
		"IPv6 into primary_ip4": fmt.Sprintf(`{"primary_ip4_id":%q}`, v6),
		"IPv4 into primary_ip6": fmt.Sprintf(`{"primary_ip6_id":%q}`, v4),
		"address not held":      fmt.Sprintf(`{"primary_ip4_id":%q}`, foreign),
		"unknown address":       fmt.Sprintf(`{"oob_ip_id":%q}`, uuid.New()),
		"not a uuid":            `{"oob_ip_id":"x"}`,
		"unknown field":         `{"primary_address":null}`,
		"empty":                 `{}`,
	} {
		if _, err := f.patch(f.asset, body); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: %v, want ErrIPAMInvalid", name, err)
		}
	}
	// Nothing above changed the row.
	var p4 uuid.UUID
	if err := f.owner.QueryRow(`SELECT primary_ip4_id FROM assets WHERE id = $1`, f.asset).Scan(&p4); err != nil || p4 != v4 {
		t.Fatalf("a refused write changed primary_ip4_id: %v %v", p4, err)
	}
	if _, err := f.patch(uuid.New(), `{"oob_ip_id":null}`); !errors.Is(err, ErrCatalogueAssetNotFound) {
		t.Fatalf("missing asset: %v", err)
	}

	// Clearing one leaves the others; it is one change record with before/after.
	out, err = f.patch(f.asset, `{"oob_ip_id":null}`)
	if err != nil || out.OOBIPID != nil || out.PrimaryIP4ID == nil {
		t.Fatalf("clear oob: %+v, %v", out, err)
	}
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_id = $2 AND action = 'update'
		AND postchange_data->>'oob_ip_id' IS NULL AND prechange_data->>'oob_ip_id' = $3`, f.tenant, f.asset, v4.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("clear recorded %d matching change rows (%v), want 1", n, err)
	}
	// A no-op write records nothing.
	before := countChanges(t, f)
	if _, err := f.patch(f.asset, fmt.Sprintf(`{"primary_ip4_id":%q}`, v4)); err != nil {
		t.Fatal(err)
	}
	if countChanges(t, f) != before {
		t.Fatal("re-setting the same address recorded a change")
	}
}

func countChanges(t *testing.T, f *primaryIPFixture) int {
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_id = $2`, f.tenant, f.asset).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntegration_AssetPrimaryIPs_TenantIsolation(t *testing.T) {
	f := newPrimaryIPFixture(t)
	v4 := f.addr(t, "10.9.2.1/24", &f.ifc)
	otherTenant := testdb.NewTenant(t, f.owner)
	_, err := NewAssetPrimaryIPService(f.app).Update(f.ctx, otherTenant, f.asset, AssetPrimaryIPsPatch{"primary_ip4_id": json.RawMessage(fmt.Sprintf("%q", v4))})
	if !errors.Is(err, ErrCatalogueAssetNotFound) {
		t.Fatalf("another tenant patching this asset: %v, want not found", err)
	}
}
