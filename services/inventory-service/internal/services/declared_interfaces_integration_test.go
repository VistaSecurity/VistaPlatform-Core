package services

// DCIM row 1.5f: the declared adapters of the intake seam — NetBox import (the
// internal source route), spreadsheet import and manual create — write the
// interfaces and addresses they state through the identity engine, with the
// declaration's own source kind, and the source's own ids on the rows.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// declaredIface is one interface row of an asset, with its addresses.
type declaredIface struct {
	Name, SourceKind, MAC, Mode string
	VLAN                        int
	ExternalIDs                 map[string]any
	Addresses                   []string // "host/len kind netbox=<id>"
}

func readDeclaredInterfaces(t *testing.T, db *database.DB, tenant, asset uuid.UUID) map[string]declaredIface {
	t.Helper()
	out := map[string]declaredIface{}
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(`
			SELECT i.id, i.name, i.source_kind, coalesce(i.mac_address::macaddr::text, ''), coalesce(i.mode, ''),
			       coalesce(v.vid, 0), i.external_ids
			  FROM interfaces i LEFT JOIN vlans v ON v.tenant_id = i.tenant_id AND v.id = i.untagged_vlan_id
			 WHERE i.tenant_id = $1 AND i.asset_id = $2 AND i.status <> 'rejected'`, tenant, asset)
		if err != nil {
			return err
		}
		ids := map[string]uuid.UUID{}
		for rows.Next() {
			var (
				id  uuid.UUID
				d   declaredIface
				raw []byte
			)
			if err := rows.Scan(&id, &d.Name, &d.SourceKind, &d.MAC, &d.Mode, &d.VLAN, &raw); err != nil {
				return err
			}
			_ = json.Unmarshal(raw, &d.ExternalIDs)
			out[d.Name], ids[d.Name] = d, id
		}
		_ = rows.Close()
		for name, id := range ids {
			ar, err := tx.Query(`
				SELECT host(address) || '/' || masklen(address), source_kind, coalesce(external_ids ->> 'netbox', '')
				  FROM ip_addresses WHERE tenant_id = $1 AND assigned_kind = 'interface' AND assigned_id = $2`, tenant, id)
			if err != nil {
				return err
			}
			d := out[name]
			for ar.Next() {
				var addr, kind, nb string
				if err := ar.Scan(&addr, &kind, &nb); err != nil {
					return err
				}
				entry := addr + " " + kind
				if nb != "" {
					entry += " netbox=" + nb
				}
				d.Addresses = append(d.Addresses, entry)
			}
			_ = ar.Close()
			sort.Strings(d.Addresses)
			out[name] = d
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rowCounts(t *testing.T, db *database.DB, tenant uuid.UUID) string {
	t.Helper()
	var parts []string
	for _, table := range []string{"assets", "interfaces", "ip_addresses", "vlans"} {
		var n int
		if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
			return tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenant).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, table+"="+itoaTest(n))
	}
	return strings.Join(parts, " ")
}

func itoaTest(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func boolp(v bool) *bool { return &v }

// declaredAssets is the asset service the spreadsheet and manual paths call.
func declaredAssets(f *sourceFixture) *AssetService {
	return NewAssetService(f.db)
}

// TestIntegration_DeclaredInterfaces_NetBoxImportStampsExternalIDs: a NetBox
// device's interfaces, declared through the internal source route the
// importer calls, become `imported` interfaces and addresses carrying
// `external_ids.netbox` — the key the bidirectional sync matches on — and a
// second import changes nothing.
//
// Mutations, each red: remove the declaredInterfaces call in declaredSighting
// (no interface rows); remove the stampDeclaredExternalIDs call in
// createAssetResolved (no external ids); take the source kind out of the
// seam writer's interface insert (Gi1/0/2 lands `measured`).
func TestIntegration_DeclaredInterfaces_NetBoxImportStampsExternalIDs(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	netbox := identity.Source{Kind: identity.SourceImported, Ref: "netbox:" + uuid.NewString()}

	item := sourceHost("NB-SERIAL-301", "192.0.2.11", "ams-core-sw-01")
	item.Input.Interfaces = []models.AssetInterfaceInput{
		{Name: "GigabitEthernet1/0/1", Type: "1000base-t", MACAddress: "00:1b:54:aa:bb:01", MTU: intp(9000),
			Enabled: boolp(true), Mode: "access", UntaggedVLAN: 30, ExternalIDs: map[string]string{"netbox": "9001"},
			Addresses: []models.AssetInterfaceAddressInput{{Address: "192.0.2.11/24", ExternalIDs: map[string]string{"netbox": "7001"}}}},
		// No address and no MAC: posture only, written by the seam's writer.
		{Name: "GigabitEthernet1/0/2", Type: "1000base-t", Enabled: boolp(false), ExternalIDs: map[string]string{"netbox": "9002"}},
	}

	first := f.svc.ResolveAssets(ctx, tenant, netbox, []SourceAssetItem{item})
	if first[0].AssetID == nil {
		t.Fatalf("import resolved to no asset: %+v", first[0])
	}
	asset := *first[0].AssetID
	before := rowCounts(t, f.db, tenant)

	got := readDeclaredInterfaces(t, f.db, tenant, asset)
	gi1, gi2 := got["GigabitEthernet1/0/1"], got["GigabitEthernet1/0/2"]
	if len(got) != 2 {
		t.Fatalf("interfaces = %+v, want exactly the two NetBox declared", got)
	}
	if gi1.SourceKind != "imported" || gi1.MAC != "00:1b:54:aa:bb:01" || gi1.Mode != "access" || gi1.VLAN != 30 ||
		gi1.ExternalIDs["netbox"] != "9001" {
		t.Errorf("Gi1/0/1 = %+v", gi1)
	}
	if strings.Join(gi1.Addresses, ",") != "192.0.2.11/24 imported netbox=7001" {
		t.Errorf("Gi1/0/1 addresses = %v", gi1.Addresses)
	}
	if gi2.SourceKind != "imported" || gi2.ExternalIDs["netbox"] != "9002" || len(gi2.Addresses) != 0 {
		t.Errorf("Gi1/0/2 = %+v", gi2)
	}

	second := f.svc.ResolveAssets(ctx, tenant, netbox, []SourceAssetItem{item})
	if second[0].AssetID == nil || *second[0].AssetID != asset {
		t.Fatalf("re-import resolved to %v, want %s", second[0].AssetID, asset)
	}
	if after := rowCounts(t, f.db, tenant); after != before {
		t.Errorf("re-import changed the rows: %s → %s", before, after)
	}
}

// TestIntegration_DeclaredInterfaces_SpreadsheetRow: a spreadsheet row's
// interface, MAC, IP, prefix length and VLAN become an imported interface
// with the address at its length on its VLAN; a row with an IP and a MAC but
// no interface name puts both on the one interface the engine names.
//
// Mutation: remove the declaredInterfaces call — red (no eth0, the address
// lands on an engine-named interface at /32).
func TestIntegration_DeclaredInterfaces_SpreadsheetRow(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	spreadsheet := identity.Source{Kind: identity.SourceImported, Ref: identity.SpreadsheetImportSourceRef}
	named := models.AssetInput{
		ClassKey:    string(assetclass.KeyServer),
		Identifiers: []models.AssetIdentifierInput{{Kind: "hostname", Value: "app-07"}},
		Interfaces: []models.AssetInterfaceInput{{Name: "eth0", MACAddress: "b4:96:91:0a:00:07", UntaggedVLAN: 20,
			Addresses: []models.AssetInterfaceAddressInput{{Address: "198.51.100.7", PrefixLength: 24}}}},
	}
	unnamed := models.AssetInput{
		ClassKey:    string(assetclass.KeyServer),
		Identifiers: []models.AssetIdentifierInput{{Kind: "hostname", Value: "app-08"}},
		Interfaces: []models.AssetInterfaceInput{{MACAddress: "b4:96:91:0a:00:08",
			Addresses: []models.AssetInterfaceAddressInput{{Address: "198.51.100.8", PrefixLength: 24}}}},
	}
	res := declaredAssets(f).BulkCreateAssetsFromSource(tenant, []models.AssetInput{named, unnamed}, spreadsheet)
	if res.Failed != 0 {
		t.Fatalf("import failed: %+v", res)
	}
	assetOf := func(host string) uuid.UUID {
		var id uuid.UUID
		if err := database.WithTenantTx(context.Background(), f.db, tenant, func(tx *sqlx.Tx) error {
			return tx.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND display_name = $2`, tenant, host).Scan(&id)
		}); err != nil {
			t.Fatalf("asset %s: %v", host, err)
		}
		return id
	}

	got := readDeclaredInterfaces(t, f.db, tenant, assetOf("app-07"))
	eth0, ok := got["eth0"]
	if !ok || len(got) != 1 {
		t.Fatalf("interfaces = %+v, want eth0", got)
	}
	if eth0.SourceKind != "imported" || eth0.MAC != "b4:96:91:0a:00:07" || eth0.VLAN != 20 || eth0.Mode != "access" {
		t.Errorf("eth0 = %+v", eth0)
	}
	if strings.Join(eth0.Addresses, ",") != "198.51.100.7/24 imported" {
		t.Errorf("eth0 addresses = %v", eth0.Addresses)
	}

	got = readDeclaredInterfaces(t, f.db, tenant, assetOf("app-08"))
	if len(got) != 1 {
		t.Fatalf("unnamed row interfaces = %+v, want the one the engine names", got)
	}
	for name, ifc := range got {
		if !identity.IsSyntheticInterfaceName(name) || ifc.MAC != "b4:96:91:0a:00:08" || len(ifc.Addresses) != 1 ||
			!strings.HasPrefix(ifc.Addresses[0], "198.51.100.8/") {
			t.Errorf("unnamed row interface %s = %+v, want an engine-named interface with the MAC and the address", name, ifc)
		}
	}
}

// TestIntegration_DeclaredInterfaces_ManualCreate: an asset a person adds with
// a named interface gets it as a `declared` interface carrying the address.
func TestIntegration_DeclaredInterfaces_ManualCreate(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	asset, err := declaredAssets(f).CreateAsset(tenant, models.AssetInput{
		ClassKey:    string(assetclass.KeyServer),
		Identifiers: []models.AssetIdentifierInput{{Kind: "hostname", Value: "manual-01"}},
		Interfaces: []models.AssetInterfaceInput{{Name: "ens192", MACAddress: "b4:96:91:0a:00:09",
			Addresses: []models.AssetInterfaceAddressInput{{Address: "203.0.113.9/25"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := readDeclaredInterfaces(t, f.db, tenant, asset.ID)
	ens, ok := got["ens192"]
	if !ok || ens.SourceKind != "declared" || ens.MAC != "b4:96:91:0a:00:09" ||
		strings.Join(ens.Addresses, ",") != "203.0.113.9/25 declared" {
		t.Errorf("interfaces = %+v, want a declared ens192 with 203.0.113.9/25", got)
	}
}
