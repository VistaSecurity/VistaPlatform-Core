package postgres_test

// DCIM row 4.4: the wireless half of an observation, written by
// RecordObservedNetwork on the engine's transaction -- LANs, the interfaces
// that serve them, and links -- and the rule that no key material has a field
// to travel in.

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RecordObservedNetwork_Wireless(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	repo := postgres.New(app)

	mkAsset := func(name string) uuid.UUID {
		id := uuid.New()
		if _, err := owner.Exec(`INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
			VALUES ($1, $2, $3, $3, 'switch', 'hardware.network.switch', 'monitoring')`, id, tenant, name); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ap, peer := mkAsset("ap-1"), mkAsset("ap-2")
	if _, err := owner.Exec(`INSERT INTO interfaces (tenant_id, asset_id, name, type, mac_address) VALUES ($1, $2, 'sta0', 'ieee802.11ac', '02:00:5e:00:53:b2')`, tenant, peer); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	record := func(n identity.ObservedNetwork) identity.ObservedNetworkResult {
		t.Helper()
		n.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:test", Mode: identity.ModeActive}
		n.ObservedAt = time.Now().UTC()
		res, err := repo.RecordObservedNetwork(ctx, identity.AssetRef{TenantID: tenant.String(), ID: ap.String()}, n)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	obs := identity.ObservedNetwork{
		Interfaces: []identity.ObservedInterface{
			{Name: "ra0", Type: "ieee802.11n", RFRole: "ap", SSIDs: []string{"Guest"}, MAC: "02:00:5e:00:53:a1"},
			{Name: "ra1", Type: "ieee802.11ac", RFRole: "ap", SSIDs: []string{"Guest", "Corp"}},
		},
		WirelessLANs: []identity.ObservedWirelessLAN{
			{SSID: "Guest", AuthType: "wpa-personal", AuthCipher: "tkip", PSKPresent: true, Group: "HQ"},
			{SSID: "Corp", AuthType: "wpa-enterprise", AuthCipher: "aes", VLAN: 20},
		},
		WirelessLinks: []identity.ObservedWirelessLink{
			{InterfaceA: "ra1", InterfaceB: "02:00:5e:00:53:b2", SSID: "Mesh"},
			{InterfaceA: "ra1", InterfaceB: "02:00:5e:00:53:ff"},  // no such MAC: skipped, reported
			{InterfaceA: "nope", InterfaceB: "02:00:5e:00:53:b2"}, // no such interface: skipped
		},
	}
	res := record(obs)
	if res.WirelessLANsCreated != 2 || res.WirelessLinksCreated != 1 || len(res.Skipped) != 2 {
		t.Fatalf("first record = %+v, want 2 LANs, 1 link, 2 skipped", res)
	}

	var n int
	// Each LAN is pending/measured and scored through the catalogue.
	rows, err := owner.Query(`SELECT l.ssid, l.status, l.source_kind, l.auth_psk_present, COALESCE(a.code, ''), COALESCE(g.name, ''), COALESCE(v.vid, 0)
		FROM wireless_lans l LEFT JOIN algorithms a ON a.id = l.algorithm_id LEFT JOIN wireless_lan_groups g ON g.id = l.group_id
		LEFT JOIN vlans v ON v.id = l.vlan_id WHERE l.tenant_id = $1 ORDER BY l.ssid`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var ssid, status, kind, algo, group string
		var psk bool
		var vid int
		if err := rows.Scan(&ssid, &status, &kind, &psk, &algo, &group, &vid); err != nil {
			t.Fatal(err)
		}
		got = append(got, strings.Join([]string{ssid, status, kind, algo, group}, "/")+map[bool]string{true: "/psk", false: ""}[psk]+"/vlan"+string(rune('0'+vid/10))+string(rune('0'+vid%10)))
	}
	_ = rows.Close()
	want := []string{"Corp/pending/measured/WIFI-CCMP//vlan20", "Guest/pending/measured/WIFI-TKIP/HQ/psk/vlan00"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("LANs = %v, want %v", got, want)
	}

	// The radios serve what they broadcast, and gained the AP role.
	serving := func(name string) int {
		if err := owner.QueryRow(`SELECT cardinality(wireless_lan_ids) FROM interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = $3`, tenant, ap, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if serving("ra0") != 1 || serving("ra1") != 2 {
		t.Errorf("ra0/ra1 serve %d/%d LANs, want 1/2", serving("ra0"), serving("ra1"))
	}
	var role string
	if err := owner.QueryRow(`SELECT rf_role FROM interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = 'ra0'`, tenant, ap).Scan(&role); err != nil || role != "ap" {
		t.Errorf("rf_role = %q (%v), want ap", role, err)
	}
	if err := owner.QueryRow(`SELECT count(*) FROM wireless_links WHERE tenant_id = $1 AND status = 'pending' AND source_kind = 'measured' AND ssid = 'Mesh'`, tenant).Scan(&n); err != nil || n != 1 {
		t.Errorf("links = %d (%v), want 1 pending measured", n, err)
	}

	// A second sighting refreshes, creates nothing, and the cipher change
	// re-points the catalogue row. A person's declaration is not overwritten.
	if _, err := owner.Exec(`UPDATE wireless_lans SET source_kind = 'declared', description = 'mine' WHERE tenant_id = $1 AND ssid = 'Corp'`, tenant); err != nil {
		t.Fatal(err)
	}
	obs.WirelessLANs[0].AuthCipher = "aes"
	obs.WirelessLANs[1].AuthType = "open"
	obs.WirelessLANs[1].AuthCipher = ""
	res = record(obs)
	if res.WirelessLANsCreated != 0 || res.WirelessLANsUpdated != 2 || res.WirelessLinksCreated != 0 || res.WirelessLinksUpdated != 1 {
		t.Fatalf("second record = %+v", res)
	}
	var algo, authType, desc string
	if err := owner.QueryRow(`SELECT a.code FROM wireless_lans l JOIN algorithms a ON a.id = l.algorithm_id WHERE l.tenant_id = $1 AND l.ssid = 'Guest'`, tenant).Scan(&algo); err != nil || algo != "WIFI-CCMP" {
		t.Errorf("Guest after tkip -> aes: algorithm %q (%v)", algo, err)
	}
	if err := owner.QueryRow(`SELECT auth_type, description FROM wireless_lans WHERE tenant_id = $1 AND ssid = 'Corp'`, tenant).Scan(&authType, &desc); err != nil || authType != "wpa-enterprise" || desc != "mine" {
		t.Errorf("declared Corp = %s/%s (%v), want wpa-enterprise/mine untouched", authType, desc, err)
	}
	if err := owner.QueryRow(`SELECT count(*) FROM wireless_lans WHERE tenant_id = $1`, tenant).Scan(&n); err != nil || n != 2 {
		t.Errorf("%d LANs after a re-observation, want 2", n)
	}

	// RLS: the app role sees nothing without a tenant context.
	var v int
	if err := app.QueryRow(`SELECT count(*) FROM wireless_lans`).Scan(&v); err != nil || v != 0 {
		t.Errorf("%d LANs visible with no tenant context (%v)", v, err)
	}
}

// The types that carry a LAN from a collector hold no key: if a field named
// like key material appears on either type, this fails and the author has to
// say why. PSKPresent is a bool and the one permitted spelling.
func TestObservedWireless_TypesCarryNoKeyMaterial(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(identity.ObservedWirelessLAN{}), reflect.TypeOf(identity.ObservedWirelessLink{})} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			l := strings.ToLower(f.Name)
			if l == "pskpresent" {
				if f.Type.Kind() != reflect.Bool {
					t.Errorf("%s.PSKPresent is %s, want bool", typ.Name(), f.Type)
				}
				continue
			}
			if strings.Contains(l, "psk") || strings.Contains(l, "passphrase") || strings.Contains(l, "secret") || strings.Contains(l, "password") || strings.Contains(l, "key") {
				t.Errorf("%s has field %q", typ.Name(), f.Name)
			}
		}
	}
}
