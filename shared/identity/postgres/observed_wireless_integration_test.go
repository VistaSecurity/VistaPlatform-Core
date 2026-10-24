package postgres_test

// DCIM row 4.4: the wireless half of an observation, written by
// RecordObservedNetwork on the engine's transaction -- LANs, the interfaces
// that serve them, links and stations -- and the rule that no key material
// has a field to travel in.

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
	// Each LAN is measured, active because the AP serving it is approved, and
	// scored through the catalogue.
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
	want := []string{"Corp/active/measured/WIFI-CCMP//vlan20", "Guest/active/measured/WIFI-TKIP/HQ/psk/vlan00"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("LANs = %v, want %v", got, want)
	}
	// So is the VLAN the approved AP's LAN created.
	var vlanStatus string
	if err := owner.QueryRow(`SELECT status FROM vlans WHERE tenant_id = $1 AND vid = 20`, tenant).Scan(&vlanStatus); err != nil || vlanStatus != "active" {
		t.Errorf("VLAN 20 = %q (%v), want active", vlanStatus, err)
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

// A LAN and a VLAN follow the access point that reports them, as its
// interfaces do: pending from an unapproved device, promoted to active the
// next time an approved device reports them. What a person decided (archived)
// and what a person declared are never moved.
func TestIntegration_RecordObservedNetwork_WirelessFollowsTheAsset(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	repo := postgres.New(app)
	ctx := context.Background()

	ap := uuid.New()
	if _, err := owner.Exec(`INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
		VALUES ($1, $2, 'ap-new', 'ap-new', 'switch', 'hardware.network.switch', 'pending_approval')`, ap, tenant); err != nil {
		t.Fatal(err)
	}
	// A person's declared LAN, still pending, and a LAN a person archived.
	if _, err := owner.Exec(`INSERT INTO wireless_lans (tenant_id, ssid, source_kind, status) VALUES ($1, 'Declared', 'declared', 'pending'), ($1, 'Retired', 'measured', 'archived')`, tenant); err != nil {
		t.Fatal(err)
	}
	obs := identity.ObservedNetwork{
		Interfaces: []identity.ObservedInterface{{Name: "ra0", Type: "ieee802.11n", RFRole: "ap", SSIDs: []string{"Staff", "Declared", "Retired"}}},
		WirelessLANs: []identity.ObservedWirelessLAN{
			{SSID: "Staff", AuthType: "wpa-personal", AuthCipher: "aes", VLAN: 30},
			{SSID: "Declared", AuthType: "wpa-personal", AuthCipher: "aes"},
			{SSID: "Retired", AuthType: "wpa-personal", AuthCipher: "aes"},
		},
	}
	record := func() {
		t.Helper()
		obs.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:test", Mode: identity.ModeActive}
		obs.ObservedAt = time.Now().UTC()
		if _, err := repo.RecordObservedNetwork(ctx, identity.AssetRef{TenantID: tenant.String(), ID: ap.String()}, obs); err != nil {
			t.Fatal(err)
		}
	}
	statuses := func() string {
		t.Helper()
		var lans, vlan string
		if err := owner.QueryRow(`SELECT string_agg(ssid || '=' || status, ',' ORDER BY ssid) FROM wireless_lans WHERE tenant_id = $1`, tenant).Scan(&lans); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(`SELECT status FROM vlans WHERE tenant_id = $1 AND vid = 30`, tenant).Scan(&vlan); err != nil {
			t.Fatal(err)
		}
		return lans + " vlan30=" + vlan
	}

	// An unapproved AP's LAN and VLAN wait for approval, as its interfaces do.
	record()
	if got, want := statuses(), "Declared=pending,Retired=archived,Staff=pending vlan30=pending"; got != want {
		t.Fatalf("from an unapproved AP: %s, want %s", got, want)
	}
	// Approved, the next report promotes what it measured -- and only that.
	if _, err := owner.Exec(`UPDATE assets SET asset_status = 'monitoring' WHERE id = $1`, ap); err != nil {
		t.Fatal(err)
	}
	record()
	if got, want := statuses(), "Declared=pending,Retired=archived,Staff=active vlan30=active"; got != want {
		t.Fatalf("from the approved AP: %s, want %s", got, want)
	}
	var changed int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'wireless_lan'
		AND action = 'update' AND postchange_data->>'status' = 'active'`, tenant).Scan(&changed); err != nil || changed != 1 {
		t.Errorf("%d recorded promotions of a LAN (%v), want 1", changed, err)
	}
	// A stale measured LAN comes back with the approved AP.
	if _, err := owner.Exec(`UPDATE wireless_lans SET status = 'stale' WHERE tenant_id = $1 AND ssid = 'Staff'`, tenant); err != nil {
		t.Fatal(err)
	}
	record()
	if got := statuses(); !strings.Contains(got, "Staff=active") {
		t.Errorf("stale LAN re-reported by an approved AP: %s, want Staff=active", got)
	}
}

// A client's radio joins the LAN an access point reported: its interface
// (found by MAC, here the synthetic one the identity half filed it on) gains
// the LAN, the station role and the 802.11 type. An SSID no AP reported, or
// one two LANs share, is skipped and reported, never created or guessed.
func TestIntegration_RecordObservedNetwork_WirelessStation(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	repo := postgres.New(app)
	ctx := context.Background()

	oven, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{oven, other} {
		if _, err := owner.Exec(`INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
			VALUES ($1, $2, $3, $3, 'switch', 'hardware.network.switch', 'monitoring')`, id, tenant, id.String()[:8]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(`INSERT INTO interfaces (tenant_id, asset_id, name, type, mac_address) VALUES
		($1, $2, 'observed-1', 'other', '28:6b:b4:b0:1b:99'), ($1, $3, 'observed-1', 'other', '02:00:5e:00:53:c3')`, tenant, oven, other); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO wireless_lans (tenant_id, ssid, source_kind, status) VALUES ($1, 'Home', 'measured', 'active')`, tenant); err != nil {
		t.Fatal(err)
	}
	// "Twin" is one SSID in two groups: which one the client joined is not
	// said, so it is not guessed.
	if _, err := owner.Exec(`WITH g AS (INSERT INTO wireless_lan_groups (tenant_id, name, slug) VALUES ($1, 'Site B', 'site-b') RETURNING id)
		INSERT INTO wireless_lans (tenant_id, ssid, group_id, source_kind, status) SELECT $1, 'Twin', NULL, 'measured', 'active'
		UNION ALL SELECT $1, 'Twin', id, 'measured', 'active' FROM g`, tenant); err != nil {
		t.Fatal(err)
	}
	record := func(asset uuid.UUID, st ...identity.ObservedWirelessStation) identity.ObservedNetworkResult {
		t.Helper()
		res, err := repo.RecordObservedNetwork(ctx, identity.AssetRef{TenantID: tenant.String(), ID: asset.String()}, identity.ObservedNetwork{
			WirelessStations: st,
			Source:           identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:test", Mode: identity.ModeActive},
			ObservedAt:       time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	station := func(asset uuid.UUID) string {
		t.Helper()
		var typ, role, lans string
		if err := owner.QueryRow(`SELECT i.type, COALESCE(i.rf_role, ''),
			COALESCE((SELECT string_agg(l.ssid, ',' ORDER BY l.ssid) FROM wireless_lans l WHERE l.id = ANY(i.wireless_lan_ids)), '')
			FROM interfaces i WHERE i.tenant_id = $1 AND i.asset_id = $2`, tenant, asset).Scan(&typ, &role, &lans); err != nil {
			t.Fatal(err)
		}
		return typ + "/" + role + "/" + lans
	}

	res := record(oven, identity.ObservedWirelessStation{MAC: "28:6b:b4:b0:1b:99", SSID: "Home", Type: "ieee802.11ax"})
	if len(res.Skipped) != 0 {
		t.Fatalf("skipped %v", res.Skipped)
	}
	if got, want := station(oven), "ieee802.11ax/station/Home"; got != want {
		t.Fatalf("oven's interface = %s, want %s", got, want)
	}
	// Re-reported: nothing changes, nothing is recorded twice.
	var before, after int
	countChanges := func() int {
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'interface'`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before = countChanges()
	record(oven, identity.ObservedWirelessStation{MAC: "28:6b:b4:b0:1b:99", SSID: "Home", Type: "ieee802.11ax"})
	if after = countChanges(); after != before {
		t.Errorf("a repeated station report recorded %d changes", after-before)
	}

	// Not the observed asset's MAC, an SSID no AP reported, an ambiguous SSID:
	// each skipped with a reason, nothing created.
	res = record(other,
		identity.ObservedWirelessStation{MAC: "28:6b:b4:b0:1b:99", SSID: "Home"},
		identity.ObservedWirelessStation{MAC: "02:00:5e:00:53:c3", SSID: "Nowhere"},
	)
	if len(res.Skipped) != 2 {
		t.Errorf("skipped %v, want the foreign MAC and the unknown SSID", res.Skipped)
	}
	res = record(other, identity.ObservedWirelessStation{MAC: "02:00:5e:00:53:c3", SSID: "Twin"})
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "2 wireless LANs") {
		t.Errorf("skipped %v, want the ambiguous SSID", res.Skipped)
	}
	if got, want := station(other), "other//"; got != want {
		t.Errorf("other's interface = %s, want it untouched (%s)", got, want)
	}
	var lans int
	if err := owner.QueryRow(`SELECT count(*) FROM wireless_lans WHERE tenant_id = $1`, tenant).Scan(&lans); err != nil || lans != 3 {
		t.Errorf("%d LANs (%v), want 3: a station creates none", lans, err)
	}
}

// The types that carry a LAN from a collector hold no key: if a field named
// like key material appears on either type, this fails and the author has to
// say why. PSKPresent is a bool and the one permitted spelling.
func TestObservedWireless_TypesCarryNoKeyMaterial(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(identity.ObservedWirelessLAN{}), reflect.TypeOf(identity.ObservedWirelessLink{}),
		reflect.TypeOf(identity.ObservedWirelessStation{})} {
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
