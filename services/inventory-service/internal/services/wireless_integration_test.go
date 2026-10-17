package services

// Wireless (DCIM row 4.4) through the real service over the real schema as the
// app role (RLS on). Mutations that must turn each red are in the comments.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type wirelessFixture struct {
	owner, app *sql.DB
	svc        *WirelessService
	tenant     uuid.UUID
	ctx        context.Context
}

func newWirelessFixture(t *testing.T) *wirelessFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	return &wirelessFixture{owner: owner, app: app, svc: NewWirelessService(app), tenant: testdb.NewTenant(t, owner), ctx: ipamTestCtx()}
}

func (f *wirelessFixture) create(t *testing.T, route string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	raw, err := f.svc.Create(f.ctx, f.tenant, route, b)
	if err != nil {
		t.Fatalf("create %s %s: %v", route, b, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *wirelessFixture) algorithm(t *testing.T, id any) string {
	t.Helper()
	if id == nil {
		return ""
	}
	var code string
	if err := f.owner.QueryRow(`SELECT code FROM algorithms WHERE id = $1`, fmt.Sprint(id)).Scan(&code); err != nil {
		t.Fatal(err)
	}
	return code
}

// The cipher is scored by the catalogue row it points at; a PSK has no field.
// Mutation: drop `prepareWirelessAuth(ctx, tx, row)` from the wireless-lans
// Prepare -> algorithm_id stays NULL and the first assertion fails.
func TestIntegration_Wireless_CRUDScoresCipherThroughCatalogue(t *testing.T) {
	f := newWirelessFixture(t)
	grp := f.create(t, "wireless-lan-groups", map[string]any{"name": "HQ Campus"})
	if grp["slug"] != "hq-campus" {
		t.Fatalf("group slug not derived: %v", grp["slug"])
	}
	cases := []struct{ ssid, auth, cipher, want string }{
		{"Corp", "wpa-personal", "aes", "WIFI-CCMP"},
		{"Legacy", "wpa-personal", "tkip", "WIFI-TKIP"},
		{"Old", "wep", "", "WIFI-WEP"},
		{"Lobby", "open", "", "WIFI-OPEN"},
		{"Auto", "wpa-personal", "auto", ""},
		{"Blank", "", "", ""},
	}
	for _, c := range cases {
		body := map[string]any{"ssid": c.ssid, "group_id": grp["id"], "auth_psk_present": c.auth == "wpa-personal"}
		if c.auth != "" {
			body["auth_type"] = c.auth
		}
		if c.cipher != "" {
			body["auth_cipher"] = c.cipher
		}
		lan := f.create(t, "wireless-lans", body)
		if got := f.algorithm(t, lan["algorithm_id"]); got != c.want {
			t.Errorf("%s (%s/%s): algorithm %q, want %q", c.ssid, c.auth, c.cipher, got, c.want)
		}
	}
	// Changing the cipher re-points the row.
	lan := f.create(t, "wireless-lans", map[string]any{"ssid": "Flip", "auth_type": "wpa-personal", "auth_cipher": "tkip"})
	raw, err := f.svc.Update(f.ctx, f.tenant, "wireless-lans", idOf(lan), []byte(`{"auth_cipher":"aes"}`))
	if err != nil {
		t.Fatal(err)
	}
	var upd map[string]any
	_ = json.Unmarshal(raw, &upd)
	if got := f.algorithm(t, upd["algorithm_id"]); got != "WIFI-CCMP" {
		t.Errorf("after tkip -> aes the algorithm is %q", got)
	}
	// A key has no field, and neither has the computed pointer.
	for _, body := range []string{`{"ssid":"X","psk":"hunter2"}`, `{"ssid":"X","passphrase":"hunter2"}`, `{"ssid":"X","algorithm_id":"` + uuid.NewString() + `"}`} {
		if _, err := f.svc.Create(f.ctx, f.tenant, "wireless-lans", []byte(body)); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: err = %v, want invalid", body, err)
		}
	}
	// Enumerations and the SSID bound.
	for _, body := range []string{`{"ssid":"X","auth_type":"wpa9"}`, `{"ssid":"X","auth_type":"open","auth_cipher":"aes"}`,
		`{"ssid":"X","auth_cipher":"aes"}`, `{"ssid":"` + string(make([]byte, 33)) + `"}`, `{"ssid":""}`} {
		if _, err := f.svc.Create(f.ctx, f.tenant, "wireless-lans", []byte(body)); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: err = %v, want invalid", body, err)
		}
	}
	// Identity (ssid, group): a duplicate is a conflict; the same SSID ungrouped is not.
	if _, err := f.svc.Create(f.ctx, f.tenant, "wireless-lans", wlJSON(map[string]any{"ssid": "Corp", "group_id": grp["id"]})); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("duplicate (ssid, group): err = %v, want conflict", err)
	}
	f.create(t, "wireless-lans", map[string]any{"ssid": "Corp"})
	// Every write recorded a change.
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'wireless_lan'`, f.tenant).Scan(&n); err != nil || n < 8 {
		t.Errorf("wireless_lan changes recorded = %d (%v), want >= 8", n, err)
	}
}

func wlJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// RLS: another tenant sees nothing; the app role with no tenant context sees nothing.
// Mutation: drop a wireless_*_tenant_isolation policy -> a read leaks.
func TestIntegration_Wireless_RLSIsolatesTenants(t *testing.T) {
	f := newWirelessFixture(t)
	lan := f.create(t, "wireless-lans", map[string]any{"ssid": "Corp", "auth_type": "open"})
	grp := f.create(t, "wireless-lan-groups", map[string]any{"name": "G"})
	other := testdb.NewTenant(t, f.owner)
	for _, route := range []string{"wireless-lans", "wireless-lan-groups", "wireless-links"} {
		items, total, err := f.svc.List(f.ctx, other, route, IPAMListParams{Limit: 50})
		if err != nil || total != 0 || len(items) != 0 {
			t.Errorf("%s: other tenant sees %d rows (%v)", route, total, err)
		}
	}
	if _, err := f.svc.Get(f.ctx, other, "wireless-lans", idOf(lan)); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("cross-tenant get: %v, want not found", err)
	}
	if _, err := f.svc.Update(f.ctx, other, "wireless-lan-groups", idOf(grp), []byte(`{"name":"hijack"}`)); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("cross-tenant update: %v, want not found", err)
	}
	// The insert path across tenants: RLS USING doubles as WITH CHECK.
	if _, err := f.app.Exec(`INSERT INTO wireless_lans (tenant_id, ssid) VALUES ($1, 'sneak')`, f.tenant); err == nil {
		t.Error("an insert with no tenant context succeeded on the app role")
	}
	for _, table := range []string{"wireless_lans", "wireless_lan_groups", "wireless_links"} {
		var n int
		if err := f.app.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d rows visible with no tenant context (%v)", table, n, err)
		}
	}
}

// Deleting a LAN strips it from the interfaces that served it; a link needs
// two distinct interfaces; the pair is unique either way round.
func TestIntegration_Wireless_LinksAndLANDelete(t *testing.T) {
	f := newWirelessFixture(t)
	asset := ifaceSeedAsset(t, f.owner, f.tenant, "monitoring")
	asset2 := ifaceSeedAsset(t, f.owner, f.tenant, "monitoring")
	mk := func(a uuid.UUID, name string) uuid.UUID {
		var id uuid.UUID
		if err := f.owner.QueryRow(`INSERT INTO interfaces (tenant_id, asset_id, name, type) VALUES ($1, $2, $3, 'ieee802.11ac') RETURNING id`, f.tenant, a, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b := mk(asset, "ra0"), mk(asset2, "sta0")
	lan := f.create(t, "wireless-lans", map[string]any{"ssid": "Mesh", "auth_type": "wpa-personal", "auth_cipher": "aes"})
	if _, err := f.owner.Exec(`UPDATE interfaces SET wireless_lan_ids = ARRAY[$2::uuid] WHERE id = $1`, a, idOf(lan)); err != nil {
		t.Fatal(err)
	}
	link := f.create(t, "wireless-links", map[string]any{"interface_a_id": a.String(), "interface_b_id": b.String(), "ssid": "Mesh",
		"auth_type": "wpa-personal", "auth_cipher": "aes", "distance": 120.5, "distance_unit": "m"})
	if f.algorithm(t, link["algorithm_id"]) != "WIFI-CCMP" {
		t.Errorf("link not scored: %v", link["algorithm_id"])
	}
	for name, body := range map[string]map[string]any{
		"same end":         {"interface_a_id": a.String(), "interface_b_id": a.String()},
		"reversed pair":    {"interface_a_id": b.String(), "interface_b_id": a.String()},
		"missing end":      {"interface_a_id": a.String(), "interface_b_id": uuid.NewString()},
		"distance no unit": {"interface_a_id": a.String(), "interface_b_id": mk(asset, "ra9").String(), "distance": 5},
	} {
		_, err := f.svc.Create(f.ctx, f.tenant, "wireless-links", wlJSON(body))
		if err == nil || (!errors.Is(err, ErrIPAMInvalid) && !errors.Is(err, ErrIPAMConflict)) {
			t.Errorf("%s: err = %v, want invalid or conflict", name, err)
		}
	}
	// Mutation: drop the AfterWrite on wireless-lans -> the interface keeps a dangling id.
	if err := f.svc.Delete(f.ctx, f.tenant, "wireless-lans", idOf(lan)); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := f.owner.QueryRow(`SELECT cardinality(wireless_lan_ids) FROM interfaces WHERE id = $1`, a).Scan(&left); err != nil || left != 0 {
		t.Errorf("interface still serves %d deleted LAN(s) (%v)", left, err)
	}
	// Deleting an interface removes its links.
	if _, err := f.owner.Exec(`DELETE FROM interfaces WHERE id = $1`, b); err != nil {
		t.Fatal(err)
	}
	var links int
	if err := f.owner.QueryRow(`SELECT count(*) FROM wireless_links WHERE tenant_id = $1`, f.tenant).Scan(&links); err != nil || links != 0 {
		t.Errorf("%d links survive a deleted interface (%v)", links, err)
	}
}

// Intake's measured upsert: a new LAN arrives pending; a second sighting
// refreshes the measurements; a DECLARED LAN keeps what a person said.
func TestIntegration_Wireless_ObservedUpsertMeasuredFieldsOnly(t *testing.T) {
	f := newWirelessFixture(t)
	id, created, err := f.svc.UpsertObservedWirelessLAN(f.ctx, f.tenant, "unifi", ObservedWirelessLAN{SSID: "Guest", AuthType: "wpa-personal", AuthCipher: "tkip", PSKPresent: true, Group: "Site A"})
	if err != nil || !created {
		t.Fatalf("first upsert: created=%v err=%v", created, err)
	}
	row := func() (status, cipher, algo, kind string, count int) {
		if err := f.owner.QueryRow(`SELECT l.status, COALESCE(l.auth_cipher,''), COALESCE(a.code,''), l.source_kind, l.observation_count
			FROM wireless_lans l LEFT JOIN algorithms a ON a.id = l.algorithm_id WHERE l.id = $1`, id).Scan(&status, &cipher, &algo, &kind, &count); err != nil {
			t.Fatal(err)
		}
		return
	}
	if st, c, a, k, n := row(); st != "pending" || c != "tkip" || a != "WIFI-TKIP" || k != "measured" || n != 1 {
		t.Fatalf("new LAN = %s/%s/%s/%s/%d", st, c, a, k, n)
	}
	id2, created, err := f.svc.UpsertObservedWirelessLAN(f.ctx, f.tenant, "unifi", ObservedWirelessLAN{SSID: "Guest", AuthType: "wpa-personal", AuthCipher: "aes", PSKPresent: true, Group: "Site A"})
	if err != nil || created || id2 != id {
		t.Fatalf("second upsert: id=%v created=%v err=%v", id2, created, err)
	}
	if _, c, a, _, n := row(); c != "aes" || a != "WIFI-CCMP" || n != 2 {
		t.Errorf("refresh = %s/%s/%d, want aes/WIFI-CCMP/2", c, a, n)
	}
	// A declared LAN keeps its declared authentication.
	decl := f.create(t, "wireless-lans", map[string]any{"ssid": "Declared", "auth_type": "wpa-enterprise", "auth_cipher": "aes", "description": "mine"})
	if _, _, err := f.svc.UpsertObservedWirelessLAN(f.ctx, f.tenant, "unifi", ObservedWirelessLAN{SSID: "Declared", AuthType: "open"}); err != nil {
		t.Fatal(err)
	}
	var at, desc string
	if err := f.owner.QueryRow(`SELECT auth_type, description FROM wireless_lans WHERE id = $1`, idOf(decl)).Scan(&at, &desc); err != nil || at != "wpa-enterprise" || desc != "mine" {
		t.Errorf("declared LAN = %s/%s (%v), want wpa-enterprise/mine", at, desc, err)
	}
}
