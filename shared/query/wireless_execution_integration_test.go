package query_test

// The wireless fields on the asset target (QUERY_LANGUAGE §15, DCIM row 4.4)
// over real rows: an asset matches by the wireless LANs its interfaces serve.
//
// Mutation: drop the `ifc.asset_id = a.id` correlation from sql/wireless.go ->
// every asset matches and "only the access point" goes red; drop the rejected
// filter on the LAN -> "a rejected LAN does not match" goes red.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_QueryWirelessFields(t *testing.T) {
	db := testdb.Connect(t)
	requireInventorySchema(t, db)
	testdb.HoldSchemaShareLock(t, db)
	tenant := testdb.NewTenant(t, db)

	guest := ipamRow(t, db, `INSERT INTO wireless_lans (tenant_id, ssid, auth_type, auth_cipher) VALUES ($1, 'Guest', 'wpa-personal', 'tkip') RETURNING id`, tenant)
	lobby := ipamRow(t, db, `INSERT INTO wireless_lans (tenant_id, ssid, auth_type) VALUES ($1, 'Lobby', 'open') RETURNING id`, tenant)
	gone := ipamRow(t, db, `INSERT INTO wireless_lans (tenant_id, ssid, auth_type, status) VALUES ($1, 'Rejected', 'wep', 'rejected') RETURNING id`, tenant)

	ap := insertAsset(t, db, tenant, "ap-1", 0, nil)
	ap2 := insertAsset(t, db, tenant, "ap-2", 0, nil)
	sw := insertAsset(t, db, tenant, "switch", 0, nil)
	for _, r := range []struct {
		asset uuid.UUID
		name  string
		lans  []uuid.UUID
	}{{ap, "ra0", []uuid.UUID{guest, lobby}}, {ap2, "ra0", []uuid.UUID{gone}}, {sw, "Port 1", nil}} {
		ids := make([]string, len(r.lans))
		for i, l := range r.lans {
			ids[i] = l.String()
		}
		arr := "{" + joinComma(ids) + "}"
		if _, err := db.Exec(`INSERT INTO interfaces (tenant_id, asset_id, name, type, wireless_lan_ids) VALUES ($1, $2, $3, 'other', $4::uuid[])`,
			tenant, r.asset, r.name, arr); err != nil {
			t.Fatal(err)
		}
	}

	only := func(t *testing.T, q string, want ...uuid.UUID) {
		t.Helper()
		got := matchIDs(t, db, tenant, q)
		for _, w := range want {
			if !got[w] {
				t.Errorf("%q: missing %s", q, w)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%q: matched %d assets, want %d (%v)", q, len(got), len(want), got)
		}
	}
	t.Run("only the access point", func(t *testing.T) {
		only(t, "wireless_lan.ssid:guest", ap)
		only(t, "wireless_lan.ssid=Lobby", ap)
		only(t, "wireless_lan.auth_type:open", ap)
		only(t, "wireless_lan.auth_type in (open, wep)", ap)
	})
	t.Run("a rejected LAN does not match", func(t *testing.T) {
		only(t, "wireless_lan.ssid=Rejected")
		only(t, "wireless_lan.auth_type:wep")
	})
	t.Run("!= negates the whole EXISTS", func(t *testing.T) {
		only(t, "wireless_lan.auth_type != open", ap2, sw)
	})
	t.Run("exists", func(t *testing.T) {
		only(t, "exists(wireless_lan.ssid)", ap)
	})
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}
