package dcimfixture

// Wireless populators (BUILD_PLAN row 4.4): one wireless LAN group per site and
// three wireless LANs per group - a WPA2/AES corporate SSID, a WPA/TKIP guest
// SSID and an open lobby SSID - so a scale tenant carries one LAN of each
// catalogue verdict (acceptable, weak, weak). Each LAN's algorithm_id is the
// seeded catalogue row its cipher names; a tenant database without the seed
// leaves it NULL (not assessed), as the service does.

import (
	"context"
	"database/sql"
	"fmt"
)

// WirelessGroupName is site's wireless LAN group.
func WirelessGroupName(site int) string { return fmt.Sprintf("wlg-%04d", site) }

// WirelessLANsPerSite is how many LANs each group holds.
const WirelessLANsPerSite = 3

func populateWirelessGroups(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	for site := 0; site < e.Scale.Sites; site++ {
		e.Witness(WirelessGroupName(site))
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO public.wireless_lan_groups (tenant_id, name, slug, source_kind)
		SELECT $1, 'wlg-' || lpad(s::text, 4, '0'), 'wlg-' || lpad(s::text, 4, '0'), 'declared'
		  FROM generate_series(0, $2 - 1) s`, e.Tenant, e.Scale.Sites)
	if err != nil {
		return 0, fmt.Errorf("wireless_lan_groups: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func populateWirelessLANs(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	for site := 0; site < e.Scale.Sites; site++ {
		e.Witness(fmt.Sprintf("%s|Corp|Guest|Lobby", WirelessGroupName(site)))
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO public.wireless_lans (tenant_id, ssid, group_id, auth_type, auth_cipher, auth_psk_present, algorithm_id, source_kind)
		SELECT $1, v.ssid, g.id, v.auth_type, v.auth_cipher, v.psk,
		       (SELECT a.id FROM public.algorithms a WHERE a.code = v.algo), 'declared'
		  FROM public.wireless_lan_groups g
		  CROSS JOIN (VALUES
		    ('Corp',  'wpa-personal', 'aes',  true,  'WIFI-CCMP'),
		    ('Guest', 'wpa-personal', 'tkip', true,  'WIFI-TKIP'),
		    ('Lobby', 'open',          NULL,  false, 'WIFI-OPEN')) AS v(ssid, auth_type, auth_cipher, psk, algo)
		 WHERE g.tenant_id = $1`, e.Tenant)
	if err != nil {
		return 0, fmt.Errorf("wireless_lans: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
