package dcimfixture

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// Interface is one generated interface (DCIM BUILD_PLAN row 1.2). The cable
// populator (row 3.2) reads Env.Interfaces to terminate cables on them.
type Interface struct {
	ID      uuid.UUID
	AssetID uuid.UUID
	Name    string
	MAC     string
}

// interfaceMAC is a locally administered, unique-per-interface EUI-48.
func interfaceMAC(n int) string {
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", (n>>32)&255, (n>>24)&255, (n>>16)&255, (n>>8)&255, n&255)
}

// populateInterfaces gives every asset Scale.InterfacesPerAsset physical
// interfaces with canonical names (GigabitEthernet1/0/N), a MAC and its
// primary mac_addresses row: §12's 500,000 interfaces at Scale1. Ids are the
// database's (interfaces has a global primary key), read back in name order.
func populateInterfaces(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 || e.Scale.InterfacesPerAsset <= 0 {
		return -1, nil
	}
	per := e.Scale.InterfacesPerAsset
	n := len(e.Assets) * per
	names := make([]string, per)
	for p := 0; p < per; p++ {
		names[p], _ = ifnames.Canonical(ifnames.VendorCisco, InterfaceName(p))
	}
	cols := []string{"tenant_id", "asset_id", "name", "type", "enabled", "mac_address", "speed_kbps",
		"operational_status", "source_kind", "status", "first_seen_at", "last_seen_at", "observation_count"}
	err := copyRows(ctx, tx, "interfaces", cols, n, func(i int) []any {
		a := e.Assets[i/per]
		name := names[i%per]
		mac := interfaceMAC(i)
		e.Witness(a.ID.String() + "|" + name + "|" + mac)
		oper := "up"
		if e.Rng.IntN(10) == 0 {
			oper = "down"
		}
		return []any{e.Tenant, a.ID, name, "1000base-t", true, mac, int64(1_000_000), oper, "measured",
			"active", Epoch, Epoch, 1}
	})
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO mac_addresses (tenant_id, interface_id, mac, is_primary, source_kind)
		SELECT tenant_id, id, mac_address, true, 'measured' FROM interfaces
		 WHERE tenant_id = $1 AND mac_address IS NOT NULL`, e.Tenant); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, asset_id, name, mac_address::macaddr::text FROM interfaces
		 WHERE tenant_id = $1 ORDER BY asset_id, name`, e.Tenant)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	e.Interfaces = make([]Interface, 0, n)
	for rows.Next() {
		var i Interface
		if err := rows.Scan(&i.ID, &i.AssetID, &i.Name, &i.MAC); err != nil {
			return 0, err
		}
		e.Interfaces = append(e.Interfaces, i)
	}
	return n, rows.Err()
}
