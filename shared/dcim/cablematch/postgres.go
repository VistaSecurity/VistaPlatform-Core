package cablematch

import (
	"context"
	"database/sql"
	"strings"

	"github.com/google/uuid"
)

// PGDirectory is the Directory over one tenant transaction (RLS-scoped; every
// statement repeats the tenant as the control). Live assets only: not
// deleted, not denied, not archived.
type PGDirectory struct {
	Tx     *sql.Tx
	Tenant uuid.UUID
}

const liveAsset = `a.tenant_id = $1 AND a.deleted_at IS NULL AND a.asset_status NOT IN ('denied', 'archived')`

func (d PGDirectory) ids(ctx context.Context, q string, args ...any) ([]uuid.UUID, error) {
	rows, err := d.Tx.QueryContext(ctx, q, append([]any{d.Tenant}, args...)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AssetsByMAC: an asset MAC identifier, or one of its interfaces' MACs.
func (d PGDirectory) AssetsByMAC(ctx context.Context, mac string) ([]uuid.UUID, error) {
	return d.ids(ctx, `
		SELECT DISTINCT a.id FROM public.assets a
		 WHERE `+liveAsset+` AND (
		       EXISTS (SELECT 1 FROM public.asset_identifiers i WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id
		                  AND i.kind = 'mac_address' AND lower(i.value) = $2)
		    OR EXISTS (SELECT 1 FROM public.interfaces f WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id
		                  AND f.status <> 'rejected' AND f.mac_address = $2::macaddr8))
		 ORDER BY a.id`, strings.ToLower(mac))
}

// AssetsBySystemName: a hostname / FQDN identifier, the asset's hostname or
// display name — equal to the name, or to its first label.
func (d PGDirectory) AssetsBySystemName(ctx context.Context, name string) ([]uuid.UUID, error) {
	name = SystemName(name)
	if name == "" {
		return nil, nil
	}
	short := name
	if i := strings.IndexByte(name, '.'); i > 0 {
		short = name[:i]
	}
	return d.ids(ctx, `
		SELECT DISTINCT a.id FROM public.assets a
		 WHERE `+liveAsset+` AND (
		       lower(a.hostname) IN ($2, $3) OR lower(split_part(a.hostname, '.', 1)) = $3
		    OR lower(a.display_name) IN ($2, $3)
		    OR EXISTS (SELECT 1 FROM public.asset_identifiers i WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id
		                  AND i.kind IN ('hostname', 'fqdn')
		                  AND (lower(i.value) IN ($2, $3) OR lower(split_part(i.value, '.', 1)) = $3)))
		 ORDER BY a.id`, name, short)
}

// AssetsByAddress: an address identifier, or an address assigned to one of the
// asset's interfaces.
func (d PGDirectory) AssetsByAddress(ctx context.Context, addr string) ([]uuid.UUID, error) {
	return d.ids(ctx, `
		SELECT DISTINCT a.id FROM public.assets a
		 WHERE `+liveAsset+` AND (
		       EXISTS (SELECT 1 FROM public.asset_identifiers i WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id
		                  AND i.kind = 'ip_address' AND i.value = $2)
		    OR EXISTS (SELECT 1 FROM public.ip_addresses ip JOIN public.interfaces f
		                  ON f.tenant_id = ip.tenant_id AND f.id = ip.assigned_id AND ip.assigned_kind = 'interface'
		                WHERE ip.tenant_id = a.tenant_id AND f.asset_id = a.id AND ip.status <> 'rejected'
		                  AND ip.host = $2::inet))
		 ORDER BY a.id`, addr)
}

// Ports: the asset's interfaces that are not rejected.
func (d PGDirectory) Ports(ctx context.Context, asset uuid.UUID) ([]Port, error) {
	rows, err := d.Tx.QueryContext(ctx, `
		SELECT id, asset_id, name, COALESCE(lower(mac_address::text), '')
		  FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected'
		 ORDER BY name, id`, d.Tenant, asset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Port
	for rows.Next() {
		var p Port
		if err := rows.Scan(&p.ID, &p.AssetID, &p.Name, &p.MAC); err != nil {
			return nil, err
		}
		p.MAC = mac48(p.MAC)
		out = append(out, p)
	}
	return out, rows.Err()
}

// mac48 turns macaddr8's text of a 48-bit MAC (aa:bb:cc:ff:fe:dd:ee:ff, the
// form Postgres stores a 6-byte input in) back into aa:bb:cc:dd:ee:ff. A
// genuine EUI-64 is returned unchanged.
func mac48(v string) string {
	parts := strings.Split(v, ":")
	if len(parts) == 8 && parts[3] == "ff" && parts[4] == "fe" {
		return strings.Join(append(parts[:3:3], parts[5:]...), ":")
	}
	return v
}
