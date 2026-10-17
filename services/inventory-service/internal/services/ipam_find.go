package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
)

// ---------------------------------------------------------------------------
// Find
// ---------------------------------------------------------------------------

// FindResult is one VRF's answer to "where is this address?".
type FindResult struct {
	VRFID     *uuid.UUID      `json:"vrf_id"`
	VRFName   *string         `json:"vrf_name"`
	Prefix    json.RawMessage `json:"prefix"`
	IPAddress json.RawMessage `json:"ip_address"`
	Assigned  *FindAssignment `json:"assigned"`
	Asset     *FindAsset      `json:"asset"`
}

// FindAssignment is what an address is assigned to.
type FindAssignment struct {
	Kind string    `json:"kind"`
	ID   uuid.UUID `json:"id"`
}

// FindAsset is the asset holding the address, when one can be named.
type FindAsset struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Via  string    `json:"via"` // interface | primary_ip4 | primary_ip6 | oob_ip
}

// FindAddress answers where addr lives. With allVRFs false only vrf (nil =
// the global table) is searched; otherwise every VRF where the address falls
// in a prefix or exists as an IP address gets one result. One query does the
// longest match per VRF (DISTINCT ON the VRF, longest mask first) — the VRF is
// part of the match key, which is what keeps a global 10.0.0.0/8 from
// answering for an address in VRF blue — and one more names the assets.
func (s *IPAMService) FindAddress(ctx context.Context, tenant uuid.UUID, addr netip.Addr, vrf *uuid.UUID, allVRFs bool) ([]FindResult, error) {
	addr = ipam.StripZone(addr)
	out := []FindResult{}
	scope := "TRUE"
	args := []any{tenant, addr.String()}
	if !allVRFs {
		scope = vrfClause("t", 3)
		args = append(args, vrfArg(vrf))
	}
	err := s.tx(ctx, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			WITH m AS (
			  SELECT DISTINCT ON (COALESCE(t.vrf_id, '`+zeroUUID+`'::uuid)) t.vrf_id, to_jsonb(t) AS prefix
			    FROM public.prefixes t
			   WHERE t.tenant_id = $1 AND t.prefix >>= $2::inet AND t.status <> 'rejected' AND `+scope+`
			   ORDER BY COALESCE(t.vrf_id, '`+zeroUUID+`'::uuid), masklen(t.prefix) DESC
			), a AS (
			  SELECT DISTINCT ON (COALESCE(t.vrf_id, '`+zeroUUID+`'::uuid)) t.vrf_id, to_jsonb(t) AS ip, t.id, t.assigned_kind, t.assigned_id
			    FROM public.ip_addresses t
			   WHERE t.tenant_id = $1 AND t.host = public.ipam_host($2::inet) AND t.status <> 'rejected' AND `+scope+`
			   ORDER BY COALESCE(t.vrf_id, '`+zeroUUID+`'::uuid), t.created_at
			)
			SELECT COALESCE(m.vrf_id, a.vrf_id), v.name, m.prefix, a.ip, a.id, a.assigned_kind, a.assigned_id
			  FROM m FULL JOIN a ON COALESCE(m.vrf_id, '`+zeroUUID+`'::uuid) = COALESCE(a.vrf_id, '`+zeroUUID+`'::uuid)
			  LEFT JOIN public.vrfs v ON v.id = COALESCE(m.vrf_id, a.vrf_id)
			 ORDER BY v.name NULLS FIRST`, args...)
		if err != nil {
			return err
		}
		ipSpec := ipAddressSpec()
		var ipIDs []uuid.UUID
		var ifaceIDs []uuid.UUID
		for rows.Next() {
			var v uuid.NullUUID
			var name sql.NullString
			var pr, ip []byte
			var ipID, assigned uuid.NullUUID
			var kind sql.NullString
			if err := rows.Scan(&v, &name, &pr, &ip, &ipID, &kind, &assigned); err != nil {
				_ = rows.Close()
				return err
			}
			r := FindResult{Prefix: json.RawMessage("null"), IPAddress: json.RawMessage("null")}
			if v.Valid {
				id := v.UUID
				r.VRFID = &id
			}
			if name.Valid {
				n := name.String
				r.VRFName = &n
			}
			if pr != nil {
				r.Prefix = pr
			}
			if ip != nil {
				if p, err := present(ipSpec, ip); err == nil {
					r.IPAddress = p
				}
				ipIDs = append(ipIDs, ipID.UUID)
				if kind.Valid && assigned.Valid {
					r.Assigned = &FindAssignment{Kind: kind.String, ID: assigned.UUID}
					if kind.String == "interface" {
						ifaceIDs = append(ifaceIDs, assigned.UUID)
					}
				}
			}
			out = append(out, r)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ipIDs) == 0 {
			return nil
		}
		byIP, byIface, err := assetsHolding(ctx, tx, tenant, ipIDs, ifaceIDs)
		if err != nil {
			return err
		}
		for i := range out {
			var m map[string]any
			if json.Unmarshal(out[i].IPAddress, &m) != nil || m == nil {
				continue
			}
			if out[i].Assigned != nil && out[i].Assigned.Kind == "interface" {
				if a, ok := byIface[out[i].Assigned.ID]; ok {
					out[i].Asset = a
					continue
				}
			}
			if id, err := uuid.Parse(fmt.Sprint(m["id"])); err == nil {
				out[i].Asset = byIP[id]
			}
		}
		return nil
	})
	return out, mapIPAMError(err, false)
}

// assetsHolding names the assets the addresses belong to: through their
// interface (row 1.2) or as an asset's primary
// or out-of-band address.
func assetsHolding(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, ipIDs, ifaceIDs []uuid.UUID) (map[uuid.UUID]*FindAsset, map[uuid.UUID]*FindAsset, error) {
	byIP := map[uuid.UUID]*FindAsset{}
	byIface := map[uuid.UUID]*FindAsset{}
	rows, err := tx.QueryContext(ctx, `
		SELECT x.ip, a.id, COALESCE(a.display_name, a.hostname, host(a.primary_address), a.id::text),
		       CASE WHEN a.primary_ip4_id = x.ip THEN 'primary_ip4' WHEN a.primary_ip6_id = x.ip THEN 'primary_ip6' ELSE 'oob_ip' END
		  FROM unnest($2::uuid[]) AS x(ip)
		  JOIN public.assets a ON a.tenant_id = $1 AND a.deleted_at IS NULL
		   AND (a.primary_ip4_id = x.ip OR a.primary_ip6_id = x.ip OR a.oob_ip_id = x.ip)`, tenant, pq.Array(ipIDs))
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var ip uuid.UUID
		var a FindAsset
		if err := rows.Scan(&ip, &a.ID, &a.Name, &a.Via); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		if _, seen := byIP[ip]; !seen {
			byIP[ip] = &a
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil || len(ifaceIDs) == 0 {
		return byIP, byIface, err
	}
	rows, err = tx.QueryContext(ctx, `
		SELECT i.id, a.id, COALESCE(a.display_name, a.hostname, host(a.primary_address), a.id::text)
		  FROM public.interfaces i JOIN public.assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id
		 WHERE i.tenant_id = $1 AND i.id = ANY ($2::uuid[]) AND a.deleted_at IS NULL`, tenant, pq.Array(ifaceIDs))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var iface uuid.UUID
		a := FindAsset{Via: "interface"}
		if err := rows.Scan(&iface, &a.ID, &a.Name); err != nil {
			return nil, nil, err
		}
		byIface[iface] = &a
	}
	return byIP, byIface, rows.Err()
}
