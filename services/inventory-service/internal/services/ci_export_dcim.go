package services

// The DCIM half of the CI export (DCIM BUILD_PLAN row 5.7, SYNC_MODEL §6): the
// racks, prefixes, IP addresses, circuits, VLANs, interfaces and sites a CMDB
// push sends as CIs of their own (cmdb_ci_rack, cmdb_ci_ip_network, …).
//
// Same three rules as the asset export (ci_export.go):
//
//   - The push scope is decided HERE. Objects with an approval lifecycle
//     (prefixes, IP addresses, VLANs, interfaces) are exported only when
//     approved (`status = 'active'`); an interface additionally only when its
//     asset is in push scope (the v_ci_inventory rule). Racks, circuits and
//     sites are declared objects with no approval step: all of them.
//   - Every read runs under the ONE tenant the signed call names (RLS), and
//     the tenant predicate is repeated in every query.
//   - A field allowlist per class (dcimExportClasses). Never `SELECT *`, never
//     custom fields, never comments: what a CMDB needs to identify and
//     describe the CI, and nothing a tenant did not mean to send.
//
// Each item also carries its structural edges (`relations`), which the CMDB
// engine sends as CI relationships where the target supports them: a rack
// houses devices, an interface is installed on its asset, an IP address is
// assigned to its interface, a prefix is in its VLAN, a circuit terminates at
// its sites. An edge to an object outside push scope is not listed.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// The DCIM export classes. The values are vocabulary keys
// (standards/vocabulary.yaml) and are also the CI categories the CMDB engine
// files them under.
const (
	DCIMExportRack      = "rack"
	DCIMExportPrefix    = "prefix"
	DCIMExportIPAddress = "ip_address"
	DCIMExportCircuit   = "circuit"
	DCIMExportVLAN      = "vlan"
	DCIMExportInterface = "interface"
	DCIMExportSite      = "site"
)

// The structural relationship types the DCIM export emits. Each reads
// "from <type> to", the item being the from-end.
const (
	DCIMRelHouses       = "dcim.houses"        // rack → asset
	DCIMRelInstalledOn  = "dcim.installed_on"  // interface → asset
	DCIMRelAssignedTo   = "dcim.assigned_to"   // ip_address → interface
	DCIMRelInVLAN       = "dcim.in_vlan"       // prefix → vlan
	DCIMRelTerminatesAt = "dcim.terminates_at" // circuit → site
)

// CIExportDCIMRelation is one structural edge from an exported DCIM item.
type CIExportDCIMRelation struct {
	Type       string    `json:"type"`
	ToCategory string    `json:"to_category"`
	ToID       uuid.UUID `json:"to_id"`
}

// CIExportDCIMItem is one DCIM object in push scope.
type CIExportDCIMItem struct {
	ID          uuid.UUID `json:"id"`
	Category    string    `json:"category"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	// Fields are the class's allowlisted fields, as text. An unset field is
	// absent, never "".
	Fields    map[string]string      `json:"fields"`
	Relations []CIExportDCIMRelation `json:"relations"`
}

// ciScopeAsset is the push-scope predicate for an asset row aliased `a` — the
// v_ci_inventory rule (approved, not deleted, not stale-archived, not merged
// away), repeated here so an edge to an asset never names one the asset
// export would not send.
const ciScopeAsset = `a.deleted_at IS NULL AND a.asset_status = 'monitoring'
	AND a.stale_status IS DISTINCT FROM 'archived' AND NOT (a.metadata ? 'merged_into')`

// dcimExportQueries are the per-class reads. Each selects, in order: id,
// display name, description, fields (a jsonb object of text), relations (a
// jsonb array), for one tenant ($1), after an id ($2), at most $3 rows, in id
// order. Text values only: a CMDB field is coerced on the engine's side by
// the mapping's transform.
var dcimExportQueries = map[string]string{
	DCIMExportRack: `
		SELECT r.id, r.name, COALESCE(r.description, ''),
		       jsonb_strip_nulls(jsonb_build_object(
		           'name', r.name,
		           'site', s.name,
		           'location', public.location_path(r.location_id),
		           'facility_id', r.facility_id,
		           'status', r.operational_status,
		           'serial', r.serial,
		           'asset_tag', r.asset_tag,
		           'form_factor', r.form_factor,
		           'width', r.width::text,
		           'u_height', r.u_height::text,
		           'used_units', u.used_units::text,
		           'utilization', u.utilization::text)),
		       COALESCE((SELECT jsonb_agg(jsonb_build_object(
		                   'type', '` + DCIMRelHouses + `', 'to_category', 'infrastructure_asset', 'to_id', a.id) ORDER BY a.id)
		                 FROM assets a
		                WHERE a.tenant_id = r.tenant_id AND a.rack_id = r.id AND ` + ciScopeAsset + `), '[]'::jsonb)
		  FROM racks r
		  JOIN sites s ON s.id = r.site_id
		  LEFT JOIN rack_utilization u ON u.rack_id = r.id
		 WHERE r.tenant_id = $1 AND r.id > $2
		 ORDER BY r.id
		 LIMIT $3`,

	DCIMExportPrefix: `
		SELECT p.id, text(p.prefix), COALESCE(p.description, ''),
		       jsonb_strip_nulls(jsonb_build_object(
		           'prefix', text(p.prefix),
		           'network', host(p.prefix),
		           'prefix_length', masklen(p.prefix)::text,
		           'netmask', host(netmask(p.prefix)),
		           'ip_version', family(p.prefix)::text,
		           'vrf', vr.name,
		           'vlan', v.name,
		           'vlan_vid', v.vid::text,
		           'role', pr.name,
		           'status', p.operational_status,
		           'environment', p.environment,
		           'site', CASE WHEN p.scope_kind = 'site' THEN (SELECT st.name FROM sites st WHERE st.id = p.scope_id) END)),
		       CASE WHEN v.id IS NOT NULL
		            THEN jsonb_build_array(jsonb_build_object('type', '` + DCIMRelInVLAN + `', 'to_category', 'vlan', 'to_id', v.id))
		            ELSE '[]'::jsonb END
		  FROM prefixes p
		  LEFT JOIN vrfs vr ON vr.id = p.vrf_id
		  LEFT JOIN vlans v ON v.id = p.vlan_id AND v.status = 'active'
		  LEFT JOIN prefix_roles pr ON pr.id = p.role_id
		 WHERE p.tenant_id = $1 AND p.status = 'active' AND p.id > $2
		 ORDER BY p.id
		 LIMIT $3`,

	DCIMExportIPAddress: `
		SELECT ip.id, COALESCE(NULLIF(ip.dns_name, ''), host(ip.address)), COALESCE(ip.description, ''),
		       jsonb_strip_nulls(jsonb_build_object(
		           'address', host(ip.address),
		           'prefix_length', masklen(ip.address)::text,
		           'ip_version', family(ip.address)::text,
		           'dns_name', NULLIF(ip.dns_name, ''),
		           'mac_address', ` + macText("ip.mac_address") + `,
		           'vrf', vr.name,
		           'role', ip.role,
		           'status', ip.operational_status,
		           'interface', i.name,
		           'asset', COALESCE(a.display_name, a.hostname, host(a.primary_address)))),
		       CASE WHEN i.id IS NOT NULL
		            THEN jsonb_build_array(jsonb_build_object('type', '` + DCIMRelAssignedTo + `', 'to_category', 'interface', 'to_id', i.id))
		            ELSE '[]'::jsonb END
		  FROM ip_addresses ip
		  LEFT JOIN vrfs vr ON vr.id = ip.vrf_id
		  LEFT JOIN interfaces i ON ip.assigned_kind = 'interface' AND i.id = ip.assigned_id AND i.status = 'active'
		  LEFT JOIN assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id AND ` + ciScopeAsset + `
		 WHERE ip.tenant_id = $1 AND ip.status = 'active' AND ip.id > $2
		 ORDER BY ip.id
		 LIMIT $3`,

	DCIMExportCircuit: `
		SELECT c.id, c.cid, COALESCE(c.description, ''),
		       jsonb_strip_nulls(jsonb_build_object(
		           'cid', c.cid,
		           'provider', pv.name,
		           'type', ct.name,
		           'status', c.operational_status,
		           'commit_rate_kbps', c.commit_rate_kbps::text,
		           'install_date', c.install_date::text,
		           'termination_date', c.termination_date::text,
		           'a_site', (SELECT s.name FROM circuit_terminations t JOIN sites s ON s.id = ` + terminationSite + `
		                       WHERE t.tenant_id = c.tenant_id AND t.circuit_id = c.id AND t.term_side = 'A'),
		           'z_site', (SELECT s.name FROM circuit_terminations t JOIN sites s ON s.id = ` + terminationSite + `
		                       WHERE t.tenant_id = c.tenant_id AND t.circuit_id = c.id AND t.term_side = 'Z'))),
		       COALESCE((SELECT jsonb_agg(DISTINCT jsonb_build_object(
		                   'type', '` + DCIMRelTerminatesAt + `', 'to_category', 'site', 'to_id', s.id))
		                 FROM circuit_terminations t JOIN sites s ON s.id = ` + terminationSite + `
		                WHERE t.tenant_id = c.tenant_id AND t.circuit_id = c.id), '[]'::jsonb)
		  FROM circuits c
		  JOIN providers pv ON pv.id = c.provider_id
		  JOIN circuit_types ct ON ct.id = c.type_id
		 WHERE c.tenant_id = $1 AND c.id > $2
		 ORDER BY c.id
		 LIMIT $3`,

	DCIMExportVLAN: `
		SELECT v.id, v.name, COALESCE(v.description, ''),
		       jsonb_strip_nulls(jsonb_build_object(
		           'name', v.name,
		           'vid', v.vid::text,
		           'site', s.name,
		           'status', v.operational_status)),
		       '[]'::jsonb
		  FROM vlans v
		  LEFT JOIN sites s ON s.id = v.site_id
		 WHERE v.tenant_id = $1 AND v.status = 'active' AND v.id > $2
		 ORDER BY v.id
		 LIMIT $3`,

	DCIMExportInterface: `
		SELECT i.id, i.name, COALESCE(i.description, ''),
		       jsonb_strip_nulls(jsonb_build_object(
		           'name', i.name,
		           'label', NULLIF(i.label, ''),
		           'type', i.type,
		           'mac_address', ` + macText("COALESCE(i.mac_address, (SELECT m.mac FROM mac_addresses m WHERE m.tenant_id = i.tenant_id AND m.interface_id = i.id AND m.is_primary LIMIT 1))") + `,
		           'speed_kbps', i.speed_kbps::text,
		           'mtu', i.mtu::text,
		           'enabled', i.enabled::text,
		           'mgmt_only', i.mgmt_only::text,
		           'asset', COALESCE(a.display_name, a.hostname, host(a.primary_address)))),
		       jsonb_build_array(jsonb_build_object('type', '` + DCIMRelInstalledOn + `', 'to_category', 'infrastructure_asset', 'to_id', a.id))
		  FROM interfaces i
		  JOIN assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id
		 WHERE i.tenant_id = $1 AND i.status = 'active' AND ` + ciScopeAsset + ` AND i.id > $2
		 ORDER BY i.id
		 LIMIT $3`,

	DCIMExportSite: `
		SELECT s.id, s.name, COALESCE(s.description, ''),
		       jsonb_strip_nulls(jsonb_build_object(
		           'name', s.name,
		           'slug', s.slug,
		           'facility', s.facility,
		           'status', s.operational_status,
		           'region', rg.name,
		           'time_zone', s.time_zone,
		           'physical_address', s.physical_address,
		           'latitude', s.latitude::text,
		           'longitude', s.longitude::text)),
		       '[]'::jsonb
		  FROM sites s
		  LEFT JOIN regions rg ON rg.id = s.region_id
		 WHERE s.tenant_id = $1 AND s.id > $2
		 ORDER BY s.id
		 LIMIT $3`,
}

// macText renders a macaddr8 expression as text: the familiar six-octet form
// for an EUI-48 address (stored with FF:FE in the middle), eight octets
// otherwise. NULL stays NULL.
func macText(expr string) string {
	return "(CASE WHEN substr((" + expr + ")::text, 10, 5) = 'ff:fe' THEN macaddr(" + expr + ")::text ELSE (" + expr + ")::text END)"
}

// terminationSite resolves a circuit termination (alias t) to a site id: the
// site itself, or the site of the location it lands in. Region, site-group and
// provider-network terminations name no site.
const terminationSite = `(CASE t.termination_kind
		WHEN 'site' THEN t.termination_id
		WHEN 'location' THEN (SELECT l.site_id FROM locations l WHERE l.id = t.termination_id)
	END)`

// DCIMExportClasses lists the exportable classes in push order: a container
// before what it contains, so a CMDB that resolves a reference by name (a
// rack's building, an IP's subnet) finds it.
func DCIMExportClasses() []string {
	return []string{DCIMExportSite, DCIMExportRack, DCIMExportVLAN, DCIMExportPrefix,
		DCIMExportInterface, DCIMExportIPAddress, DCIMExportCircuit}
}

// IsDCIMExportClass reports whether class is exportable.
func IsDCIMExportClass(class string) bool {
	_, ok := dcimExportQueries[class]
	return ok
}

// ExportDCIM reads one page of the tenant's objects of one DCIM class in push
// scope, in id order, after `after`.
func (s *CIExportService) ExportDCIM(ctx context.Context, tenantID uuid.UUID, class string, after uuid.UUID, limit int) ([]CIExportDCIMItem, error) {
	query, ok := dcimExportQueries[class]
	if !ok {
		return nil, &ErrCIExportQuery{Message: fmt.Sprintf("unknown DCIM class %q", class)}
	}
	if limit <= 0 || limit > MaxCIExportPage {
		limit = MaxCIExportPage
	}
	out := []CIExportDCIMItem{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, query, tenantID, after, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			it := CIExportDCIMItem{Category: class}
			var fields, rels []byte
			if err := rows.Scan(&it.ID, &it.DisplayName, &it.Description, &fields, &rels); err != nil {
				return err
			}
			if err := json.Unmarshal(fields, &it.Fields); err != nil {
				return fmt.Errorf("decode %s fields: %w", class, err)
			}
			if err := json.Unmarshal(rels, &it.Relations); err != nil {
				return fmt.Errorf("decode %s relations: %w", class, err)
			}
			if it.Fields == nil {
				it.Fields = map[string]string{}
			}
			if it.Relations == nil {
				it.Relations = []CIExportDCIMRelation{}
			}
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}
