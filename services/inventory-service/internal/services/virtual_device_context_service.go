package services

// Virtual device contexts (DCIM gap 1; NetBox dcim/virtual-device-context): a
// logical partition of one physical device that owns interfaces and addresses
// — a Cisco Nexus VDC, a Palo Alto vsys, a Fortinet VDOM, an F5 route domain.
//
// The object is a hardware spec on the IPAM object engine (hardware_specs.go),
// so it gets the engine's CRUD, tenant-scoped transactions, change recording,
// custom fields and error mapping; this file is what the schema cannot say:
//
//   - a context is its asset's and never moves (preparePortAsset);
//   - operational_status is NetBox's VirtualDeviceContextStatusChoices;
//   - a primary IPv4 / IPv6 must be of that family and assigned to one of the
//     asset's interfaces (NetBox VirtualDeviceContext.clean()).
//
// An interface's membership (NetBox Interface.vdcs, the
// interface_virtual_device_contexts junction) is written by InterfaceService
// through ifaceResolveContexts / ifaceReplaceContexts below, which refuse a
// context of another asset.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// virtualDeviceContextStatuses is NetBox 4.3's
// VirtualDeviceContextStatusChoices (dcim/choices.py), which the
// netbox-choices snapshot does not carry
// (virtual_device_contexts_operational_status_check).
var virtualDeviceContextStatuses = []string{"active", "planned", "offline"}

func virtualDeviceContextSpec() *ipamSpec {
	return &ipamSpec{
		Kind: dcim.ObjectKindVirtualDeviceContext, Table: "virtual_device_contexts", Route: HardwareVirtualDeviceContext,
		Lifecycle: true,
		Cols: lifecycleSubstrate(
			ipamCol{Name: "asset_id", Type: colUUID, Required: true},
			ipamCol{Name: "name", Type: colText, Required: true},
			ipamCol{Name: "identifier", Type: colInt},
			ipamCol{Name: "operational_status", Type: colText},
			ipamCol{Name: "business_unit_id", Type: colUUID},
			ipamCol{Name: "primary_ip4_id", Type: colUUID},
			ipamCol{Name: "primary_ip6_id", Type: colUUID},
		),
		Filters: []ipamFilter{
			{Param: "asset_id", Column: "asset_id", Type: colUUID},
			{Param: "status", Column: "status", Type: colText},
			{Param: "operational_status", Column: "operational_status", Type: colText},
			{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
			{Param: "name", Column: "name", Type: colText},
			{Param: "identifier", Column: "identifier", Type: colInt},
		},
		Search:  []string{"name", "description"},
		Order:   "t.asset_id, t.identifier NULLS LAST, " + naturalNameOrder,
		Prepare: prepareVirtualDeviceContext,
	}
}

// prepareVirtualDeviceContext: the asset's own and never moved; a NetBox
// status; an identifier NetBox allows (0-32767); primary addresses of the
// right family held by the asset.
func prepareVirtualDeviceContext(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if err := preparePortAsset(ctx, tx, "virtual_device_contexts", id, tenant, row); err != nil {
		return err
	}
	if err := oneOf(row, "operational_status", virtualDeviceContextStatuses); err != nil {
		return err
	}
	if row["operational_status"] == nil {
		row["operational_status"] = "active"
	}
	if v, ok := row["identifier"]; ok && v != nil {
		n, err := sqlParam(ipamCol{Name: "identifier", Type: colInt}, v)
		if err != nil {
			return err
		}
		if i, ok := n.(int64); ok && (i < 0 || i > 32767) {
			return ipamInvalid("identifier must be 0 to 32767")
		}
	}
	for field, family := range map[string]int{"primary_ip4_id": 4, "primary_ip6_id": 6} {
		if err := checkContextPrimaryIP(ctx, tx, tenant, fmt.Sprint(row["asset_id"]), field, family, row[field]); err != nil {
			return err
		}
	}
	return nil
}

// checkContextPrimaryIP refuses an address that does not exist for the
// tenant, is of the wrong family, or is not assigned to one of the asset's
// interfaces.
func checkContextPrimaryIP(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, asset, field string, family int, v any) error {
	if isEmpty(v) {
		return nil
	}
	var fam sql.NullInt64
	var held bool
	err := tx.QueryRowContext(ctx, `
		SELECT family(ip.address),
		       EXISTS (SELECT 1 FROM interfaces i WHERE i.tenant_id = ip.tenant_id AND i.asset_id = $3::uuid
		                  AND ip.assigned_kind = 'interface' AND ip.assigned_id = i.id)
		  FROM ip_addresses ip
		 WHERE ip.tenant_id = $1 AND ip.id = $2::uuid AND ip.status <> 'rejected'`, tenant, fmt.Sprint(v), asset).Scan(&fam, &held)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("%s: no such IP address %v", field, v)
	}
	if err != nil {
		return mapIPAMError(err, false)
	}
	if int(fam.Int64) != family {
		return ipamInvalid("%s takes an IPv%d address", field, family)
	}
	if !held {
		return ipamInvalid("%s must be assigned to one of the asset's interfaces", field)
	}
	return nil
}

// VirtualDeviceContextRef names one context an interface belongs to.
type VirtualDeviceContextRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// errContextNotOnAsset is the refusal of a membership naming a context that
// is not on the interface's asset.
const errContextNotOnAsset = "must name a virtual device context of the interface's asset"

// ifaceResolveContexts turns a write's membership into context ids on the
// interface's asset: ids when the caller sent virtual_device_context_ids,
// otherwise the names in vdcs (the row 1.2 field), each of which must name a
// context of that asset. Sending both, non-empty, is refused.
func ifaceResolveContexts(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, ids []uuid.UUID, names []string, idsSent, namesSent bool) ([]uuid.UUID, error) {
	if idsSent && namesSent && len(ids) > 0 && len(names) > 0 {
		return nil, ifaceInvalid("virtual_device_context_ids", "send virtual_device_context_ids or vdcs, not both")
	}
	if !idsSent && namesSent {
		want := map[string]bool{}
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" {
				want[n] = true
			}
		}
		if len(want) == 0 {
			return []uuid.UUID{}, nil
		}
		list := make([]string, 0, len(want))
		for n := range want {
			list = append(list, n)
		}
		sort.Strings(list)
		rows, err := tx.QueryContext(ctx, `SELECT id, name FROM virtual_device_contexts
			WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected' AND name = ANY ($3::text[])`, tenant, asset, pq.Array(list))
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		found := map[string]uuid.UUID{}
		for rows.Next() {
			var id uuid.UUID
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				return nil, err
			}
			found[name] = id
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out := make([]uuid.UUID, 0, len(list))
		for _, n := range list {
			id, ok := found[n]
			if !ok {
				return nil, ifaceInvalid("vdcs", "%q is not a virtual device context of this asset", n)
			}
			out = append(out, id)
		}
		return out, nil
	}
	seen := map[uuid.UUID]bool{}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return out, nil
	}
	strs := make([]string, 0, len(out))
	for _, id := range out {
		strs = append(strs, id.String())
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM virtual_device_contexts
		WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected' AND id = ANY ($3::uuid[])`, tenant, asset, pq.Array(strs)).Scan(&n); err != nil {
		return nil, err
	}
	if n != len(out) {
		return nil, ifaceInvalid("virtual_device_context_ids", "%s", errContextNotOnAsset)
	}
	return out, nil
}

// ifaceReplaceContexts makes the interface's memberships exactly ids.
func ifaceReplaceContexts(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, ids []uuid.UUID) error {
	strs := make([]string, 0, len(ids))
	for _, c := range ids {
		strs = append(strs, c.String())
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM interface_virtual_device_contexts
		WHERE interface_id = $1 AND NOT (virtual_device_context_id = ANY ($2::uuid[]))`, id, pq.Array(strs)); err != nil {
		return err
	}
	for _, c := range strs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO interface_virtual_device_contexts (tenant_id, interface_id, virtual_device_context_id)
			VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, tenant, id, c); err != nil {
			return err
		}
	}
	return nil
}
