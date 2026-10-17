package services

// The wireless objects as engine specs (DCIM BUILD_PLAN row 4.4; ADR-0010 D8;
// DATA_MODEL §7 Wireless): wireless LAN groups, wireless LANs and wireless
// links. They run on the IPAM object engine (ipam_engine.go), so they get its
// tenant-scoped transaction, RLS, change recording and error mapping.
//
// Inventory only (D8): no RF planning, no controller management. A
// pre-shared key is never a column; `auth_psk_present` says one exists, and
// the engine rejects a body naming any other field. The cipher is scored by
// the algorithms catalogue: Prepare points `algorithm_id` at the row
// wireless.AlgorithmCode names, and the producer reads strength and risk from
// that row.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/wireless"
)

// WirelessRoutes lists the object route segments under /wireless.
func WirelessRoutes() []string {
	return []string{"wireless-lan-groups", "wireless-lans", "wireless-links"}
}

var (
	wirelessLANStatuses  = []string{"active", "reserved", "disabled", "deprecated"}
	wirelessLinkStatuses = []string{"connected", "planned", "decommissioning"}
	distanceUnits        = []string{"km", "m", "mi", "ft"}
)

// prepareWirelessAuth validates auth_type / auth_cipher and sets algorithm_id
// from them. A cipher without an auth type, or the reverse nonsense NetBox
// would also refuse, is a 400.
func prepareWirelessAuth(ctx context.Context, tx *sql.Tx, row map[string]any) error {
	for _, c := range []struct {
		col     string
		allowed []string
	}{{"auth_type", wireless.AuthTypes}, {"auth_cipher", wireless.AuthCiphers}} {
		if err := oneOf(row, c.col, c.allowed); err != nil {
			return err
		}
	}
	authType, _ := row["auth_type"].(string)
	cipher, _ := row["auth_cipher"].(string)
	if cipher != "" && authType == "" {
		return ipamInvalid("auth_cipher needs an auth_type")
	}
	if authType == "open" && cipher != "" {
		return ipamInvalid("an open wireless LAN has no cipher")
	}
	row["algorithm_id"] = nil
	code := wireless.AlgorithmCode(authType, cipher)
	if code == "" {
		return nil
	}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM public.algorithms WHERE code = $1`, code).Scan(&id)
	switch {
	case err == sql.ErrNoRows:
		// The catalogue row is missing: leave the LAN unassessed rather than
		// invent a score. The producer reports an unassessable LAN as such.
		return nil
	case err != nil:
		return err
	}
	row["algorithm_id"] = id.String()
	return nil
}

func prepareSSID(row map[string]any, col string, required bool) error {
	s, ok := row[col].(string)
	if !ok || strings.TrimSpace(s) == "" {
		if required {
			return ipamInvalid("%s is required", col)
		}
		row[col] = nil
		return nil
	}
	// An SSID is 0-32 OCTETS (IEEE 802.11); it is case-sensitive and is NOT
	// trimmed or normalised: "Guest " and "Guest" are different networks.
	if len(s) > 32 {
		return ipamInvalid("%s is longer than 32 bytes", col)
	}
	return nil
}

func wirelessSpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindWirelessLanGroup, Table: "wireless_lan_groups", Route: "wireless-lan-groups",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "parent_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "parent_id", Column: "parent_id", Type: colUUID}, {Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
				if err := prepareSlug(ctx, tx, tenant, id, row); err != nil {
					return err
				}
				if p := fmt.Sprint(row["parent_id"]); row["parent_id"] != nil && p == id.String() {
					return ipamInvalid("a group cannot be its own parent")
				}
				return visible(ctx, tx, "wireless_lan_groups", row["parent_id"])
			},
		},
		{
			Kind: dcim.ObjectKindWirelessLan, Table: "wireless_lans", Route: "wireless-lans", Lifecycle: true,
			Cols: withSubstrate(append([]ipamCol{
				{Name: "ssid", Type: colText, Required: true},
				{Name: "group_id", Type: colUUID},
				{Name: "operational_status", Type: colText},
				{Name: "vlan_id", Type: colUUID},
				{Name: "business_unit_id", Type: colUUID},
				{Name: "auth_type", Type: colText},
				{Name: "auth_cipher", Type: colText},
				{Name: "auth_psk_present", Type: colBool},
				{Name: "algorithm_id", Type: colUUID, Computed: true},
				externalIDsCol,
			}, lifecycleCols...)...),
			Filters: []ipamFilter{
				{Param: "ssid", Column: "ssid", Type: colText},
				{Param: "group_id", Column: "group_id", Type: colUUID},
				{Param: "vlan_id", Column: "vlan_id", Type: colUUID},
				{Param: "auth_type", Column: "auth_type", Type: colText},
				{Param: "auth_cipher", Column: "auth_cipher", Type: colText},
				{Param: "status", Column: "status", Type: colText},
				{Param: "operational_status", Column: "operational_status", Type: colText},
				{Param: "asset_id", Custom: lansOfFilter("i.asset_id")},
				{Param: "interface_id", Custom: lansOfFilter("i.id")},
			},
			Search: []string{"ssid", "description"},
			Order:  "t.ssid, t.id",
			// The Wireless table shows each LAN's cipher beside its catalogue
			// strength and risk, so the colour is the catalogue's.
			ListSelect: `to_jsonb(t) || jsonb_build_object(
			    'algorithm_code', a.code, 'algorithm_strength', a.strength, 'algorithm_risk_score', a.risk_score,
			    'interface_count', (SELECT count(*) FROM public.interfaces i
			        WHERE i.tenant_id = t.tenant_id AND t.id = ANY(i.wireless_lan_ids)))`,
			Join: `LEFT JOIN public.algorithms a ON a.id = t.algorithm_id`,
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := prepareSSID(row, "ssid", true); err != nil {
					return err
				}
				if err := oneOf(row, "operational_status", wirelessLANStatuses); err != nil {
					return err
				}
				if err := visible(ctx, tx, "wireless_lan_groups", row["group_id"]); err != nil {
					return err
				}
				if err := visible(ctx, tx, "vlans", row["vlan_id"]); err != nil {
					return err
				}
				return prepareWirelessAuth(ctx, tx, row)
			},
			// A deleted LAN leaves the interfaces that served it (the array has
			// no foreign key).
			AfterWrite: func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
				if post != nil || pre == nil {
					return nil
				}
				_, err := tx.ExecContext(ctx, `UPDATE public.interfaces SET wireless_lan_ids = array_remove(wireless_lan_ids, $2::uuid), updated_at = now()
					WHERE tenant_id = $1 AND $2::uuid = ANY(wireless_lan_ids)`, tenant, fmt.Sprint(pre["id"]))
				return err
			},
		},
		{
			Kind: dcim.ObjectKindWirelessLink, Table: "wireless_links", Route: "wireless-links", Lifecycle: true,
			Cols: withSubstrate(append([]ipamCol{
				{Name: "interface_a_id", Type: colUUID, Required: true},
				{Name: "interface_b_id", Type: colUUID, Required: true},
				{Name: "ssid", Type: colText},
				{Name: "operational_status", Type: colText},
				{Name: "auth_type", Type: colText},
				{Name: "auth_cipher", Type: colText},
				{Name: "auth_psk_present", Type: colBool},
				{Name: "algorithm_id", Type: colUUID, Computed: true},
				{Name: "distance", Type: colNumeric},
				{Name: "distance_unit", Type: colText},
				externalIDsCol,
			}, lifecycleCols...)...),
			Filters: []ipamFilter{
				{Param: "interface_a_id", Column: "interface_a_id", Type: colUUID},
				{Param: "interface_b_id", Column: "interface_b_id", Type: colUUID},
				{Param: "ssid", Column: "ssid", Type: colText},
				{Param: "status", Column: "status", Type: colText},
				{Param: "operational_status", Column: "operational_status", Type: colText},
			},
			Search: []string{"ssid", "description"},
			Order:  "t.created_at, t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object(
			    'algorithm_code', a.code, 'algorithm_strength', a.strength, 'algorithm_risk_score', a.risk_score,
			    'interface_a_name', ia.name, 'interface_a_asset_id', ia.asset_id,
			    'interface_b_name', ib.name, 'interface_b_asset_id', ib.asset_id)`,
			Join: `LEFT JOIN public.algorithms a ON a.id = t.algorithm_id
			       LEFT JOIN public.interfaces ia ON ia.tenant_id = t.tenant_id AND ia.id = t.interface_a_id
			       LEFT JOIN public.interfaces ib ON ib.tenant_id = t.tenant_id AND ib.id = t.interface_b_id`,
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := prepareSSID(row, "ssid", false); err != nil {
					return err
				}
				if fmt.Sprint(row["interface_a_id"]) == fmt.Sprint(row["interface_b_id"]) {
					return ipamInvalid("a wireless link needs two different interfaces")
				}
				if err := visible(ctx, tx, "interfaces", row["interface_a_id"]); err != nil {
					return err
				}
				if err := visible(ctx, tx, "interfaces", row["interface_b_id"]); err != nil {
					return err
				}
				if err := oneOf(row, "operational_status", wirelessLinkStatuses); err != nil {
					return err
				}
				if err := oneOf(row, "distance_unit", distanceUnits); err != nil {
					return err
				}
				if !isEmpty(row["distance"]) && isEmpty(row["distance_unit"]) {
					return ipamInvalid("distance needs a distance_unit")
				}
				return prepareWirelessAuth(ctx, tx, row)
			},
		},
	}
}

// lansOfFilter filters wireless LANs to those an interface (or any interface
// of an asset) serves: col is the interfaces column compared with the value.
func lansOfFilter(col string) func(value string, n int) (string, any, error) {
	return func(value string, n int) (string, any, error) {
		id, err := uuid.Parse(value)
		if err != nil {
			return "", nil, ipamInvalid("%s must be a UUID", strings.TrimPrefix(col, "i."))
		}
		return fmt.Sprintf(`t.id IN (SELECT unnest(i.wireless_lan_ids) FROM public.interfaces i WHERE i.tenant_id = t.tenant_id AND %s = $%d::uuid)`, col, n), id.String(), nil
	}
}
