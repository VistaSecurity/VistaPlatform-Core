package postgres

// DCIM row 1.4: an asset's addresses are the addresses of its interfaces
// (ADR-0010 D3), and the identity engine reads them from there.
//
// The engine still reasons in identifiers — `ip_address` and `mac_address` are
// identity concepts, and the class precedence lists keep naming them — but this
// store resolves them from the DCIM tables:
//
//   - `ip_address` identifiers ARE `ip_addresses` rows assigned to one of the
//     asset's interfaces (global VRF). They are never written to
//     `asset_identifiers` (DATA_MODEL §9 retires that kind there); the four
//     identity columns on `ip_addresses` (identity_scope, address_assignment,
//     device_confirmed_at, identity_confidence) carry what the identifier row
//     carried. An address IPAM holds on no interface names no asset.
//   - `mac_address` identifiers stay in `asset_identifiers` (DATA_MODEL §9:
//     "the kind stays for mac"), AND every MAC the engine files is also put on
//     the asset's interfaces; a MAC lookup answers from the union of the
//     identifier rows, `interfaces.mac_address`, `mac_addresses.mac` and the
//     ARP-seen `ip_addresses.mac_address` of an assigned address — so a MAC an
//     interrogation or a person put on a SECOND interface matches too.
//
// Interfaces the engine files values under come from [identity.PlanInterfaces]
// + [identity.ResolveInterfaces] — the rule the in-memory store applies too.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identifiersql"
)

// AddressIdentifiersSQL and IdentifierRowsSQL are re-exported from
// shared/identity/identifiersql, where readers outside this package take them
// from without importing the repository.
const (
	AddressIdentifiersSQL = identifiersql.Addresses
	IdentifierRowsSQL     = identifiersql.All
)

// identityChangeSource is the `object_changes.source` of a write the engine
// makes to an interface or an address.
var identityChangeSource = changes.IntakeSource("identity")

// isAddressKind reports whether a kind is resolved from `ip_addresses`.
func isAddressKind(k identity.Kind) bool { return k == identity.KindIPAddress }

// macAddr8 is the canonical MAC as the macaddr8 columns compare it, or false
// when it is not a MAC Postgres would accept (the cast would abort the query).
func macAddr8(v string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(v))
	if err != nil || (len(hw) != 6 && len(hw) != 8) {
		return "", false
	}
	return hw.String(), true
}

// parseHost is an identifier value as an address, or false.
func parseHost(v string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// FindAddressOwnersMarker and FindMACOwnersMarker open the two
// FindByIdentifier statements that answer from the DCIM tables, so a test that
// counts owner lookups per identifier (inventory-service's
// observation_once_integration_test, F5) recognises them without copying
// their text. Arguments: address — tenant, value, scope; MAC — tenant, value,
// then the macaddr8 spelling (or the scope, for a scoped lookup).
const (
	FindAddressOwnersMarker = "/* identity:find_owners ip_address */"
	FindMACOwnersMarker     = "/* identity:find_owners mac_address */"
)

// findAddressOwners answers FindByIdentifier for `ip_address`: the assets
// whose interfaces hold the address in the global VRF, within the scope. A
// row with no identity scope (declared or imported through IPAM) is the VRF's
// answer for every scope.
func findAddressOwners(ctx context.Context, tx *sql.Tx, tenantID, value, scope string) ([]uuid.UUID, error) {
	a, ok := parseHost(value)
	if !ok {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, FindAddressOwnersMarker+`
		SELECT DISTINCT ifc.asset_id
		  FROM public.ip_addresses ip
		  JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
		 WHERE ip.tenant_id = $1 AND ip.vrf_id IS NULL AND ip.host = $2::inet
		   AND ip.assigned_kind = 'interface'
		   AND ip.status <> 'rejected' AND ifc.status <> 'rejected'
		   AND (ip.identity_scope IS NULL OR ip.identity_scope = $3)
		 ORDER BY ifc.asset_id`, tenantID, a.String(), scope)
	if err != nil {
		return nil, fmt.Errorf("identity/postgres: find ip_address: %w", err)
	}
	return scanUUIDs(rows)
}

// findMACOwners answers FindByIdentifier for `mac_address`: the identifier
// rows, unioned with every interface MAC the DCIM tables hold.
func findMACOwners(ctx context.Context, tx *sql.Tx, tenantID, value, scope string) ([]uuid.UUID, error) {
	mac, ok := macAddr8(value)
	if !ok || scope != "" {
		// Not a MAC the columns can hold, or a scoped lookup (MACs are
		// unscoped): only the identifier rows can answer.
		rows, err := tx.QueryContext(ctx, FindMACOwnersMarker+`
			SELECT asset_id FROM public.asset_identifiers
			 WHERE tenant_id = $1 AND kind = 'mac_address' AND value = $2 AND coalesce(scope, '') = $3
			 ORDER BY asset_id`, tenantID, value, scope)
		if err != nil {
			return nil, fmt.Errorf("identity/postgres: find mac_address: %w", err)
		}
		return scanUUIDs(rows)
	}
	rows, err := tx.QueryContext(ctx, FindMACOwnersMarker+`
		SELECT asset_id FROM public.asset_identifiers
		 WHERE tenant_id = $1 AND kind = 'mac_address' AND value = $2 AND coalesce(scope, '') = ''
		UNION
		SELECT ifc.asset_id FROM public.interfaces ifc
		 WHERE ifc.tenant_id = $1 AND ifc.mac_address = $3::macaddr8 AND ifc.status <> 'rejected'
		UNION
		SELECT ifc.asset_id FROM public.mac_addresses m
		  JOIN public.interfaces ifc ON ifc.tenant_id = m.tenant_id AND ifc.id = m.interface_id
		 WHERE m.tenant_id = $1 AND m.mac = $3::macaddr8 AND ifc.status <> 'rejected'
		UNION
		SELECT ifc.asset_id FROM public.ip_addresses ip
		  JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
		 WHERE ip.tenant_id = $1 AND ip.mac_address = $3::macaddr8 AND ip.assigned_kind = 'interface'
		   AND ip.status <> 'rejected' AND ifc.status <> 'rejected'
		ORDER BY 1`, tenantID, value, mac)
	if err != nil {
		return nil, fmt.Errorf("identity/postgres: find mac_address: %w", err)
	}
	return scanUUIDs(rows)
}

// addressHeldElsewhere is attach's conflict check: does an interface of ANOTHER
// asset hold the address in this scope? The unique index on
// asset_identifiers answered it for an identifier row; for an address it is
// this read, under the identifier lock lockIdentifiers took.
func addressHeldElsewhere(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID, id identity.Identifier) (bool, error) {
	a, ok := parseHost(id.Value)
	if !ok {
		return false, nil
	}
	var held bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM public.ip_addresses ip
		      JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
		     WHERE ip.tenant_id = $1 AND ip.vrf_id IS NULL AND ip.host = $2::inet
		       AND ip.assigned_kind = 'interface'
		       AND ip.status <> 'rejected' AND ifc.status <> 'rejected'
		       AND (ip.identity_scope IS NULL OR ip.identity_scope = $3)
		       AND ifc.asset_id <> $4)`, tenantID, a.String(), id.Scope, assetID).Scan(&held)
	if err != nil {
		return false, fmt.Errorf("identity/postgres: check address %s: %w", id.Value, err)
	}
	return held, nil
}

func scanUUIDs(rows *sql.Rows) ([]uuid.UUID, error) {
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("identity/postgres: scan owner: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// storedInterface is one existing interface of an asset.
type storedInterface struct {
	id uuid.UUID
	identity.StoredInterface
	primaryMAC string
}

// loadInterfaces reads the asset's live interfaces with their MACs and
// global-VRF addresses, oldest first.
func loadInterfaces(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID) ([]*storedInterface, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT ifc.id, ifc.name, coalesce(ifc.source_ref, '') = $3 AND ifc.source_kind = 'measured',
		       coalesce(ifc.mac_address::text, ''),
		       coalesce((SELECT array_agg(m.mac::text ORDER BY m.created_at, m.mac)
		                   FROM public.mac_addresses m
		                  WHERE m.tenant_id = ifc.tenant_id AND m.interface_id = ifc.id), '{}'),
		       coalesce((SELECT array_agg(host(ip.address) ORDER BY ip.created_at, ip.host)
		                   FROM public.ip_addresses ip
		                  WHERE ip.tenant_id = ifc.tenant_id AND ip.assigned_kind = 'interface'
		                    AND ip.assigned_id = ifc.id AND ip.vrf_id IS NULL AND ip.status <> 'rejected'), '{}')
		  FROM public.interfaces ifc
		 WHERE ifc.tenant_id = $1 AND ifc.asset_id = $2 AND ifc.status <> 'rejected'
		 ORDER BY ifc.created_at, ifc.name`, tenantID, assetID, identity.SyntheticInterfaceSourceRef)
	if err != nil {
		return nil, fmt.Errorf("identity/postgres: read interfaces: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*storedInterface
	for rows.Next() {
		var (
			s          storedInterface
			synthetic  bool
			primary    string
			macs, adds pq.StringArray
		)
		if err := rows.Scan(&s.id, &s.Name, &synthetic, &primary, &macs, &adds); err != nil {
			return nil, fmt.Errorf("identity/postgres: scan interface: %w", err)
		}
		s.Synthetic = synthetic && identity.IsSyntheticInterfaceName(s.Name)
		if primary != "" {
			s.primaryMAC = macIdentifier(primary)
			s.MACs = append(s.MACs, s.primaryMAC)
		}
		for _, m := range macs {
			if v := macIdentifier(m); v != "" && v != s.primaryMAC {
				s.MACs = append(s.MACs, v)
			}
		}
		s.Addresses = append(s.Addresses, adds...)
		out = append(out, &s)
	}
	return out, rows.Err()
}

// macIdentifier turns a macaddr8 column's text back into the identifier's
// canonical spelling: a 6-byte MAC Postgres stored as EUI-64 (ff:fe in the
// middle) is reported as the 6-byte MAC it was.
func macIdentifier(v string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	if len(hw) == 8 && hw[3] == 0xff && hw[4] == 0xfe {
		hw = net.HardwareAddr{hw[0], hw[1], hw[2], hw[5], hw[6], hw[7]}
	}
	n, err := identity.Normalize(identity.KindMACAddress, hw.String())
	if err != nil {
		return hw.String()
	}
	return n
}

// fileUnderInterfaces writes the MACs and addresses among ids under the
// asset's interfaces, and returns how many ADDRESSES were new to the asset
// (the `added` count AttachIdentifiers reports for the kinds it no longer
// writes to `asset_identifiers`). An address another asset holds in the same
// scope is [identity.ErrIdentifierConflict], checked before anything is
// written.
func (r *Repository) fileUnderInterfaces(ctx context.Context, tx *sql.Tx, asset identity.AssetRef, assetID uuid.UUID, ids []identity.Identifier) (int, error) {
	norm := make([]identity.Identifier, 0, len(ids))
	for _, raw := range ids {
		if raw.Kind != identity.KindMACAddress && raw.Kind != identity.KindIPAddress {
			continue
		}
		id, err := raw.Normalized()
		if err != nil {
			return 0, err
		}
		if id.Kind == identity.KindIPAddress {
			if _, ok := parseHost(id.Value); !ok {
				continue
			}
		}
		norm = append(norm, id)
	}
	if len(norm) == 0 {
		return 0, nil
	}

	// Conflicts first: a failed attach must write nothing.
	for _, id := range norm {
		if id.Kind != identity.KindIPAddress {
			continue
		}
		held, err := addressHeldElsewhere(ctx, tx, asset.TenantID, assetID, id)
		if err != nil {
			return 0, err
		}
		if held {
			return 0, fmt.Errorf("%w: %s=%q", identity.ErrIdentifierConflict, id.Kind, id.Value)
		}
	}

	existing, err := loadInterfaces(ctx, tx, asset.TenantID, assetID)
	if err != nil {
		return 0, err
	}
	stored := make([]identity.StoredInterface, 0, len(existing))
	byName := make(map[string]*storedInterface, len(existing))
	for _, e := range existing {
		stored = append(stored, e.StoredInterface)
		byName[e.Name] = e
	}
	status, err := componentStatus(ctx, tx, asset.TenantID, assetID)
	if err != nil {
		return 0, err
	}

	added := 0
	for _, as := range identity.ResolveInterfaces(stored, identity.PlanInterfaces(norm)) {
		src := planSource(as)
		var target *storedInterface
		switch {
		case as.RenameFrom != "":
			target = byName[as.RenameFrom]
			if err := renameInterface(ctx, tx, asset.TenantID, target, as.Name, src); err != nil {
				return 0, err
			}
			delete(byName, as.RenameFrom)
			byName[as.Name] = target
		case as.Create:
			target, err = createInterface(ctx, tx, asset.TenantID, assetID, as, src, status)
			if err != nil {
				return 0, err
			}
			byName[as.Name] = target
		default:
			target = byName[as.Name]
		}
		if target == nil {
			return 0, fmt.Errorf("identity/postgres: interface %q of %s vanished mid-attach", as.Name, asset.ID)
		}
		if err := addInterfaceMACs(ctx, tx, asset.TenantID, target, as.MACs, src); err != nil {
			return 0, err
		}
		for _, ad := range as.Addresses {
			isNew, err := upsertAddress(ctx, tx, asset.TenantID, assetID, target.id, ad, status)
			if err != nil {
				return 0, err
			}
			if isNew {
				added++
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE public.interfaces
			   SET last_seen_at = GREATEST(last_seen_at, $3), observation_count = observation_count + 1
			 WHERE tenant_id = $1 AND id = $2`, asset.TenantID, target.id, timeOrNow(src.seenAt)); err != nil {
			return 0, fmt.Errorf("identity/postgres: touch interface %q: %w", target.Name, err)
		}
	}
	if err := setPrimaryIPs(ctx, tx, asset.TenantID, assetID); err != nil {
		return 0, err
	}
	if err := linkEndpointAddresses(ctx, tx, asset.TenantID, assetID); err != nil {
		return 0, err
	}
	return added, nil
}

// linkEndpointAddresses sets `asset_endpoints.ip_address_id` on the asset's
// endpoints that have none, once an `ip_addresses` row exists for the address
// (DATA_MODEL §5 "Services": resolved on write). The asset's own address — on
// one of its interfaces — is preferred; otherwise the global VRF's row for the
// address. It runs after the asset's endpoints or addresses change, whichever
// lands second, so the order an observation's parts arrive in does not matter.
func linkEndpointAddresses(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.asset_endpoints e
		   SET ip_address_id = (
		         SELECT ip.id FROM public.ip_addresses ip
		           LEFT JOIN public.interfaces ifc
		             ON ip.assigned_kind = 'interface' AND ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
		          WHERE ip.tenant_id = e.tenant_id AND ip.vrf_id IS NULL AND ip.host = public.ipam_host(e.address)
		            AND ip.status <> 'rejected'
		          ORDER BY (ifc.asset_id = e.asset_id) DESC NULLS LAST, ip.created_at
		          LIMIT 1)
		 WHERE e.tenant_id = $1 AND e.asset_id = $2 AND e.address IS NOT NULL AND e.ip_address_id IS NULL`,
		tenantID, assetID); err != nil {
		return fmt.Errorf("identity/postgres: link endpoint addresses: %w", err)
	}
	return nil
}

// planProvenance is the provenance an interface written for a plan carries:
// the strongest of the values filed under it.
type planProvenance struct {
	kind   string
	ref    string
	seenAt time.Time
}

func planSource(as identity.InterfaceAssignment) planProvenance {
	p := planProvenance{kind: string(identity.SourceMeasured)}
	best := -1
	consider := func(s identity.Source, at time.Time) {
		k := identity.SourceKind(sourceKindOr(s.Kind))
		if rk := identity.SourceRank(k); rk > best {
			best, p.kind, p.ref = rk, string(k), s.Ref
		}
		if at.After(p.seenAt) {
			p.seenAt = at
		}
	}
	for _, ad := range as.Addresses {
		consider(ad.Source, ad.SeenAt)
	}
	if best < 0 {
		// A MAC-only plan: the MACs carry no per-value source here, so the
		// interface is measured, by the engine.
		p.ref = "identity"
	}
	return p
}

// componentStatus is the lifecycle status an interface or address the engine
// writes starts in: `active` on an approved asset, `pending` otherwise — the
// rule interface_service.UpsertObserved applies, so the two writers agree.
func componentStatus(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID) (string, error) {
	var st string
	err := tx.QueryRowContext(ctx, `SELECT asset_status FROM public.assets WHERE tenant_id = $1 AND id = $2`, tenantID, assetID).Scan(&st)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: %s", identity.ErrAssetNotFound, assetID)
		}
		return "", fmt.Errorf("identity/postgres: read asset status: %w", err)
	}
	if st == identity.StatusMonitoring {
		return "active", nil
	}
	return "pending", nil
}

func createInterface(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID, as identity.InterfaceAssignment, src planProvenance, status string) (*storedInterface, error) {
	sourceKind, sourceRef := src.kind, src.ref
	if as.Synthetic {
		sourceKind, sourceRef = string(identity.SourceMeasured), identity.SyntheticInterfaceSourceRef
	}
	var primary any
	if len(as.MACs) > 0 {
		if m, ok := macAddr8(as.MACs[0]); ok {
			primary = m
		}
	}
	id := uuid.New()
	seen := timeOrNow(src.seenAt)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO public.interfaces (id, tenant_id, asset_id, name, type, mac_address, source_kind, source_ref,
		                               status, first_seen_at, last_seen_at, observation_count)
		VALUES ($1, $2, $3, $4, $5, $6::macaddr8, $7, NULLIF($8, ''), $9, $10, $10, 0)`,
		id, tenantID, assetID, as.Name, identity.SyntheticInterfaceType, primary, sourceKind, sourceRef, status, seen); err != nil {
		return nil, fmt.Errorf("identity/postgres: create interface %q: %w", as.Name, err)
	}
	post := map[string]any{"name": as.Name, "type": identity.SyntheticInterfaceType, "asset_id": assetID.String(),
		"source_kind": sourceKind, "source_ref": sourceRef, "status": status}
	if primary != nil {
		post["mac_address"] = primary
	}
	if err := recordChange(ctx, tx, tenantID, dcim.ObjectKindInterface, id, changes.ActionCreate, nil, post); err != nil {
		return nil, err
	}
	s := &storedInterface{id: id}
	s.Name, s.Synthetic = as.Name, as.Synthetic
	if len(as.MACs) > 0 {
		s.primaryMAC = as.MACs[0]
		s.MACs = []string{as.MACs[0]}
	}
	return s, nil
}

// renameInterface is the "merge by MAC and rename" of row 1.4: a report that
// names the interface a synthetic one stood in for renames it and takes over
// its provenance, which is what un-flags it.
func renameInterface(ctx context.Context, tx *sql.Tx, tenantID string, s *storedInterface, name string, src planProvenance) error {
	if s == nil {
		return errors.New("identity/postgres: rename of an unknown interface")
	}
	ref := src.ref
	if ref == "" || ref == identity.SyntheticInterfaceSourceRef {
		ref = "identity"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.interfaces SET name = $3, source_kind = $4, source_ref = $5, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`, tenantID, s.id, name, src.kind, ref); err != nil {
		return fmt.Errorf("identity/postgres: rename interface %q to %q: %w", s.Name, name, err)
	}
	if err := recordChange(ctx, tx, tenantID, dcim.ObjectKindInterface, s.id, changes.ActionUpdate,
		map[string]any{"name": s.Name, "source_ref": identity.SyntheticInterfaceSourceRef},
		map[string]any{"name": name, "source_ref": ref}); err != nil {
		return err
	}
	s.Name, s.Synthetic = name, false
	return nil
}

// addInterfaceMACs puts MACs on an interface: the first becomes its primary
// MAC when it has none, every other one a `mac_addresses` row.
func addInterfaceMACs(ctx context.Context, tx *sql.Tx, tenantID string, s *storedInterface, macs []string, src planProvenance) error {
	for _, m := range macs {
		if containsStr(s.MACs, m) {
			continue
		}
		col, ok := macAddr8(m)
		if !ok {
			continue
		}
		if s.primaryMAC == "" {
			if _, err := tx.ExecContext(ctx, `
				UPDATE public.interfaces SET mac_address = $3::macaddr8, updated_at = now()
				 WHERE tenant_id = $1 AND id = $2`, tenantID, s.id, col); err != nil {
				return fmt.Errorf("identity/postgres: set MAC on interface %q: %w", s.Name, err)
			}
			if err := recordChange(ctx, tx, tenantID, dcim.ObjectKindInterface, s.id, changes.ActionUpdate,
				map[string]any{"mac_address": nil}, map[string]any{"mac_address": col}); err != nil {
				return err
			}
			s.primaryMAC = m
		} else {
			id := uuid.New()
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO public.mac_addresses (id, tenant_id, interface_id, mac, is_primary, source_kind, source_ref)
				VALUES ($1, $2, $3, $4::macaddr8, false, 'measured', NULLIF($5, ''))
				ON CONFLICT DO NOTHING`, id, tenantID, s.id, col, src.ref); err != nil {
				return fmt.Errorf("identity/postgres: add MAC to interface %q: %w", s.Name, err)
			}
			if err := recordChange(ctx, tx, tenantID, dcim.ObjectKindMacAddress, id, changes.ActionCreate, nil,
				map[string]any{"interface_id": s.id.String(), "mac": col}); err != nil {
				return err
			}
		}
		s.MACs = append(s.MACs, m)
	}
	return nil
}

// lastSeenSource maps an identifier's provenance onto
// `ip_addresses.last_seen_source`'s vocabulary.
func lastSeenSource(s identity.Source) string {
	ref := strings.ToLower(s.Ref)
	switch {
	case s.Kind == identity.SourceDeclared:
		return "declared"
	case strings.HasPrefix(ref, "cloud"):
		return "cloud"
	case strings.HasPrefix(ref, "agent") || strings.Contains(ref, "host_inventory") || strings.Contains(ref, "device-agent"):
		return "agent"
	case strings.Contains(ref, "dhcp"):
		return "dhcp"
	case strings.Contains(ref, "arp"):
		return "arp"
	case s.Mode == identity.ModeActive || strings.HasPrefix(ref, "scan") || strings.HasPrefix(ref, "probe"):
		return "probe"
	default:
		return "passive"
	}
}

// upsertAddress writes one `ip_address` identifier as an `ip_addresses` row
// assigned to the interface, and reports whether the address was new to the
// asset. Provenance on a re-sighting follows [identity.UpsertIdentifier]'s
// rule, the one `asset_identifiers` applied: source kind moves only up, its ref
// travels with it, a pin is never lost to a weaker or silent sighting,
// last-seen and device confirmation never move backwards.
//
// The row adopted, in order: one this asset already holds in the scope; else
// the one THIS INTERFACE already holds for the host in an older scope — the
// tenant's topology changed under it (a prefix or a segment now covers the
// address, DCIM row 1.5a) and the row follows the address into its current
// scope rather than a second row being written for one address on one
// interface; else one this asset holds for the host in the TENANT DEFAULT
// scope, on any of its interfaces — the address was filed before any prefix
// covered it (a device record's synthetic interface), and the first sighting
// that names its interface AND its prefix moves it there (DCIM row 1.6: a
// device's own sighting records its prefixes before it is scoped); else
// an address IPAM holds on no interface (a declared or ARP-seen address
// becomes the asset's); else a new row, masked to the longest-matching prefix
// the way NetBox records an interface address.
func upsertAddress(ctx context.Context, tx *sql.Tx, tenantID string, assetID, ifaceID uuid.UUID, id identity.Identifier, status string) (bool, error) {
	host, _ := parseHost(id.Value)
	var (
		rowID    uuid.UUID
		assigned sql.NullString
		owner    uuid.NullUUID
	)
	err := tx.QueryRowContext(ctx, `
		SELECT ip.id, ip.assigned_kind, ifc.asset_id
		  FROM public.ip_addresses ip
		  LEFT JOIN public.interfaces ifc
		    ON ip.assigned_kind = 'interface' AND ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
		 WHERE ip.tenant_id = $1 AND ip.vrf_id IS NULL AND ip.host = $2::inet AND ip.status <> 'rejected'
		   AND (((ip.identity_scope IS NULL OR ip.identity_scope = $3) AND (ifc.asset_id = $4 OR ip.assigned_id IS NULL))
		        OR (ip.assigned_kind = 'interface' AND ip.assigned_id = $5)
		        OR (ip.identity_scope = $6 AND ifc.asset_id = $4))
		 ORDER BY (ifc.asset_id = $4 AND (ip.identity_scope IS NULL OR ip.identity_scope = $3)) DESC NULLS LAST,
		          (ip.assigned_id = $5) DESC NULLS LAST,
		          (ifc.asset_id = $4) DESC NULLS LAST, (ip.identity_scope IS NULL), ip.created_at
		 LIMIT 1
		 FOR UPDATE OF ip`, tenantID, host.String(), id.Scope, assetID, ifaceID, identity.ScopeTenantDefault).Scan(&rowID, &assigned, &owner)
	isNew := true
	switch {
	case errors.Is(err, sql.ErrNoRows):
		rowID = uuid.New()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO public.ip_addresses (id, tenant_id, address, operational_status, assigned_kind, assigned_id,
			                                 last_seen_source, status, first_seen_at, last_seen_at, observation_count,
			                                 source_kind, source_ref, identity_scope, address_assignment,
			                                 device_confirmed_at, identity_confidence)
			VALUES ($1, $2,
			        coalesce((SELECT set_masklen($3::inet, masklen(p.prefix)) FROM public.prefixes p
			                   WHERE p.tenant_id = $2 AND p.vrf_id IS NULL AND p.status <> 'rejected'
			                     AND family(p.prefix) = family($3::inet) AND p.prefix >>= $3::inet
			                   ORDER BY masklen(p.prefix) DESC LIMIT 1), $3::inet),
			        CASE WHEN $4::text = 'dynamic' THEN 'dhcp' ELSE 'active' END, 'interface', $5,
			        $6, $7, $8, $8, 1, $9, NULLIF($10::text, ''), $11, NULLIF($4::text, ''), $12, $13)`,
			rowID, tenantID, host.String(), string(id.StoredAssignment()), ifaceID,
			lastSeenSource(id.Source), status, timeOrNow(id.SeenAt), sourceKindOr(id.Source.Kind), id.Source.Ref,
			id.Scope, nullTime(id.DeviceConfirmedAt), clampConfidence(id.Confidence)); err != nil {
			return false, fmt.Errorf("identity/postgres: write address %s: %w", id.Value, err)
		}
		return true, recordChange(ctx, tx, tenantID, dcim.ObjectKindIpAddress, rowID, changes.ActionCreate, nil,
			map[string]any{"address": host.String(), "assigned_kind": "interface", "assigned_id": ifaceID.String(),
				"source_kind": sourceKindOr(id.Source.Kind), "status": status})
	case err != nil:
		return false, fmt.Errorf("identity/postgres: read address %s: %w", id.Value, err)
	}
	if owner.Valid && owner.UUID == assetID {
		isNew = false
	}
	// The identity scope is recorded on a row the engine owns; an adopted IPAM
	// row with none stays the VRF's answer for every scope.
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.ip_addresses ip
		   SET assigned_kind = 'interface', assigned_id = $3,
		       identity_scope = CASE WHEN ip.source_kind = 'declared' THEN ip.identity_scope
		                             WHEN ip.identity_scope IS NOT NULL AND $4::text <> '' THEN $4::text
		                             ELSE coalesce(ip.identity_scope, NULLIF($4::text, '')) END,
		       last_seen_at = GREATEST(coalesce(ip.last_seen_at, $5::timestamptz), $5::timestamptz),
		       first_seen_at = coalesce(ip.first_seen_at, $5),
		       device_confirmed_at = GREATEST(ip.device_confirmed_at, $6::timestamptz),
		       identity_confidence = GREATEST(coalesce(ip.identity_confidence, 0), $7::numeric),
		       address_assignment = CASE
		           WHEN $8::text <> '' AND `+sourceRankSQL("$9::text")+` >= `+sourceRankSQL("ip.source_kind")+`
		           THEN $8::text ELSE ip.address_assignment END,
		       source_ref = CASE
		           WHEN `+sourceRankSQL("$9::text")+` > `+sourceRankSQL("ip.source_kind")+` THEN NULLIF($10::text, '')
		           WHEN $9::text = ip.source_kind THEN coalesce(NULLIF($10::text, ''), ip.source_ref)
		           ELSE ip.source_ref END,
		       source_kind = CASE
		           WHEN `+sourceRankSQL("$9::text")+` > `+sourceRankSQL("ip.source_kind")+` THEN $9::text
		           ELSE ip.source_kind END,
		       last_seen_source = CASE WHEN ip.source_kind = 'declared' AND $9::text <> 'declared'
		                               THEN coalesce(ip.last_seen_source, $11::text) ELSE $11::text END,
		       observation_count = ip.observation_count + 1,
		       updated_at = now()
		 WHERE ip.tenant_id = $1 AND ip.id = $2`,
		tenantID, rowID, ifaceID, id.Scope, timeOrNow(id.SeenAt), nullTime(id.DeviceConfirmedAt),
		clampConfidence(id.Confidence), string(id.StoredAssignment()), sourceKindOr(id.Source.Kind), id.Source.Ref,
		lastSeenSource(id.Source)); err != nil {
		return false, fmt.Errorf("identity/postgres: refresh address %s: %w", id.Value, err)
	}
	if isNew {
		if err := recordChange(ctx, tx, tenantID, dcim.ObjectKindIpAddress, rowID, changes.ActionUpdate,
			map[string]any{"assigned_kind": nullStr(assigned), "assigned_id": nil},
			map[string]any{"assigned_kind": "interface", "assigned_id": ifaceID.String()}); err != nil {
			return false, err
		}
	}
	return isNew, nil
}

// setPrimaryIPs fills `assets.primary_ip4_id` / `primary_ip6_id` by rule
// ([identity.PickPrimaryIP]) when nobody has chosen them: the asset's stated
// `primary_address` when it holds it, else a management interface's address,
// else its first non-link-local one. A choice already made — by a person, or
// an earlier sighting — is never overwritten.
func setPrimaryIPs(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID) error {
	var (
		stated     string
		has4, has6 bool
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT coalesce(host(primary_address), ''), primary_ip4_id IS NOT NULL, primary_ip6_id IS NOT NULL
		  FROM public.assets WHERE tenant_id = $1 AND id = $2`, tenantID, assetID).Scan(&stated, &has4, &has6); err != nil {
		return fmt.Errorf("identity/postgres: read primary addresses: %w", err)
	}
	if has4 && has6 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT ip.id, host(ip.address), ifc.mgmt_only
		  FROM public.ip_addresses ip
		  JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
		 WHERE ip.tenant_id = $1 AND ifc.asset_id = $2 AND ip.assigned_kind = 'interface'
		   AND ip.status <> 'rejected' AND ifc.status <> 'rejected'
		 ORDER BY ip.first_seen_at NULLS LAST, ip.created_at, ip.host`, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("identity/postgres: read asset addresses: %w", err)
	}
	ids := map[string]uuid.UUID{}
	var cands []identity.PrimaryAddressCandidate
	for rows.Next() {
		var (
			id   uuid.UUID
			addr string
			mgmt bool
		)
		if err := rows.Scan(&id, &addr, &mgmt); err != nil {
			_ = rows.Close()
			return err
		}
		if _, dup := ids[addr]; !dup {
			ids[addr] = id
			cands = append(cands, identity.PrimaryAddressCandidate{Address: addr, Management: mgmt})
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, fam := range []struct {
		col string
		v6  bool
		has bool
	}{{"primary_ip4_id", false, has4}, {"primary_ip6_id", true, has6}} {
		if fam.has {
			continue
		}
		pick := identity.PickPrimaryIP(stated, cands, fam.v6)
		if pick == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE public.assets SET `+fam.col+` = $3, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2 AND `+fam.col+` IS NULL`, tenantID, assetID, ids[pick]); err != nil {
			return fmt.Errorf("identity/postgres: set %s: %w", fam.col, err)
		}
	}
	return nil
}

// releaseAddress takes an address off the asset: the row is unassigned and its
// identity metadata cleared, so it names no asset any more but IPAM keeps the
// fact that the address was seen. Zero rows is reported, not hidden.
func releaseAddress(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID, id identity.Identifier) (int64, error) {
	host, ok := parseHost(id.Value)
	if !ok {
		return 0, nil
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE public.ip_addresses ip
		   SET assigned_kind = NULL, assigned_id = NULL, identity_scope = NULL, address_assignment = NULL,
		       device_confirmed_at = NULL, updated_at = now()
		  FROM public.interfaces ifc
		 WHERE ip.tenant_id = $1 AND ip.vrf_id IS NULL AND ip.host = $3::inet AND ip.assigned_kind = 'interface'
		   AND ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id AND ifc.asset_id = $2
		   AND ip.status <> 'rejected'
		   AND (ip.identity_scope IS NULL OR ip.identity_scope = $4)`,
		tenantID, assetID, host.String(), id.Scope)
	if err != nil {
		return 0, fmt.Errorf("identity/postgres: release %s: %w", id.Value, err)
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return n, err
	}
	// A primary address the asset no longer holds is not its primary: clear
	// it, and let the rule pick again from what is left.
	for _, col := range []string{"primary_ip4_id", "primary_ip6_id"} {
		if _, err := tx.ExecContext(ctx, `
			UPDATE public.assets a SET `+col+` = NULL, updated_at = now()
			 WHERE a.tenant_id = $1 AND a.id = $2 AND a.`+col+` IS NOT NULL
			   AND NOT EXISTS (SELECT 1 FROM public.ip_addresses ip
			                     JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
			                    WHERE ip.tenant_id = a.tenant_id AND ip.id = a.`+col+`
			                      AND ip.assigned_kind = 'interface' AND ifc.asset_id = a.id)`, tenantID, assetID); err != nil {
			return 0, fmt.Errorf("identity/postgres: clear %s: %w", col, err)
		}
	}
	return n, setPrimaryIPs(ctx, tx, tenantID, assetID)
}

// stripInterfaceMAC takes a MAC off every interface of the asset — the
// interface half of retiring or moving a `mac_address` identifier, so the MAC
// union in [findMACOwners] does not keep answering for the old owner.
func stripInterfaceMAC(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID, value string) error {
	mac, ok := macAddr8(value)
	if !ok {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.interfaces SET mac_address = NULL, updated_at = now()
		 WHERE tenant_id = $1 AND asset_id = $2 AND mac_address = $3::macaddr8`, tenantID, assetID, mac); err != nil {
		return fmt.Errorf("identity/postgres: strip MAC: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM public.mac_addresses m USING public.interfaces ifc
		 WHERE m.tenant_id = $1 AND ifc.tenant_id = m.tenant_id AND ifc.id = m.interface_id
		   AND ifc.asset_id = $2 AND m.mac = $3::macaddr8`, tenantID, assetID, mac); err != nil {
		return fmt.Errorf("identity/postgres: strip MAC: %w", err)
	}
	return nil
}

func recordChange(ctx context.Context, tx *sql.Tx, tenantID string, kind dcim.ObjectKind, id uuid.UUID, action changes.Action, pre, post map[string]any) error {
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("identity/postgres: tenant id %q is not a uuid: %w", tenantID, err)
	}
	c := changes.Change{TenantID: tid, Kind: kind, ID: id, Action: action, Source: identityChangeSource}
	if pre != nil {
		c.Pre = pre
	}
	if post != nil {
		c.Post = post
	}
	if err := changes.InTx(tx).Record(ctx, c); err != nil {
		return fmt.Errorf("identity/postgres: record %s change: %w", kind, err)
	}
	return nil
}

func nullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t.UTC(), Valid: !t.IsZero()}
}

func nullStr(s sql.NullString) any {
	if s.Valid {
		return s.String
	}
	return nil
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// errNotInterfaceBorne tells FindByIdentifier the kind is stored as an
// identifier row only.
var errNotInterfaceBorne = errors.New("identity/postgres: not an interface-borne kind")

// Interfaces returns the asset's live interfaces, oldest first, with their
// MACs (primary first) and global-VRF addresses. It is the read-back
// identitytest.InterfaceReader needs; nothing in the engine reads it.
func (r *Repository) Interfaces(ref identity.AssetRef) []identity.StoredInterface {
	assetID, err := parseAsset(ref.ID)
	if err != nil {
		return nil
	}
	var out []identity.StoredInterface
	_ = r.withTx(context.Background(), ref.TenantID, func(tx *sql.Tx) error {
		got, err := loadInterfaces(context.Background(), tx, ref.TenantID, assetID)
		if err != nil {
			return err
		}
		for _, s := range got {
			out = append(out, s.StoredInterface)
		}
		return nil
	})
	return out
}

// annotateMatchedInterfaces names, on each candidate's matched MACs and
// addresses, the interface of THAT candidate that holds the value (row 1.4):
// "matched 00:11:22:33:44:55 on eth1" is evidence a reviewer can check, where a
// bare MAC is not. The proposal's slices are copied, never written through.
func (r *Repository) annotateMatchedInterfaces(ctx context.Context, tenantID string, p identity.MergeProposal) (identity.MergeProposal, error) {
	need := false
	for _, c := range p.Candidates {
		for _, id := range c.MatchedIdentifiers {
			if (id.Kind == identity.KindIPAddress || id.Kind == identity.KindMACAddress) && id.Interface == "" {
				need = true
			}
		}
	}
	if !need {
		return p, nil
	}
	cands := make([]identity.MergeCandidate, len(p.Candidates))
	copy(cands, p.Candidates)
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		for i := range cands {
			assetID, err := parseAsset(cands[i].Ref.ID)
			if err != nil {
				continue
			}
			ids := append([]identity.Identifier(nil), cands[i].MatchedIdentifiers...)
			for j := range ids {
				if ids[j].Interface != "" {
					continue
				}
				name, err := interfaceHolding(ctx, tx, tenantID, assetID, ids[j])
				if err != nil {
					return err
				}
				ids[j].Interface = name
			}
			cands[i].MatchedIdentifiers = ids
		}
		return nil
	})
	if err != nil {
		return p, err
	}
	p.Candidates = cands
	return p, nil
}

// interfaceHolding is the name of the asset's interface holding a MAC or an
// address, or "" when none does (an identifier-row MAC on no interface).
func interfaceHolding(ctx context.Context, tx *sql.Tx, tenantID string, assetID uuid.UUID, id identity.Identifier) (string, error) {
	var (
		q   string
		arg string
	)
	switch id.Kind {
	case identity.KindIPAddress:
		a, ok := parseHost(id.Value)
		if !ok {
			return "", nil
		}
		q, arg = `
			SELECT ifc.name FROM public.ip_addresses ip
			  JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
			 WHERE ip.tenant_id = $1 AND ifc.asset_id = $2 AND ip.assigned_kind = 'interface' AND ip.host = $3::inet
			 ORDER BY ifc.created_at LIMIT 1`, a.String()
	case identity.KindMACAddress:
		m, ok := macAddr8(id.Value)
		if !ok {
			return "", nil
		}
		q, arg = `
			SELECT name FROM (
			    SELECT ifc.name, ifc.created_at FROM public.interfaces ifc
			     WHERE ifc.tenant_id = $1 AND ifc.asset_id = $2 AND ifc.mac_address = $3::macaddr8
			    UNION ALL
			    SELECT ifc.name, ifc.created_at FROM public.mac_addresses mm
			      JOIN public.interfaces ifc ON ifc.tenant_id = mm.tenant_id AND ifc.id = mm.interface_id
			     WHERE mm.tenant_id = $1 AND ifc.asset_id = $2 AND mm.mac = $3::macaddr8) held
			 ORDER BY created_at LIMIT 1`, m
	default:
		return "", nil
	}
	var name string
	err := tx.QueryRowContext(ctx, q, tenantID, assetID, arg).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("identity/postgres: interface holding %s: %w", id.Value, err)
	}
	return name, nil
}
