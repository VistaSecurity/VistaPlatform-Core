package postgres

// DCIM row 1.5: the posture half of an observation's network evidence.
//
// The identity half — an interface's MAC and its global-VRF addresses — was
// already filed by AttachIdentifiers (addresses.go, row 1.4's one rule). This
// records what is not identity, on the engine's own transaction:
//
//   - VLANs (`vlans`, global: no group, no site) and prefixes (`prefixes`),
//     with UpsertObservedPrefix's semantics: a new row is `measured` and
//     `pending`; an existing one gets its measured columns refreshed and a
//     declared column only where nobody has said (COALESCE);
//   - each interface by (asset, canonical name), with
//     interface_service.UpsertObserved's semantics: a new interface carries
//     the observation's source kind (`measured` from a collector, `declared` /
//     `imported` from the manual, spreadsheet and NetBox adapters of row
//     1.5f), its status following its asset; an existing one — measured or
//     declared — gets its MEASURED fields only (type while it is still `other`,
//     MTU, speed, operational and admin status). `enabled`, `description`,
//     `label`, `mgmt_only` and custom fields are never in a write here. The
//     structural fields a person may also set (parent, LAG, mode, untagged
//     VLAN) are filled where they are empty and never overwritten; tagged VLANs
//     are added, never removed;
//   - an address's configured length on its interface (NetBox records an
//     interface address with its mask), and addresses in a NAMED VRF, which
//     are recorded on the interface but are never identity;
//   - the device's virtual device contexts and each interface's membership
//     (DCIM gap 1, observed_vdc.go).
//
// It never writes a MAC or a global-VRF address the identity half did not:
// an interface's MAC is filled only when it is empty AND the asset already
// holds that MAC, so a value intake withheld as an identifier (a virtual
// interface's generated MAC, a locally administered one) cannot come back in
// through this door and start matching assets.
//
// Every row it creates or visibly changes is recorded in `object_changes`
// through shared/dcim/changes, source `intake:identity`.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/sites"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// RecordObservedNetwork implements [identity.ObservedNetworkRepository].
func (r *Repository) RecordObservedNetwork(ctx context.Context, asset identity.AssetRef, n identity.ObservedNetwork) (identity.ObservedNetworkResult, error) {
	var res identity.ObservedNetworkResult
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return res, err
	}
	at := timeOrNow(n.ObservedAt)
	err = r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		w := &networkWriter{ctx: ctx, tx: tx, tenant: asset.TenantID, asset: assetID, at: at, src: n.Source,
			res: &res, vlans: map[int]uuid.UUID{}, vrfs: map[string]*uuid.UUID{}}
		status, err := componentStatus(ctx, tx, asset.TenantID, assetID)
		if err != nil {
			return err
		}
		w.status = status
		if err := w.vlansOf(n); err != nil {
			return err
		}
		for _, p := range n.Prefixes {
			if err := w.prefix(p); err != nil {
				return err
			}
		}
		if err := w.interfaces(n.Interfaces); err != nil {
			return err
		}
		if err := w.virtualDeviceContexts(n); err != nil {
			return err
		}
		return w.wirelessOf(n)
	})
	return res, err
}

type networkWriter struct {
	ctx    context.Context
	tx     *sql.Tx
	tenant string
	asset  uuid.UUID
	at     time.Time
	src    identity.Source
	status string
	res    *identity.ObservedNetworkResult
	// vlans maps a VID to its row, for the VLANs this observation named or
	// referenced. vrfs caches VRF lookups by the observation's spelling (nil:
	// the tenant has no such VRF).
	vlans map[int]uuid.UUID
	vrfs  map[string]*uuid.UUID
}

func (w *networkWriter) skip(format string, args ...any) {
	w.res.Skipped = append(w.res.Skipped, fmt.Sprintf(format, args...))
}

func (w *networkWriter) record(kind dcim.ObjectKind, id uuid.UUID, action changes.Action, pre, post map[string]any) error {
	return recordChange(w.ctx, w.tx, w.tenant, kind, id, action, pre, post)
}

// ---------------------------------------------------------------- VLANs ----

// vlansOf upserts every VLAN the observation names, and every VID one of its
// interfaces or prefixes references: a VLAN carried on a port is a VLAN that
// exists. Each is counted once per observation.
func (w *networkWriter) vlansOf(n identity.ObservedNetwork) error {
	names := map[int]string{}
	var order []int
	add := func(vid int, name string) {
		if vid < 1 || vid > 4094 {
			return
		}
		if _, ok := names[vid]; !ok {
			order = append(order, vid)
			names[vid] = ""
		}
		if names[vid] == "" {
			names[vid] = name
		}
	}
	for _, v := range n.VLANs {
		add(v.VID, v.Name)
	}
	for _, ifc := range n.Interfaces {
		add(ifc.UntaggedVLAN, "")
		for _, v := range ifc.TaggedVLANs {
			add(v, "")
		}
	}
	for _, p := range n.Prefixes {
		add(p.VLAN, "")
	}
	for _, l := range n.WirelessLANs {
		add(l.VLAN, "")
	}
	for _, vid := range order {
		id, err := w.vlan(vid, names[vid])
		if err != nil {
			return err
		}
		w.vlans[vid] = id
	}
	return nil
}

func defaultVLANName(vid int) string { return fmt.Sprintf("VLAN %d", vid) }

func (w *networkWriter) vlan(vid int, name string) (uuid.UUID, error) {
	var (
		id         uuid.UUID
		cur, srcKd string
	)
	err := w.tx.QueryRowContext(w.ctx, `
		SELECT id, name, source_kind FROM public.vlans
		 WHERE tenant_id = $1 AND vid = $2 AND group_id IS NULL AND site_id IS NULL AND status <> 'rejected'
		 ORDER BY created_at, id LIMIT 1 FOR UPDATE`, w.tenant, vid).Scan(&id, &cur, &srcKd)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id = uuid.New()
		if name == "" {
			name = defaultVLANName(vid)
		}
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO public.vlans (id, tenant_id, vid, name, source_kind, source_ref, status,
			                          first_seen_at, last_seen_at, observation_count)
			VALUES ($1, $2, $3, $4, 'measured', NULLIF($5, ''), 'pending', $6, $6, 1)`,
			id, w.tenant, vid, name, w.src.Ref, w.at); err != nil {
			return uuid.Nil, fmt.Errorf("identity/postgres: create vlan %d: %w", vid, err)
		}
		w.res.VLANsCreated++
		return id, w.record(dcim.ObjectKindVlan, id, changes.ActionCreate, nil,
			map[string]any{"vid": vid, "name": name, "source_kind": "measured", "status": "pending"})
	case err != nil:
		return uuid.Nil, fmt.Errorf("identity/postgres: read vlan %d: %w", vid, err)
	}
	// A name is the source's only while nobody gave it one: a declared VLAN's
	// name, or one already measured, is not overwritten.
	newName := cur
	if name != "" && srcKd != "declared" && cur == defaultVLANName(vid) {
		newName = name
	}
	if _, err := w.tx.ExecContext(w.ctx, `
		UPDATE public.vlans
		   SET name = $3, last_seen_at = GREATEST(coalesce(last_seen_at, $4), $4), first_seen_at = coalesce(first_seen_at, $4),
		       observation_count = observation_count + 1, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`, w.tenant, id, newName, w.at); err != nil {
		return uuid.Nil, fmt.Errorf("identity/postgres: refresh vlan %d: %w", vid, err)
	}
	w.res.VLANsUpdated++
	if newName != cur {
		return id, w.record(dcim.ObjectKindVlan, id, changes.ActionUpdate, map[string]any{"name": cur}, map[string]any{"name": newName})
	}
	return id, nil
}

// ----------------------------------------------------------------- VRFs ----

// vrf resolves the observation's VRF spelling (a name or a route
// distinguisher) to the tenant's VRF. "" is the global table (nil, true); an
// unknown VRF is (nil, false): the writer never creates a VRF, because a VRF a
// collector names but nobody declared is a routing-table question for a
// person, not a row to invent.
func (w *networkWriter) vrf(spelling string) (*uuid.UUID, bool, error) {
	spelling = strings.TrimSpace(spelling)
	if spelling == "" {
		return nil, true, nil
	}
	if id, ok := w.vrfs[spelling]; ok {
		return id, id != nil, nil
	}
	var id uuid.UUID
	err := w.tx.QueryRowContext(w.ctx, `
		SELECT id FROM public.vrfs WHERE tenant_id = $1 AND (name = $2 OR rd = $2)
		 ORDER BY (name = $2) DESC, created_at, id LIMIT 1`, w.tenant, spelling).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		w.vrfs[spelling] = nil
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("identity/postgres: read vrf %q: %w", spelling, err)
	}
	w.vrfs[spelling] = &id
	return &id, true, nil
}

func vrfArg(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}

// ------------------------------------------------------------- prefixes ----

func nilIfBlank(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func (w *networkWriter) prefix(p identity.ObservedPrefix) error {
	vrfID, ok, err := w.vrf(p.VRF)
	if err != nil {
		return err
	}
	if !ok {
		w.skip("prefix %s: VRF %q is not one of the tenant's", p.Prefix, p.VRF)
		return nil
	}
	var vlan any
	if id, ok := w.vlans[p.VLAN]; ok {
		vlan = id
	}
	var dhcp any
	if p.DHCPManaged != nil {
		dhcp = *p.DHCPManaged
	}
	scopeKind, scopeID := w.prefixScope(p)
	var id uuid.UUID
	// A cloud network's prefix is its own row (prefixes_identity_uniq keys on
	// cloud_network_ref): two VPCs sharing a CIDR are two address spaces. A
	// row with no network named (a person declared the range, or a collector
	// that cannot say) is adopted by the first network that reports it; one
	// naming ANOTHER network is never touched.
	err = w.tx.QueryRowContext(w.ctx, `
		SELECT id FROM public.prefixes
		 WHERE tenant_id = $1 AND vrf_id IS NOT DISTINCT FROM $2::uuid AND prefix = $3::cidr AND status <> 'rejected'
		   AND (cloud_network_ref IS NULL OR cloud_network_ref = coalesce($4, ''))
		 ORDER BY (coalesce(cloud_network_ref, '') = coalesce($4, '')) DESC, created_at, id
		 LIMIT 1
		 FOR UPDATE`, w.tenant, vrfArg(vrfID), p.Prefix, nilIfBlank(p.CloudNetworkRef)).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id = uuid.New()
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO public.prefixes (id, tenant_id, prefix, vrf_id, vlan_id, dhcp_managed, network_type, cloud_network_ref,
			                             source_kind, source_ref, status, first_seen_at, last_seen_at, observation_count, scope_kind, scope_id)
			VALUES ($1, $2, $3::cidr, $4, $5, $6, $7, $8, 'measured', NULLIF($9, ''), 'pending', $10, $10, 1, $11, $12::uuid)`,
			id, w.tenant, p.Prefix, vrfArg(vrfID), vlan, dhcp, nilIfBlank(p.NetworkType), nilIfBlank(p.CloudNetworkRef),
			w.src.Ref, w.at, scopeKind, scopeID); err != nil {
			return fmt.Errorf("identity/postgres: create prefix %s: %w", p.Prefix, err)
		}
		w.res.PrefixesCreated++
		post := map[string]any{"prefix": p.Prefix, "source_kind": "measured", "status": "pending"}
		if vlan != nil {
			post["vlan_id"] = fmt.Sprint(vlan)
		}
		if dhcp != nil {
			post["dhcp_managed"] = dhcp
		}
		if scopeKind != nil {
			post["scope_kind"], post["scope_id"] = scopeKind, scopeID
		}
		return w.record(dcim.ObjectKindPrefix, id, changes.ActionCreate, nil, post)
	case err != nil:
		return fmt.Errorf("identity/postgres: read prefix %s: %w", p.Prefix, err)
	}
	var (
		preVLAN, postVLAN   sql.NullString
		preDHCP, postDHCP   sql.NullBool
		preScope, postScope sql.NullString
	)
	if err := w.tx.QueryRowContext(w.ctx, `
		WITH pre AS (SELECT vlan_id::text AS vlan_id, dhcp_managed, scope_kind || ':' || scope_id::text AS scope FROM public.prefixes WHERE tenant_id = $1 AND id = $2)
		UPDATE public.prefixes t
		   SET last_seen_at = GREATEST(coalesce(t.last_seen_at, $3), $3), first_seen_at = coalesce(t.first_seen_at, $3),
		       observation_count = t.observation_count + 1,
		       vlan_id = coalesce(t.vlan_id, $4),
		       dhcp_managed = CASE WHEN t.dhcp_managed IS NULL AND t.source_kind <> 'declared' THEN $5::boolean ELSE t.dhcp_managed END,
		       network_type = coalesce(t.network_type, $6), cloud_network_ref = coalesce(t.cloud_network_ref, $7),
		       source_ref = coalesce(t.source_ref, $8),
		       scope_kind = CASE WHEN t.scope_kind IS NULL THEN $9 ELSE t.scope_kind END,
		       scope_id = CASE WHEN t.scope_kind IS NULL THEN $10::uuid ELSE t.scope_id END,
		       updated_at = now()
		  FROM pre
		 WHERE t.tenant_id = $1 AND t.id = $2
		RETURNING pre.vlan_id, pre.dhcp_managed, pre.scope, t.vlan_id::text, t.dhcp_managed, t.scope_kind || ':' || t.scope_id::text`,
		w.tenant, id, w.at, vlan, dhcp, nilIfBlank(p.NetworkType), nilIfBlank(p.CloudNetworkRef), nilIfBlank(w.src.Ref), scopeKind, scopeID).
		Scan(&preVLAN, &preDHCP, &preScope, &postVLAN, &postDHCP, &postScope); err != nil {
		return fmt.Errorf("identity/postgres: refresh prefix %s: %w", p.Prefix, err)
	}
	w.res.PrefixesUpdated++
	if preVLAN != postVLAN || preDHCP != postDHCP || preScope != postScope {
		return w.record(dcim.ObjectKindPrefix, id, changes.ActionUpdate,
			map[string]any{"vlan_id": nullableStr(preVLAN), "dhcp_managed": nullableBool(preDHCP), "scope": nullableStr(preScope)},
			map[string]any{"vlan_id": nullableStr(postVLAN), "dhcp_managed": nullableBool(postDHCP), "scope": nullableStr(postScope)})
	}
	return nil
}

// prefixScope is the observation's scope as SQL arguments, or (nil, nil) when
// it states none or names one that does not resolve for the tenant (the
// prefix is still recorded; the scope is reported as skipped).
func (w *networkWriter) prefixScope(p identity.ObservedPrefix) (any, any) {
	kind, raw := strings.TrimSpace(p.ScopeKind), strings.TrimSpace(p.ScopeID)
	if kind == "" && raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		w.skip("prefix %s: scope id %q is not a uuid", p.Prefix, raw)
		return nil, nil
	}
	if err := sites.CheckScope(w.ctx, w.tx, kind, &id); err != nil {
		if errors.Is(err, sites.ErrScope) {
			w.skip("prefix %s: %v", p.Prefix, err)
			return nil, nil
		}
		w.skip("prefix %s: scope not checked: %v", p.Prefix, err)
		return nil, nil
	}
	return kind, id.String()
}

// EnsureObservedPrefixes implements [identity.ObservedPrefixEnsurer]: each
// prefix the sighting names that is not already a row (by the same identity
// the observed-prefix writer matches on) is created `measured` and `pending`,
// with its stated DHCP posture, network type and cloud network, no VLAN link
// and no observation counted. An existing row is not touched; RecordObservedNetwork
// refreshes it once the sighting resolves to an asset. A prefix in a VRF the
// tenant has not declared is skipped, as the writer skips it.
func (r *Repository) EnsureObservedPrefixes(ctx context.Context, tenantID string, prefixes []identity.ObservedPrefix, src identity.Source) (int, error) {
	if len(prefixes) == 0 {
		return 0, nil
	}
	created := 0
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		var res identity.ObservedNetworkResult
		w := &networkWriter{ctx: ctx, tx: tx, tenant: tenantID, at: time.Now().UTC(), src: src,
			res: &res, vlans: map[int]uuid.UUID{}, vrfs: map[string]*uuid.UUID{}}
		for _, p := range prefixes {
			ok, err := w.ensurePrefix(p)
			if err != nil {
				return err
			}
			if ok {
				created++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return created, nil
}

// ensurePrefix creates p when no row holds it, reporting whether it did.
func (w *networkWriter) ensurePrefix(p identity.ObservedPrefix) (bool, error) {
	vrfID, ok, err := w.vrf(p.VRF)
	if err != nil || !ok {
		return false, err
	}
	var dhcp any
	if p.DHCPManaged != nil {
		dhcp = *p.DHCPManaged
	}
	id := uuid.New()
	res, err := w.tx.ExecContext(w.ctx, `
		INSERT INTO public.prefixes (id, tenant_id, prefix, vrf_id, dhcp_managed, network_type, cloud_network_ref,
		                             source_kind, source_ref, status, observation_count)
		SELECT $1, $2, $3::cidr, $4, $5, $6, $7, 'measured', NULLIF($8, ''), 'pending', 0
		 WHERE NOT EXISTS (
		       SELECT 1 FROM public.prefixes
		        WHERE tenant_id = $2 AND vrf_id IS NOT DISTINCT FROM $4::uuid AND prefix = $3::cidr AND status <> 'rejected'
		          AND (cloud_network_ref IS NULL OR cloud_network_ref = coalesce($7, '')))
		ON CONFLICT DO NOTHING`,
		id, w.tenant, p.Prefix, vrfArg(vrfID), dhcp, nilIfBlank(p.NetworkType), nilIfBlank(p.CloudNetworkRef), w.src.Ref)
	if err != nil {
		return false, fmt.Errorf("identity/postgres: ensure prefix %s: %w", p.Prefix, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	post := map[string]any{"prefix": p.Prefix, "source_kind": "measured", "status": "pending"}
	if dhcp != nil {
		post["dhcp_managed"] = dhcp
	}
	return true, w.record(dcim.ObjectKindPrefix, id, changes.ActionCreate, nil, post)
}

func nullableStr(v sql.NullString) any {
	if v.Valid {
		return v.String
	}
	return nil
}

func nullableBool(v sql.NullBool) any {
	if v.Valid {
		return v.Bool
	}
	return nil
}

// ----------------------------------------------------------- interfaces ----

// observedInterfaceRow is the slice of an `interfaces` row this writer reads.
type observedInterfaceRow struct {
	id                    uuid.UUID
	typ                   string
	mtu                   sql.NullInt64
	speed                 sql.NullInt64
	oper, admin, mode     sql.NullString
	untagged, parent, lag uuid.NullUUID
	mac                   sql.NullString
	status                string
	lastSeen              time.Time
}

func (w *networkWriter) loadInterfaces() (map[string]*observedInterfaceRow, error) {
	rows, err := w.tx.QueryContext(w.ctx, `
		SELECT id, name, type, mtu, speed_kbps, operational_status, admin_status, mode,
		       untagged_vlan_id, parent_id, lag_id, mac_address::text, status, last_seen_at
		  FROM public.interfaces
		 WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected'`, w.tenant, w.asset)
	if err != nil {
		return nil, fmt.Errorf("identity/postgres: read interfaces: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]*observedInterfaceRow{}
	for rows.Next() {
		var (
			r    observedInterfaceRow
			name string
		)
		if err := rows.Scan(&r.id, &name, &r.typ, &r.mtu, &r.speed, &r.oper, &r.admin, &r.mode,
			&r.untagged, &r.parent, &r.lag, &r.mac, &r.status, &r.lastSeen); err != nil {
			return nil, fmt.Errorf("identity/postgres: scan interface: %w", err)
		}
		out[name] = &r
	}
	return out, rows.Err()
}

func adminStatus(enabled *bool) any {
	if enabled == nil {
		return nil
	}
	if *enabled {
		return "up"
	}
	return "down"
}

func optInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func optInt64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// interfaces upserts every observed interface by its canonical name, then
// links what refers to other interfaces or to VLANs, then records addresses.
func (w *networkWriter) interfaces(obs []identity.ObservedInterface) error {
	if len(obs) == 0 {
		return nil
	}
	existing, err := w.loadInterfaces()
	if err != nil {
		return err
	}
	for _, o := range obs {
		if cur, ok := existing[o.Name]; ok {
			if err := w.refreshInterface(o, cur); err != nil {
				return err
			}
			continue
		}
		row, err := w.createInterface(o)
		if err != nil {
			return err
		}
		existing[o.Name] = row
	}
	for _, o := range obs {
		if err := w.linkInterface(o, existing); err != nil {
			return err
		}
	}
	for _, o := range obs {
		for _, a := range o.Addresses {
			if err := w.address(existing[o.Name].id, o.Name, a); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *networkWriter) createInterface(o identity.ObservedInterface) (*observedInterfaceRow, error) {
	id := uuid.New()
	// `enabled` is declared, but a new interface has no declaration yet: the
	// device's own admin state is the best first answer, and later
	// observations never touch it (interface_service.UpsertObserved's rule).
	enabled := o.Enabled == nil || *o.Enabled
	// The observation's own source kind: a collector's interface is measured;
	// one a person or a system of record declared (the manual, spreadsheet and
	// NetBox-import adapters, row 1.5f) is declared / imported.
	kind := sourceKindOr(w.src.Kind)
	if _, err := w.tx.ExecContext(w.ctx, `
		INSERT INTO public.interfaces (id, tenant_id, asset_id, name, type, enabled, mtu, speed_kbps,
		                               operational_status, admin_status, source_kind, source_ref, status,
		                               first_seen_at, last_seen_at, observation_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $14, NULLIF($11, ''), $12, $13, $13, 1)`,
		id, w.tenant, w.asset, o.Name, o.Type, enabled, optInt(o.MTU), optInt64(o.SpeedKbps),
		o.OperStatus, adminStatus(o.Enabled), w.src.Ref, w.status, w.at, kind); err != nil {
		return nil, fmt.Errorf("identity/postgres: create interface %q: %w", o.Name, err)
	}
	w.res.InterfacesCreated++
	post := map[string]any{"name": o.Name, "type": o.Type, "asset_id": w.asset.String(), "enabled": enabled,
		"source_kind": kind, "status": w.status}
	if o.MTU != nil {
		post["mtu"] = *o.MTU
	}
	if o.SpeedKbps != nil {
		post["speed_kbps"] = *o.SpeedKbps
	}
	if o.OperStatus != "" {
		post["operational_status"] = o.OperStatus
	}
	if a := adminStatus(o.Enabled); a != nil {
		post["admin_status"] = a
	}
	if err := w.record(dcim.ObjectKindInterface, id, changes.ActionCreate, nil, post); err != nil {
		return nil, err
	}
	return &observedInterfaceRow{id: id, typ: o.Type, status: w.status, lastSeen: w.at}, nil
}

// refreshInterface writes the measured fields of an existing interface. The
// column list IS the guard: enabled, description, label, mgmt_only and custom
// fields are not in it. observation_count moves once per observation: the
// identity half already counted an interface it filed a value under at this
// observation's time, so this counts only one it did not.
func (w *networkWriter) refreshInterface(o identity.ObservedInterface, cur *observedInterfaceRow) error {
	status := cur.status
	if status == "stale" || (status == "pending" && w.status == "active") {
		status = w.status
	}
	typ := cur.typ
	if typ == identity.SyntheticInterfaceType && o.Type != identity.SyntheticInterfaceType {
		typ = o.Type
	}
	mtu, speed := cur.mtu, cur.speed
	if o.MTU != nil {
		mtu = sql.NullInt64{Int64: int64(*o.MTU), Valid: true}
	}
	if o.SpeedKbps != nil {
		speed = sql.NullInt64{Int64: *o.SpeedKbps, Valid: true}
	}
	oper, admin := cur.oper, cur.admin
	if o.OperStatus != "" {
		oper = sql.NullString{String: o.OperStatus, Valid: true}
	}
	if a := adminStatus(o.Enabled); a != nil {
		admin = sql.NullString{String: a.(string), Valid: true}
	}
	if _, err := w.tx.ExecContext(w.ctx, `
		UPDATE public.interfaces
		   SET status = $3, type = $4, mtu = $5, speed_kbps = $6, operational_status = $7, admin_status = $8,
		       observation_count = observation_count + CASE WHEN last_seen_at >= $9 THEN 0 ELSE 1 END,
		       last_seen_at = GREATEST(last_seen_at, $9), updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`,
		w.tenant, cur.id, status, typ, mtu, speed, oper, admin, w.at); err != nil {
		return fmt.Errorf("identity/postgres: refresh interface %q: %w", o.Name, err)
	}
	pre, post := map[string]any{}, map[string]any{}
	diff := func(col string, before, after any) {
		if fmt.Sprint(before) != fmt.Sprint(after) {
			pre[col], post[col] = before, after
		}
	}
	diff("status", cur.status, status)
	diff("type", cur.typ, typ)
	diff("mtu", nullInt(cur.mtu), nullInt(mtu))
	diff("speed_kbps", nullInt(cur.speed), nullInt(speed))
	diff("operational_status", nullableStr(cur.oper), nullableStr(oper))
	diff("admin_status", nullableStr(cur.admin), nullableStr(admin))
	cur.status, cur.typ, cur.mtu, cur.speed, cur.oper, cur.admin = status, typ, mtu, speed, oper, admin
	w.res.InterfacesUpdated++
	if len(post) == 0 {
		return nil
	}
	return w.record(dcim.ObjectKindInterface, cur.id, changes.ActionUpdate, pre, post)
}

func nullInt(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}

// linkInterface fills the structural fields that are empty: parent, LAG, mode,
// untagged VLAN, the asset-held MAC; and adds tagged VLANs.
func (w *networkWriter) linkInterface(o identity.ObservedInterface, all map[string]*observedInterfaceRow) error {
	cur := all[o.Name]
	pre, post := map[string]any{}, map[string]any{}
	ref := func(name string) uuid.NullUUID {
		if r, ok := all[name]; ok && name != "" && r.id != cur.id {
			return uuid.NullUUID{UUID: r.id, Valid: true}
		}
		return uuid.NullUUID{}
	}
	parent, lag := cur.parent, cur.lag
	if !parent.Valid {
		parent = ref(o.Parent)
	}
	if !lag.Valid {
		lag = ref(o.LAG)
	}
	mode := cur.mode
	if !mode.Valid && o.Mode != "" {
		mode = sql.NullString{String: o.Mode, Valid: true}
	}
	untagged := cur.untagged
	if !untagged.Valid {
		if id, ok := w.vlans[o.UntaggedVLAN]; ok {
			untagged = uuid.NullUUID{UUID: id, Valid: true}
		}
	}
	mac := cur.mac
	if !mac.Valid && o.MAC != "" {
		held, err := w.assetHoldsMAC(o.MAC)
		if err != nil {
			return err
		}
		if col, ok := macAddr8(o.MAC); ok && held {
			mac = sql.NullString{String: col, Valid: true}
		}
	}
	setUUID := func(col string, before, after uuid.NullUUID) {
		if before != after {
			pre[col], post[col] = nullUUIDText(before), nullUUIDText(after)
		}
	}
	setUUID("parent_id", cur.parent, parent)
	setUUID("lag_id", cur.lag, lag)
	setUUID("untagged_vlan_id", cur.untagged, untagged)
	if mode != cur.mode {
		pre["mode"], post["mode"] = nullableStr(cur.mode), nullableStr(mode)
	}
	if mac != cur.mac {
		pre["mac_address"], post["mac_address"] = nullableStr(cur.mac), nullableStr(mac)
	}
	if len(post) > 0 {
		if _, err := w.tx.ExecContext(w.ctx, `
			UPDATE public.interfaces
			   SET parent_id = $3, lag_id = $4, mode = $5, untagged_vlan_id = $6, mac_address = $7::macaddr8, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2`,
			w.tenant, cur.id, parent, lag, mode, untagged, mac); err != nil {
			return fmt.Errorf("identity/postgres: link interface %q: %w", o.Name, err)
		}
		if err := w.record(dcim.ObjectKindInterface, cur.id, changes.ActionUpdate, pre, post); err != nil {
			return err
		}
		cur.parent, cur.lag, cur.mode, cur.untagged, cur.mac = parent, lag, mode, untagged, mac
	}
	for _, vid := range o.TaggedVLANs {
		vlanID, ok := w.vlans[vid]
		if !ok {
			continue
		}
		res, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO public.interface_tagged_vlans (tenant_id, interface_id, vlan_id)
			VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, w.tenant, cur.id, vlanID)
		if err != nil {
			return fmt.Errorf("identity/postgres: tag vlan %d on %q: %w", vid, o.Name, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			if err := w.record(dcim.ObjectKindInterface, cur.id, changes.ActionUpdate,
				map[string]any{}, map[string]any{"tagged_vlan_added": vlanID.String()}); err != nil {
				return err
			}
		}
	}
	return nil
}

func nullUUIDText(v uuid.NullUUID) any {
	if v.Valid {
		return v.UUID.String()
	}
	return nil
}

// assetHoldsMAC reports whether this asset already holds the MAC — as an
// identifier, or on one of its interfaces. Only such a MAC may be put on
// another of its interfaces here (a VLAN sub-interface shares its parent's).
func (w *networkWriter) assetHoldsMAC(mac string) (bool, error) {
	col, ok := macAddr8(mac)
	if !ok {
		return false, nil
	}
	var held bool
	err := w.tx.QueryRowContext(w.ctx, `
		SELECT EXISTS (SELECT 1 FROM public.asset_identifiers
		                WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'mac_address' AND value = $3)
		    OR EXISTS (SELECT 1 FROM public.interfaces
		                WHERE tenant_id = $1 AND asset_id = $2 AND mac_address = $4::macaddr8 AND status <> 'rejected')`,
		w.tenant, w.asset, mac, col).Scan(&held)
	if err != nil {
		return false, fmt.Errorf("identity/postgres: check MAC %s: %w", mac, err)
	}
	return held, nil
}

// ------------------------------------------------------------ addresses ----

// address records the posture of one observed address on its interface:
//
//   - global VRF: the identity half filed it (or withheld it — then there is
//     no row on this interface and nothing happens here). This sets the
//     length the device configured it with and the source's own
//     last_seen_source, on a row that is not declared;
//   - a named VRF: the row is found or created in that VRF and assigned to
//     the interface. Never an identity address.
func (w *networkWriter) address(ifaceID uuid.UUID, ifaceName string, a identity.ObservedAddress) error {
	host, err := netip.ParseAddr(a.Address)
	if err != nil {
		return nil
	}
	bits := a.PrefixLen
	if bits <= 0 {
		bits = host.BitLen()
	}
	if a.VRF == "" {
		// A declared row is a person's statement, and only another declaration
		// (the manual / spreadsheet adapters, row 1.5f) restates its length.
		res, err := w.tx.ExecContext(w.ctx, `
			UPDATE public.ip_addresses
			   SET address = set_masklen(address, $4::int),
			       last_seen_source = coalesce(NULLIF($5::text, ''), last_seen_source), updated_at = now()
			 WHERE tenant_id = $1 AND vrf_id IS NULL AND host = $2::inet AND assigned_kind = 'interface' AND assigned_id = $3
			   AND status <> 'rejected' AND (source_kind <> 'declared' OR $6::text = 'declared')
			   AND (masklen(address) <> $4::int OR ($5::text <> '' AND last_seen_source IS DISTINCT FROM $5::text))`,
			w.tenant, host.String(), ifaceID, bits, a.Source, sourceKindOr(w.src.Kind))
		if err != nil {
			return fmt.Errorf("identity/postgres: record address %s on %q: %w", a.Address, ifaceName, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			w.res.AddressesRecorded++
		}
		return nil
	}
	vrfID, ok, err := w.vrf(a.VRF)
	if err != nil {
		return err
	}
	if !ok {
		w.skip("address %s on %s: VRF %q is not one of the tenant's", a.Address, ifaceName, a.VRF)
		return nil
	}
	source := a.Source
	if source == "" {
		source = lastSeenSource(w.src)
	}
	cidr := netip.PrefixFrom(host, bits).String()
	var (
		id    uuid.UUID
		owner uuid.NullUUID
	)
	err = w.tx.QueryRowContext(w.ctx, `
		SELECT ip.id, ifc.asset_id
		  FROM public.ip_addresses ip
		  LEFT JOIN public.interfaces ifc
		    ON ip.assigned_kind = 'interface' AND ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
		 WHERE ip.tenant_id = $1 AND ip.vrf_id = $2 AND ip.host = $3::inet AND ip.status <> 'rejected'
		 ORDER BY (ifc.asset_id = $4) DESC NULLS LAST, ip.created_at LIMIT 1 FOR UPDATE OF ip`,
		w.tenant, *vrfID, host.String(), w.asset).Scan(&id, &owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id = uuid.New()
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO public.ip_addresses (id, tenant_id, address, vrf_id, assigned_kind, assigned_id, last_seen_source,
			                                 source_kind, source_ref, status, first_seen_at, last_seen_at, observation_count)
			VALUES ($1, $2, $3::inet, $4, 'interface', $5, $6, $10, NULLIF($7, ''), $8, $9, $9, 1)`,
			id, w.tenant, cidr, *vrfID, ifaceID, source, w.src.Ref, w.status, w.at, sourceKindOr(w.src.Kind)); err != nil {
			return fmt.Errorf("identity/postgres: create address %s in VRF %q: %w", cidr, a.VRF, err)
		}
		w.res.AddressesRecorded++
		return w.record(dcim.ObjectKindIpAddress, id, changes.ActionCreate, nil,
			map[string]any{"address": cidr, "vrf_id": vrfID.String(), "assigned_kind": "interface",
				"assigned_id": ifaceID.String(), "source_kind": sourceKindOr(w.src.Kind), "status": w.status})
	case err != nil:
		return fmt.Errorf("identity/postgres: read address %s in VRF %q: %w", a.Address, a.VRF, err)
	}
	if owner.Valid && owner.UUID != w.asset {
		w.skip("address %s on %s: VRF %q already has it on another asset", a.Address, ifaceName, a.VRF)
		return nil
	}
	if _, err := w.tx.ExecContext(w.ctx, `
		UPDATE public.ip_addresses
		   SET assigned_kind = 'interface', assigned_id = $3,
		       address = CASE WHEN source_kind = 'declared' THEN address ELSE $4::inet END,
		       last_seen_source = $5, last_seen_at = GREATEST(coalesce(last_seen_at, $6), $6),
		       first_seen_at = coalesce(first_seen_at, $6), observation_count = observation_count + 1, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`, w.tenant, id, ifaceID, cidr, source, w.at); err != nil {
		return fmt.Errorf("identity/postgres: refresh address %s in VRF %q: %w", a.Address, a.VRF, err)
	}
	w.res.AddressesRecorded++
	if !owner.Valid {
		return w.record(dcim.ObjectKindIpAddress, id, changes.ActionUpdate,
			map[string]any{"assigned_id": nil}, map[string]any{"assigned_kind": "interface", "assigned_id": ifaceID.String()})
	}
	return nil
}
