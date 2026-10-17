package services

// Inventory items, modules and stack membership from discovery (DCIM
// BUILD_PLAN row 2.4; ADR-0010 D4). The SNMP collector's entPhysicalTable and
// the Cisco collector's `show inventory` / `show switch` reach here as the
// hardware half of a sighting (shared/identity/observed_hardware.go), written
// on the identity engine's transaction once the sighting resolved to an asset —
// the tunnels' pattern (vpn_intake.go). CRUD for a person is the object engine
// (hardware_specs.go).
//
// The rules:
//
//   - An inventory item's identity is (asset, parent, name). An observation
//     that names an existing item updates it — measured columns on a measured
//     row; only the columns nobody filled on a row a person declared — and
//     counts the observation. Nothing is duplicated on the next run.
//   - An item is linked to what it IS: a module whose bay has the item's name
//     (component_kind = module), else an interface of the name the collector
//     tied it to (entAliasMappingTable) or of the item's own name — a
//     transceiver called `Te1/1/1` is that port (component_kind = interface).
//   - A module seen in a bay the asset has, of a part number a module type
//     carries, is installed (InstallModuleTx, measured) when the bay is empty;
//     a bay holding another type is never overwritten.
//   - Stack members (virtual chassis): the observed asset joins the chassis
//     at its own position; another member joins when the tenant has exactly
//     one asset with that member's serial; the rest are reported. Discovery
//     never creates member assets (that is the identity engine's decision).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// hardwareChangeSource is the object_changes source of an observed hardware
// write.
var hardwareChangeSource = changes.IntakeSource("hardware")

// ObservedHardwareResult is what one recording did, for logs and tests.
type ObservedHardwareResult struct {
	ItemsCreated, ItemsUpdated, ItemsUnchanged int
	ModulesInstalled, ModulesUpdated           int
	ChassisMembers                             int
	Skipped                                    []string
}

// ObservedHardware is a sighting's hardware half.
type ObservedHardware struct {
	Items          []identity.ObservedInventoryItem
	Modules        []identity.ObservedModule
	VirtualChassis *identity.ObservedVirtualChassis
}

// Empty reports whether there is nothing to record.
func (h ObservedHardware) Empty() bool {
	return len(h.Items) == 0 && len(h.Modules) == 0 && h.VirtualChassis == nil
}

// UpsertObservedHardware records a sighting's hardware for asset on the
// engine's transaction.
func UpsertObservedHardware(ctx context.Context, tx *sqlx.Tx, tenant, asset uuid.UUID, h ObservedHardware, src identity.Source, at time.Time) (ObservedHardwareResult, error) {
	return upsertObservedHardwareTx(ctx, tx.Tx, tenant, asset, h, src, at)
}

func upsertObservedHardwareTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, h ObservedHardware, src identity.Source, at time.Time) (ObservedHardwareResult, error) {
	var res ObservedHardwareResult
	items, modules, vc, dropped := identity.NormalizeObservedHardware(h.Items, h.Modules, h.VirtualChassis)
	res.Skipped = append(res.Skipped, dropped...)
	if len(items) == 0 && len(modules) == 0 && vc == nil {
		return res, nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ref := strings.TrimSpace(src.Ref)
	if ref == "" {
		ref = "intake:hardware"
	}
	ctx = changes.WithSource(ctx, hardwareChangeSource)
	w := &hardwareWriter{ctx: ctx, tx: tx, hw: NewHardwareService(nil), tenant: tenant, asset: asset, at: at.UTC(), ref: ref, res: &res}
	var st sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, asset).Scan(&st); err != nil {
		return res, err
	}
	w.status = "pending"
	if st.String == "monitoring" {
		w.status = "active"
	}
	// Modules first: an item named after a bay then links to the module in it.
	for _, m := range modules {
		if err := w.module(m); err != nil {
			return res, fmt.Errorf("module in bay %q: %w", m.Bay, err)
		}
	}
	ids := map[string]uuid.UUID{}
	for _, it := range orderItems(items) {
		if err := w.item(it, ids); err != nil {
			return res, fmt.Errorf("inventory item %q: %w", it.Name, err)
		}
	}
	if vc != nil {
		if err := w.chassis(*vc); err != nil {
			return res, fmt.Errorf("virtual chassis: %w", err)
		}
	}
	return res, nil
}

// orderItems puts every parent before its children (a parent the batch does
// not list was dropped to the top level by normalisation).
func orderItems(items []identity.ObservedInventoryItem) []identity.ObservedInventoryItem {
	var out []identity.ObservedInventoryItem
	placed := map[string]bool{}
	pending := items
	for len(pending) > 0 {
		var next []identity.ObservedInventoryItem
		for _, it := range pending {
			if it.Parent == "" || placed[it.Parent] {
				out = append(out, it)
				placed[it.Name] = true
				continue
			}
			next = append(next, it)
		}
		if len(next) == len(pending) { // a cycle: place the rest at the top
			for _, it := range next {
				it.Parent = ""
				out = append(out, it)
			}
			break
		}
		pending = next
	}
	return out
}

type hardwareWriter struct {
	ctx    context.Context
	tx     *sql.Tx
	hw     *HardwareService
	tenant uuid.UUID
	asset  uuid.UUID
	at     time.Time
	ref    string
	status string
	res    *ObservedHardwareResult
}

func (w *hardwareWriter) spec(route string) *ipamSpec {
	sp, _ := w.hw.eng.spec(route)
	return sp
}

// lookupID runs a query returning one id, uuid.Nil when none.
func (w *hardwareWriter) lookupID(q string, args ...any) (uuid.UUID, error) {
	var id uuid.UUID
	err := w.tx.QueryRowContext(w.ctx, q, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// observed counts one observation of a row the writer touched.
func (w *hardwareWriter) observed(table string, id uuid.UUID, created bool) error {
	q := `UPDATE public.` + table + ` SET last_seen_at = GREATEST(last_seen_at, $3), observation_count = observation_count + 1 WHERE tenant_id = $1 AND id = $2`
	if created {
		q = `UPDATE public.` + table + ` SET first_seen_at = $3, last_seen_at = $3, observation_count = 1 WHERE tenant_id = $1 AND id = $2`
	}
	_, err := w.tx.ExecContext(w.ctx, q, w.tenant, id, w.at)
	return err
}

func (w *hardwareWriter) module(m identity.ObservedModule) error {
	bay, err := w.lookupID(`SELECT id FROM module_bays WHERE tenant_id = $1 AND asset_id = $2 AND name = $3 AND status <> 'rejected'`,
		w.tenant, w.asset, m.Bay)
	if err != nil {
		return err
	}
	if bay == uuid.Nil {
		w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("module %s: the asset has no module bay %q (apply its device type)", m.PartID, m.Bay))
		return nil
	}
	typ, err := w.lookupID(`SELECT id FROM module_types
		WHERE (tenant_id = $1 OR tenant_id IS NULL) AND (lower(part_number) = lower($2) OR lower(model) = lower($2))
		ORDER BY tenant_id NULLS LAST, created_at LIMIT 1`, w.tenant, m.PartID)
	if err != nil {
		return err
	}
	if typ == uuid.Nil {
		w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("module %s in bay %q: no module type has that part number", m.PartID, m.Bay))
		return nil
	}
	var (
		cur     uuid.UUID
		curType uuid.UUID
		curSK   string
		serial  sql.NullString
	)
	err = w.tx.QueryRowContext(w.ctx, `SELECT id, module_type_id, source_kind, serial FROM modules
		WHERE tenant_id = $1 AND module_bay_id = $2 AND status <> 'rejected'`, w.tenant, bay).Scan(&cur, &curType, &curSK, &serial)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		row := map[string]any{"module_bay_id": bay.String(), "module_type_id": typ.String(), "source_kind": "measured",
			"source_ref": w.ref, "status": w.status}
		if m.Serial != "" {
			row["serial"] = m.Serial
		}
		r, err := w.hw.InstallModuleTx(w.ctx, w.tx, w.tenant, &w.asset, row, "")
		if err != nil {
			return err
		}
		w.res.ModulesInstalled++
		return w.observed("modules", uuid.MustParse(fmt.Sprint(r.Module["id"])), true)
	case err != nil:
		return err
	case curType != typ:
		w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("module %s in bay %q: the bay holds a module of another type; not replaced", m.PartID, m.Bay))
		return nil
	}
	patch := map[string]any{}
	if m.Serial != "" && serial.String != m.Serial && (curSK == "measured" || !serial.Valid) {
		patch["serial"] = m.Serial
	}
	if len(patch) > 0 {
		if _, err := w.hw.eng.updateTx(w.ctx, w.tx, w.spec(HardwareModule), w.tenant, cur, patch, ""); err != nil {
			return err
		}
		w.res.ModulesUpdated++
	}
	return w.observed("modules", cur, false)
}

// itemLink is what an observed item IS: the module in the bay of its name,
// else the interface it names or is named after.
func (w *hardwareWriter) itemLink(it identity.ObservedInventoryItem) (string, uuid.UUID, error) {
	mod, err := w.lookupID(`SELECT m.id FROM modules m JOIN module_bays b ON b.id = m.module_bay_id
		WHERE b.tenant_id = $1 AND b.asset_id = $2 AND b.name = $3 AND m.status <> 'rejected' AND b.status <> 'rejected'`,
		w.tenant, w.asset, it.Name)
	if err != nil || mod != uuid.Nil {
		return "module", mod, err
	}
	for _, name := range []string{it.Interface, identity.CanonicalInterfaceName(it.Name)} {
		if name == "" {
			continue
		}
		ifc, err := w.lookupID(`SELECT id FROM interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = $3 AND status <> 'rejected'`,
			w.tenant, w.asset, name)
		if err != nil || ifc != uuid.Nil {
			return "interface", ifc, err
		}
	}
	return "", uuid.Nil, nil
}

func (w *hardwareWriter) item(it identity.ObservedInventoryItem, ids map[string]uuid.UUID) error {
	var parent any
	if it.Parent != "" {
		if p, ok := ids[it.Parent]; ok {
			parent = p
		}
	}
	role := uuid.Nil
	if it.Role != "" {
		var err error
		if role, err = w.lookupID(`SELECT id FROM inventory_item_roles WHERE (tenant_id = $1 OR tenant_id IS NULL) AND slug = $2
			ORDER BY tenant_id NULLS LAST LIMIT 1`, w.tenant, it.Role); err != nil {
			return err
		}
	}
	mfr := uuid.Nil
	if it.Manufacturer != "" {
		var err error
		if mfr, err = w.lookupID(`SELECT id FROM manufacturers WHERE (tenant_id = $1 OR tenant_id IS NULL)
			AND (lower(name) = lower($2) OR slug = $3) ORDER BY tenant_id NULLS LAST LIMIT 1`, w.tenant, it.Manufacturer, Slugify(it.Manufacturer)); err != nil {
			return err
		}
	}
	kind, comp, err := w.itemLink(it)
	if err != nil {
		return err
	}
	measured := map[string]any{"part_id": it.PartID, "serial": it.Serial, "asset_tag": it.AssetTag, "description": it.Description}
	if role != uuid.Nil {
		measured["role_id"] = role.String()
	}
	if mfr != uuid.Nil {
		measured["manufacturer_id"] = mfr.String()
	}

	cur, err := jsonRows(w.ctx, w.tx, `SELECT to_jsonb(i) FROM inventory_items i
		WHERE i.tenant_id = $1 AND i.asset_id = $2 AND COALESCE(i.parent_id, '`+zeroUUID+`'::uuid) = COALESCE($3::uuid, '`+zeroUUID+`'::uuid)
		  AND i.name = $4 AND i.status <> 'rejected'`, w.tenant, w.asset, parent, it.Name)
	if err != nil {
		return err
	}
	sp := w.spec(HardwareInventoryItem)
	if len(cur) == 0 {
		row := map[string]any{"asset_id": w.asset.String(), "name": it.Name, "discovered": true,
			"source_kind": "measured", "source_ref": w.ref, "status": w.status}
		if parent != nil {
			row["parent_id"] = fmt.Sprint(parent)
		}
		for k, v := range measured {
			if v != "" {
				row[k] = v
			}
		}
		if kind != "" {
			row["component_kind"], row["component_id"] = kind, comp.String()
		}
		created, err := w.hw.eng.createTx(w.ctx, w.tx, sp, w.tenant, row, "")
		if err != nil {
			return err
		}
		id := uuid.MustParse(fmt.Sprint(created["id"]))
		ids[it.Name] = id
		w.res.ItemsCreated++
		return w.observed("inventory_items", id, true)
	}
	row := cur[0]
	id := uuid.MustParse(fmt.Sprint(row["id"]))
	ids[it.Name] = id
	patch := map[string]any{}
	measuredRow := row["source_kind"] == "measured"
	for k, v := range measured {
		if v == "" {
			continue
		}
		// A person's value stands; a measured row takes the newer reading.
		if row[k] == nil || (measuredRow && fmt.Sprint(row[k]) != fmt.Sprint(v)) {
			patch[k] = v
		}
	}
	if row["discovered"] != true {
		patch["discovered"] = true
	}
	if kind != "" && row["component_id"] == nil {
		patch["component_kind"], patch["component_id"] = kind, comp.String()
	}
	if len(patch) == 0 {
		w.res.ItemsUnchanged++
	} else {
		if _, err := w.hw.eng.updateTx(w.ctx, w.tx, sp, w.tenant, id, patch, ""); err != nil {
			return err
		}
		w.res.ItemsUpdated++
	}
	return w.observed("inventory_items", id, false)
}

// chassis records stack membership: the observed asset at its own position,
// another member where exactly one asset of the tenant carries its serial.
func (w *hardwareWriter) chassis(vc identity.ObservedVirtualChassis) error {
	var (
		cur                   uuid.NullUUID
		serial, display, host sql.NullString
	)
	if err := w.tx.QueryRowContext(w.ctx, `SELECT virtual_chassis_id, serial, display_name, hostname FROM assets WHERE tenant_id = $1 AND id = $2`,
		w.tenant, w.asset).Scan(&cur, &serial, &display, &host); err != nil {
		return err
	}
	// Which member is this asset: its serial, else the master.
	self := -1
	for i, m := range vc.Members {
		if m.Serial != "" && strings.EqualFold(m.Serial, serial.String) {
			self = i
		}
	}
	if self < 0 {
		var err error
		if self, err = w.memberBySerialIdentifier(vc); err != nil {
			return err
		}
	}
	if self < 0 {
		for i, m := range vc.Members {
			if m.Master {
				self = i
			}
		}
	}
	if self < 0 {
		w.res.Skipped = append(w.res.Skipped, "virtual chassis: no member is this asset (no serial matched and no master reported)")
		return nil
	}
	chassis := cur.UUID
	if !cur.Valid {
		name := vc.Name
		if name == "" {
			name = firstNonEmpty(display.String, host.String, w.asset.String())
		}
		id, err := w.lookupID(`SELECT id FROM virtual_chassis WHERE tenant_id = $1 AND name = $2`, w.tenant, name)
		if err != nil {
			return err
		}
		if id == uuid.Nil {
			row := map[string]any{"name": name, "source_kind": "measured", "source_ref": w.ref}
			if vc.Domain != "" {
				row["domain"] = vc.Domain
			}
			created, err := w.hw.eng.createTx(w.ctx, w.tx, w.spec(HardwareVirtualChassis), w.tenant, row, "")
			if err != nil {
				return err
			}
			id = uuid.MustParse(fmt.Sprint(created["id"]))
		}
		chassis = id
	}
	for i, m := range vc.Members {
		member := w.asset
		if i != self {
			var err error
			if member, err = w.assetBySerial(m.Serial); err != nil {
				return err
			}
			if member == uuid.Nil {
				w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("virtual chassis member %d (serial %q): no single asset carries that serial yet", m.Position, m.Serial))
				continue
			}
		}
		var other uuid.NullUUID
		var pos, pri sql.NullInt64
		if err := w.tx.QueryRowContext(w.ctx, `SELECT virtual_chassis_id, vc_position, vc_priority FROM assets WHERE tenant_id = $1 AND id = $2`,
			w.tenant, member).Scan(&other, &pos, &pri); err != nil {
			return err
		}
		if other.Valid && other.UUID != chassis {
			w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("virtual chassis member %d: asset %s is in another virtual chassis", m.Position, member))
			continue
		}
		position := m.Position
		priority := m.Priority
		if other.Valid && pos.Valid && int(pos.Int64) == position && ((priority == nil && !pri.Valid) || (priority != nil && pri.Valid && int(pri.Int64) == *priority)) {
			w.res.ChassisMembers++
		} else {
			// The position is the member's; one another asset holds (a stale
			// member) is released first.
			if _, err := w.tx.ExecContext(w.ctx, `UPDATE assets SET vc_position = NULL WHERE tenant_id = $1 AND virtual_chassis_id = $2 AND vc_position = $3 AND id <> $4`,
				w.tenant, chassis, position, member); err != nil {
				return err
			}
			c := chassis
			if err := setMembership(w.ctx, w.tx, w.tenant, member, &c, &position, priority); err != nil {
				return err
			}
			w.res.ChassisMembers++
		}
		if m.Master {
			if _, err := w.tx.ExecContext(w.ctx, `UPDATE virtual_chassis SET master_asset_id = $3, updated_at = now()
				WHERE tenant_id = $1 AND id = $2 AND master_asset_id IS DISTINCT FROM $3`, w.tenant, chassis, member); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *hardwareWriter) memberBySerialIdentifier(vc identity.ObservedVirtualChassis) (int, error) {
	for i, m := range vc.Members {
		if m.Serial == "" {
			continue
		}
		var ok bool
		if err := w.tx.QueryRowContext(w.ctx, `SELECT EXISTS (SELECT 1 FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2
			AND kind = 'serial_number' AND upper(value) = upper($3))`, w.tenant, w.asset, m.Serial).Scan(&ok); err != nil {
			return -1, err
		}
		if ok {
			return i, nil
		}
	}
	return -1, nil
}

// assetBySerial is the one live asset of the tenant carrying serial (the
// declared column or a serial_number identifier); uuid.Nil for none or many.
func (w *hardwareWriter) assetBySerial(serial string) (uuid.UUID, error) {
	if serial == "" {
		return uuid.Nil, nil
	}
	rows, err := w.tx.QueryContext(w.ctx, `
		SELECT DISTINCT a.id FROM assets a
		 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.id <> $3
		   AND (upper(a.serial) = upper($2) OR EXISTS (SELECT 1 FROM asset_identifiers i WHERE i.tenant_id = $1 AND i.asset_id = a.id
		        AND i.kind = 'serial_number' AND upper(i.value) = upper($2)))
		 LIMIT 2`, w.tenant, serial, w.asset)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return uuid.Nil, err
		}
		ids = append(ids, id)
	}
	if len(ids) != 1 {
		return uuid.Nil, rows.Err()
	}
	return ids[0], rows.Err()
}
