package services

// ComponentService owns the asset component tables beyond interfaces (DCIM
// BUILD_PLAN row 3.1; ADR-0010 D3/D9): console ports, console server ports,
// rear ports, front ports, device bays, power ports and power outlets.
//
// CRUD runs on the IPAM object engine over componentSpecs(): one tenant-scoped
// transaction per call, RLS in force, every write recorded in object_changes.
// InstantiateComponentTemplatesTx is the other half of ApplyDeviceType: it
// creates these kinds from the device type's templates inside the caller's
// transaction (the interface kind is InterfaceService's).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// ComponentService is the component store.
type ComponentService struct {
	db  *sql.DB
	eng *IPAMService
	// hw serves the module-bay spec (row 2.4): module bays are instantiated
	// from templates with the port kinds, but are a hardware object.
	hw *IPAMService
}

// NewComponentService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewComponentService(db *sql.DB) *ComponentService {
	return &ComponentService{db: db, eng: newObjectEngine(db, componentSpecs()), hw: newObjectEngine(db, hardwareSpecs())}
}

func (s *ComponentService) assetExists(ctx context.Context, tenant, asset uuid.UUID) error {
	return shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL)`,
			tenant, asset).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrCatalogueAssetNotFound
		}
		return nil
	})
}

// List returns one page of a component route across the tenant's assets.
func (s *ComponentService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.eng.List(ctx, tenant, route, p)
}

// ListForAsset returns one asset's components of one kind.
func (s *ComponentService) ListForAsset(ctx context.Context, tenant, asset uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	if _, err := s.eng.spec(route); err != nil {
		return nil, 0, err
	}
	if err := s.assetExists(ctx, tenant, asset); err != nil {
		return nil, 0, mapIPAMError(err, false)
	}
	f := map[string]string{}
	for k, v := range p.Filters {
		f[k] = v
	}
	f["asset_id"] = asset.String()
	p.Filters = f
	return s.eng.List(ctx, tenant, route, p)
}

// Get returns one component.
func (s *ComponentService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	return s.eng.Get(ctx, tenant, route, id)
}

// Create declares a component (the body names its asset).
func (s *ComponentService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	return s.eng.Create(ctx, tenant, route, body)
}

// CreateForAsset declares a component on the asset the path names.
func (s *ComponentService) CreateForAsset(ctx context.Context, tenant, asset uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if _, err := s.eng.spec(route); err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, ipamInvalid("body must be a JSON object")
	}
	if v, ok := m["asset_id"]; ok && fmt.Sprint(v) != asset.String() {
		return nil, ipamInvalid("asset_id does not match the asset in the path")
	}
	if err := s.assetExists(ctx, tenant, asset); err != nil {
		return nil, mapIPAMError(err, false)
	}
	m["asset_id"] = asset.String()
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return s.eng.Create(ctx, tenant, route, b)
}

// Update patches a component.
func (s *ComponentService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	return s.eng.Update(ctx, tenant, route, id, body)
}

// Delete removes a component. Deleting a rear port removes the front ports
// mapped to it (NetBox cascades); a power port's outlets are detached.
func (s *ComponentService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	return s.eng.Delete(ctx, tenant, route, id)
}

// ---------------------------------------------------------------------------
// Instantiation from a device type's templates

// ComponentKindResult is what instantiating one kind did.
type ComponentKindResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	Removed   int `json:"removed"`
	// Skipped names a template that could not be placed and why ({module}
	// names wait for a module; a name longer than 64 characters; a front port
	// whose rear port or position is unusable).
	Skipped []string `json:"skipped"`
}

// InstantiateComponentsResult is the per-kind result, keyed by component route
// segment (rear-ports, front-ports, console-ports, ...).
type InstantiateComponentsResult map[string]ComponentKindResult

// instantiateOrder: rear ports before front ports (the mapping resolves by
// rear port name), power ports before outlets (likewise). Module bays are row
// 2.4's (hardware_specs.go) and instantiate with the rest.
var instantiateOrder = []string{ComponentRearPort, ComponentFrontPort, ComponentConsolePort, ComponentConsoleServerPort,
	ComponentDeviceBay, ComponentPowerPort, ComponentPowerOutlet, HardwareModuleBay}

// removalOrder: dependants first, so a rear port is judged after its front
// ports have been.
var removalOrder = []string{ComponentFrontPort, ComponentRearPort, ComponentConsolePort, ComponentConsoleServerPort,
	ComponentDeviceBay, ComponentPowerOutlet, ComponentPowerPort, HardwareModuleBay}

// templateSource is where instantiation reads templates from: a device type
// (ApplyDeviceType) or a module type being installed into a bay (row 2.4,
// InstallModule). For a module, `{module}` in a template name is replaced by
// the bay's position (NetBox's rule) and every component placed carries the
// module's id.
type templateSource struct {
	col    string    // device_type_id | module_type_id
	id     uuid.UUID // the type
	ref    string    // source_ref of what this source declares
	module *uuid.UUID
	// position replaces `{module}`; only meaningful with module set.
	position string
}

func deviceTypeSource(deviceType uuid.UUID) templateSource {
	return templateSource{col: "device_type_id", id: deviceType, ref: DeviceTypeSourceRef(deviceType)}
}

// ModuleSourceRef is the source_ref a component a module declared carries:
// it is how removing the module recognises the rows it may delete.
func ModuleSourceRef(module uuid.UUID) string { return "module:" + module.String() }

// substitute replaces NetBox's {module} placeholder. ok is false when the name
// holds the placeholder and the source cannot fill it (a device type, or a bay
// with no position).
func (src templateSource) substitute(name string) (string, bool) {
	if !strings.Contains(name, "{module}") {
		return name, true
	}
	if src.module == nil || src.position == "" {
		return name, false
	}
	return strings.ReplaceAll(name, "{module}", src.position), true
}

// spec finds a route's spec on the component engine or (module bays) the
// hardware engine.
func (s *ComponentService) spec(route string) (*ipamSpec, error) {
	if route == HardwareModuleBay {
		return s.hw.spec(route)
	}
	return s.eng.spec(route)
}

// templateFill is the template columns copied onto a component, per kind. An
// existing component is only ever filled where its column is NULL.
var templateFill = map[string][]string{
	ComponentConsolePort:       {"type"},
	ComponentConsoleServerPort: {"type"},
	ComponentRearPort:          {"type", "color", "positions"},
	ComponentFrontPort:         {"type", "color", "rear_port_position"},
	ComponentDeviceBay:         {},
	ComponentPowerPort:         {"type", "maximum_draw", "allocated_draw"},
	ComponentPowerOutlet:       {"type", "feed_leg"},
	HardwareModuleBay:          {"position"},
}

func templateQuery(route, parentCol string) string {
	tpl := replaceDash(componentTemplateRoute[route])
	if route == HardwareModuleBay {
		tpl = "module_bay_templates"
	}
	switch route {
	case ComponentFrontPort:
		return `SELECT to_jsonb(t) || jsonb_build_object('rear_port_name', r.name) FROM ` + tpl + ` t
			LEFT JOIN rear_port_templates r ON r.id = t.rear_port_id WHERE t.` + parentCol + ` = $1 ORDER BY t.name`
	case ComponentPowerOutlet:
		return `SELECT to_jsonb(t) || jsonb_build_object('power_port_name', p.name) FROM ` + tpl + ` t
			LEFT JOIN power_port_templates p ON p.id = t.power_port_id WHERE t.` + parentCol + ` = $1 ORDER BY t.name`
	}
	return `SELECT to_jsonb(t) FROM ` + tpl + ` t WHERE t.` + parentCol + ` = $1 ORDER BY t.name`
}

func validTypeFor(route, typ string) bool {
	switch route {
	case ComponentConsolePort, ComponentConsoleServerPort:
		_, ok := dcim.ParseConsolePortType(typ)
		return ok
	case ComponentFrontPort, ComponentRearPort:
		_, ok := dcim.ParsePortType(typ)
		return ok
	case ComponentPowerPort:
		_, ok := dcim.ParsePowerPortType(typ)
		return ok
	case ComponentPowerOutlet:
		_, ok := dcim.ParsePowerOutletType(typ)
		return ok
	}
	return true
}

// InstantiateComponentTemplatesTx applies a device type's console, port, bay
// and power templates to an asset INSIDE the caller's tenant transaction (the
// catalogue service's ApplyDeviceType), recording each change.
//
// The rule, per kind, by exact name:
//
//   - No component of that name: one is created, source_kind `declared`,
//     source_ref DeviceTypeSourceRef(deviceType), status `active`. A front port
//     is mapped to the rear port the template names (and the template's
//     position); an outlet to the power port its template names.
//   - A component of that name exists: it is never duplicated and nothing a
//     person or a collector set is overwritten; the template fills only the
//     columns that are NULL (type, label, description, colour, draw, ...) and
//     a row the previous type declared is re-attributed to this one.
//
// Re-applying the same type is therefore idempotent. Changing to another type
// is additive with one removal rule: a component is deleted only when it was
// declared from a template of a DIFFERENT type, this type has no template of
// that name, nothing was ever observed on it (observation_count = 0), it has
// no cable and is not marked connected, and nothing hangs off it (a bay with
// an installed asset, a rear port with front ports, a power port with outlets
// stay). `{module}` names are left for the module path (InstallModule).
// Module bays (row 2.4) follow the same rule; a bay holding a module stays.
func (s *ComponentService) InstantiateComponentTemplatesTx(ctx context.Context, tx *sql.Tx, tenant, asset, deviceType uuid.UUID) (InstantiateComponentsResult, error) {
	src := deviceTypeSource(deviceType)
	out := InstantiateComponentsResult{}
	wanted := map[string]map[string]bool{}
	ids := map[string]map[string]uuid.UUID{} // route -> name -> id, existing and created
	for _, route := range instantiateOrder {
		res, w, err := s.instantiateKind(ctx, tx, tenant, asset, src, route, ids)
		if err != nil {
			return out, err
		}
		out[route], wanted[route] = res, w
	}
	for _, route := range removalOrder {
		res := out[route]
		n, err := s.removeStale(ctx, tx, tenant, asset, src.ref, route, wanted[route])
		if err != nil {
			return out, err
		}
		res.Removed = n
		out[route] = res
	}
	return out, nil
}

// InstantiateModuleTemplatesTx places a module type's templates on the asset
// the module is installed in (row 2.4): every port kind and nested module bay,
// names with `{module}` replaced by the bay's position, each carrying the
// module's id and source_ref ModuleSourceRef. A same-name component the asset
// already has (measured, or declared by hand or by the device type) is never
// duplicated: it is adopted into the module where it has none, and filled only
// where NULL. Additive: nothing is removed (RemoveModule is the removal path).
func (s *ComponentService) InstantiateModuleTemplatesTx(ctx context.Context, tx *sql.Tx, tenant, asset, moduleType, module uuid.UUID, position string) (InstantiateComponentsResult, error) {
	m := module
	src := templateSource{col: "module_type_id", id: moduleType, ref: ModuleSourceRef(module), module: &m, position: position}
	out := InstantiateComponentsResult{}
	ids := map[string]map[string]uuid.UUID{}
	for _, route := range instantiateOrder {
		if route == ComponentDeviceBay {
			continue // a module type has no device bay templates (NetBox)
		}
		res, _, err := s.instantiateKind(ctx, tx, tenant, asset, src, route, ids)
		if err != nil {
			return out, err
		}
		out[route] = res
	}
	return out, nil
}

func (s *ComponentService) instantiateKind(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, src templateSource, route string,
	ids map[string]map[string]uuid.UUID) (ComponentKindResult, map[string]bool, error) {
	res := ComponentKindResult{Skipped: []string{}}
	wanted := map[string]bool{}
	ref := src.ref
	sp, err := s.spec(route)
	if err != nil {
		return res, wanted, err
	}
	ids[route] = map[string]uuid.UUID{}

	// What the asset already has of this kind.
	existing := map[string]map[string]any{}
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT to_jsonb(t) FROM public.%s t
		WHERE t.tenant_id = $1 AND t.asset_id = $2 AND t.status <> 'rejected'`, sp.Table), tenant, asset)
	if err != nil {
		return res, wanted, err
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return res, wanted, err
		}
		r, err := decodeRow(sp, raw)
		if err != nil {
			_ = rows.Close()
			return res, wanted, err
		}
		existing[fmt.Sprint(r["name"])] = r
		ids[route][fmt.Sprint(r["name"])] = uuid.MustParse(fmt.Sprint(r["id"]))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return res, wanted, err
	}
	_ = rows.Close()

	// Front-port bookkeeping: positions of each rear port and the positions
	// already taken (the unique index would abort the whole apply).
	positions := map[uuid.UUID]int{}
	taken := map[string]string{} // "rearID/pos" -> front port name
	if route == ComponentFrontPort {
		for _, id := range ids[ComponentRearPort] {
			var p int
			if err := tx.QueryRowContext(ctx, `SELECT positions FROM rear_ports WHERE id = $1`, id).Scan(&p); err != nil {
				return res, wanted, err
			}
			positions[id] = p
		}
		for _, r := range existing {
			if p, ok := rowInt(r["rear_port_position"]); ok {
				taken[fmt.Sprintf("%v/%d", r["rear_port_id"], p)] = fmt.Sprint(r["name"])
			}
		}
	}

	trows, err := tx.QueryContext(ctx, templateQuery(route, src.col), src.id)
	if err != nil {
		return res, wanted, err
	}
	var tpls []map[string]any
	for trows.Next() {
		var raw []byte
		if err := trows.Scan(&raw); err != nil {
			_ = trows.Close()
			return res, wanted, err
		}
		t, err := decodeRow(sp, raw)
		if err != nil {
			_ = trows.Close()
			return res, wanted, err
		}
		tpls = append(tpls, t)
	}
	if err := trows.Err(); err != nil {
		_ = trows.Close()
		return res, wanted, err
	}
	_ = trows.Close()

	for _, t := range tpls {
		name, ok := src.substitute(fmt.Sprint(t["name"]))
		if !ok {
			if src.module == nil {
				res.Skipped = append(res.Skipped, name+": placed when a module is installed")
			} else {
				res.Skipped = append(res.Skipped, name+": the module bay has no position to replace {module} with")
			}
			continue
		}
		if len(name) > 64 {
			res.Skipped = append(res.Skipped, name+": name longer than 64 characters")
			continue
		}
		if wanted[name] {
			continue
		}
		wanted[name] = true

		// The values the template offers, with an unusable type dropped (or
		// made `other` where the column is required).
		offer := map[string]any{}
		for _, c := range []string{"label", "description"} {
			if v, ok := t[c].(string); ok && v != "" {
				offer[c] = v
			}
		}
		for _, c := range templateFill[route] {
			if t[c] != nil {
				offer[c] = t[c]
			}
		}
		if p, ok := offer["position"].(string); ok {
			if v, ok := src.substitute(p); ok {
				offer["position"] = v
			} else {
				delete(offer, "position")
			}
		}
		if typ, ok := offer["type"].(string); ok && !validTypeFor(route, typ) {
			delete(offer, "type")
		}
		if _, ok := offer["type"]; !ok && (route == ComponentFrontPort || route == ComponentRearPort) {
			offer["type"] = "other"
		}

		// References resolved by template name.
		switch route {
		case ComponentFrontPort:
			rn, _ := t["rear_port_name"].(string)
			rn, _ = src.substitute(rn)
			rid, ok := ids[ComponentRearPort][rn]
			if rn == "" || !ok {
				res.Skipped = append(res.Skipped, name+": its template names no rear port placed on this asset")
				continue
			}
			pos, _ := rowInt(t["rear_port_position"])
			if pos < 1 || pos > positions[rid] {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: position %d is outside rear port %s's %d position(s)", name, pos, rn, positions[rid]))
				continue
			}
			key := fmt.Sprintf("%s/%d", rid, pos)
			if other, busy := taken[key]; busy && other != name {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %s position %d is already used by %s", name, rn, pos, other))
				continue
			}
			taken[key] = name
			offer["rear_port_id"] = rid.String()
		case ComponentPowerOutlet:
			if pn, _ := t["power_port_name"].(string); pn != "" {
				pn, _ = src.substitute(pn)
				if pid, ok := ids[ComponentPowerPort][pn]; ok {
					offer["power_port_id"] = pid.String()
				}
			}
		}

		if cur, ok := existing[name]; ok {
			patch := map[string]any{}
			for k, v := range offer {
				// Mapping columns are structure, not defaults: never re-pointed.
				if k == "rear_port_id" || k == "rear_port_position" || k == "positions" {
					continue
				}
				if cur[k] == nil {
					patch[k] = v
				}
			}
			if k := "power_port_id"; offer[k] != nil && cur[k] == nil {
				patch[k] = offer[k]
			}
			if src.module != nil {
				// Adopted into the module where no module claims it. The
				// merge by name is the point: a measured `Gi1/1/1` and the
				// module's `Gi1/1/{module}` at position 1 are one port.
				if cur["module_id"] == nil {
					patch["module_id"] = src.module.String()
				}
			} else if sk, _ := cur["source_kind"].(string); sk == "declared" {
				if sr, ok := cur["source_ref"].(string); ok && strings.HasPrefix(sr, "device-type:") && sr != ref {
					patch["source_ref"] = ref
				}
			}
			if len(patch) == 0 {
				res.Unchanged++
				continue
			}
			if _, err := s.eng.updateTx(ctx, tx, sp, tenant, uuid.MustParse(fmt.Sprint(cur["id"])), patch, ""); err != nil {
				return res, wanted, err
			}
			res.Updated++
			continue
		}
		offer["asset_id"] = asset.String()
		offer["name"] = name
		offer["source_kind"] = "declared"
		offer["source_ref"] = ref
		offer["status"] = "active"
		if src.module != nil {
			offer["module_id"] = src.module.String()
		}
		created, err := s.eng.createTx(ctx, tx, sp, tenant, offer, "")
		if err != nil {
			return res, wanted, err
		}
		id := uuid.MustParse(fmt.Sprint(created["id"]))
		ids[route][name] = id
		res.Created++
	}
	return res, wanted, nil
}

// staleBusy is the per-kind "something hangs off it" test of the removal rule.
var staleBusy = map[string]string{
	ComponentRearPort:    `EXISTS (SELECT 1 FROM front_ports f WHERE f.rear_port_id = c.id)`,
	ComponentDeviceBay:   `c.installed_asset_id IS NOT NULL`,
	ComponentPowerPort:   `EXISTS (SELECT 1 FROM power_outlets o WHERE o.power_port_id = c.id)`,
	ComponentFrontPort:   `false`,
	ComponentConsolePort: `false`, ComponentConsoleServerPort: `false`, ComponentPowerOutlet: `false`,
	HardwareModuleBay: `EXISTS (SELECT 1 FROM modules m WHERE m.module_bay_id = c.id)`,
}

// staleCabled is the per-kind "connected" test: module bays are no cable
// termination and have neither column.
func staleCabled(route string) string {
	if route == HardwareModuleBay {
		return `true`
	}
	return `c.cable_id IS NULL AND NOT c.mark_connected`
}

func (s *ComponentService) removeStale(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, ref, route string, wanted map[string]bool) (int, error) {
	sp, err := s.spec(route)
	if err != nil {
		return 0, err
	}
	keep := []string{} // never nil: `x = ANY(NULL)` would match nothing
	for n := range wanted {
		keep = append(keep, n)
	}
	sort.Strings(keep)
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT to_jsonb(c) FROM public.%s c
		WHERE c.tenant_id = $1 AND c.asset_id = $2 AND c.status <> 'rejected'
		  AND c.source_kind = 'declared' AND c.source_ref LIKE 'device-type:%%' AND c.source_ref <> $3
		  AND NOT (c.name = ANY($4)) AND c.observation_count = 0 AND %s
		  AND NOT (%s)`, sp.Table, staleCabled(route), staleBusy[route]), tenant, asset, ref, pq.Array(keep))
	if err != nil {
		return 0, err
	}
	var stale []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return 0, err
		}
		r, err := decodeRow(sp, raw)
		if err != nil {
			_ = rows.Close()
			return 0, err
		}
		stale = append(stale, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()
	for _, pre := range stale {
		id := uuid.MustParse(fmt.Sprint(pre["id"]))
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM public.%s WHERE tenant_id = $1 AND id = $2`, sp.Table), tenant, id); err != nil {
			return 0, err
		}
		if err := recordIPAMChange(ctx, tx, sp, tenant, changes.ActionDelete, pre, nil, ""); err != nil {
			return 0, err
		}
	}
	return len(stale), nil
}
