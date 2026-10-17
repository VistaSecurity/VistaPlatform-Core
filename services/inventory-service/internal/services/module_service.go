package services

// HardwareService owns DCIM BUILD_PLAN row 2.4's objects (ADR-0010 D4;
// DATA_MODEL §2): module bays, modules, inventory item roles, inventory items
// and virtual chassis. CRUD runs on the IPAM object engine over
// hardwareSpecs(); this file adds what installing and removing a module means.
//
//   - Module bays are instantiated from a device type's module_bay_templates by
//     ApplyDeviceType (ComponentService.InstantiateComponentTemplatesTx), and
//     from a module type's when a module carrying nested bays is installed.
//   - InstallModule (POST /dcim/modules) puts a module of a module type into an
//     empty bay and instantiates the module type's templates onto the bay's
//     asset: interfaces, console / console server / front / rear / power ports
//     and outlets, nested module bays. NetBox's `{module}` placeholder in a
//     template name becomes the bay's position, so `Te1/{module}/1` in bay
//     position 1 is `Te1/1/1`, and the result merges by canonical name with
//     what the asset already has — a port a collector measured is adopted into
//     the module, never duplicated. Installing the same module type into the
//     same bay again is idempotent; another type is a conflict.
//   - RemoveModule (DELETE /dcim/modules/{id}) deletes only the components the
//     module declared that carry no measured data (never observed, no cable,
//     no MAC, no address, nothing hanging off them); everything else stays on
//     the asset with module_id cleared. Nested modules go first, by the same
//     rule.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// HardwareService is the row 2.4 store.
type HardwareService struct {
	db     *sql.DB
	eng    *IPAMService
	comps  *ComponentService
	ifaces *InterfaceService
}

// NewHardwareService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewHardwareService(db *sql.DB) *HardwareService {
	return &HardwareService{db: db, eng: newObjectEngine(db, hardwareSpecs()), comps: NewComponentService(db), ifaces: NewInterfaceService(db)}
}

// HardwareObjects describes every hardware object for the contract tests.
func HardwareObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range hardwareSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}

// List returns one page of a hardware route.
func (s *HardwareService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.eng.List(ctx, tenant, route, p)
}

// ListForAsset returns one asset's module bays, modules or inventory items.
func (s *HardwareService) ListForAsset(ctx context.Context, tenant, asset uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	if !hardwareAssetRoutes[route] {
		return nil, 0, fmt.Errorf("%w: unknown asset hardware %q", ErrIPAMNotFound, route)
	}
	if err := s.comps.assetExists(ctx, tenant, asset); err != nil {
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

// Get returns one hardware object.
func (s *HardwareService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	return s.eng.Get(ctx, tenant, route, id)
}

// Create creates a hardware object; a module is installed (InstallModule).
func (s *HardwareService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if route != HardwareModule {
		return s.eng.Create(ctx, tenant, route, body)
	}
	return s.installJSON(ctx, tenant, nil, body)
}

// CreateForAsset declares a module bay or inventory item on the asset the
// path names, or installs a module into one of its bays.
func (s *HardwareService) CreateForAsset(ctx context.Context, tenant, asset uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if !hardwareAssetRoutes[route] {
		return nil, fmt.Errorf("%w: unknown asset hardware %q", ErrIPAMNotFound, route)
	}
	if err := s.comps.assetExists(ctx, tenant, asset); err != nil {
		return nil, mapIPAMError(err, false)
	}
	if route == HardwareModule {
		return s.installJSON(ctx, tenant, &asset, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, ipamInvalid("body must be a JSON object")
	}
	if v, ok := m["asset_id"]; ok && fmt.Sprint(v) != asset.String() {
		return nil, ipamInvalid("asset_id does not match the asset in the path")
	}
	m["asset_id"] = asset.String()
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return s.eng.Create(ctx, tenant, route, b)
}

// Update patches a hardware object.
func (s *HardwareService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	return s.eng.Update(ctx, tenant, route, id, body)
}

// Delete removes a hardware object. Deleting a module is RemoveModule (the
// spec's BeforeDelete); deleting a virtual chassis releases its members.
func (s *HardwareService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	return s.eng.Delete(ctx, tenant, route, id)
}

// RemoveModule removes a module, keeping its measured components.
func (s *HardwareService) RemoveModule(ctx context.Context, tenant, module uuid.UUID) error {
	return s.eng.Delete(ctx, tenant, HardwareModule, module)
}

func (s *HardwareService) installJSON(ctx context.Context, tenant uuid.UUID, asset *uuid.UUID, body []byte) (json.RawMessage, error) {
	sp, err := s.eng.spec(HardwareModule)
	if err != nil {
		return nil, err
	}
	patch, err := decodeBody(sp, body)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		res, err := s.InstallModuleTx(ctx, tx, tenant, asset, patch, "")
		if err != nil {
			return err
		}
		out, err = json.Marshal(res.Module)
		return err
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

// ModuleInstallResult is what installing a module did.
type ModuleInstallResult struct {
	Module map[string]any `json:"module"`
	// AlreadyInstalled: the bay already held a module of this type; the
	// templates were re-applied (fill-only) and nothing else changed.
	AlreadyInstalled bool                        `json:"already_installed"`
	Interfaces       InstantiateInterfacesResult `json:"interfaces"`
	Components       InstantiateComponentsResult `json:"components"`
}

// InstallModule installs a module (body: module_bay_id, module_type_id and
// optionally serial, asset_tag, operational_status, description, ...) in its
// own transaction.
func (s *HardwareService) InstallModule(ctx context.Context, tenant uuid.UUID, row map[string]any) (*ModuleInstallResult, error) {
	var res *ModuleInstallResult
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		res, err = s.InstallModuleTx(ctx, tx, tenant, nil, row, "")
		return err
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return res, nil
}

// moduleTemplateTables are the template tables a module type can carry
// (device bay templates hang off device types only).
var moduleTemplateTables = []string{"interface_templates", "console_port_templates", "console_server_port_templates",
	"front_port_templates", "rear_port_templates", "module_bay_templates", "power_port_templates", "power_outlet_templates"}

// InstallModuleTx is InstallModule inside the caller's tenant transaction.
// asset, when set, is the asset the bay must belong to (the asset-scoped
// route). source overrides the change source (intake's measured install).
func (s *HardwareService) InstallModuleTx(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, asset *uuid.UUID, row map[string]any, source changes.Source) (*ModuleInstallResult, error) {
	sp, err := s.eng.spec(HardwareModule)
	if err != nil {
		return nil, err
	}
	bayID, err := uuid.Parse(fmt.Sprint(row["module_bay_id"]))
	if err != nil {
		return nil, ipamInvalid("module_bay_id must be a UUID")
	}
	typeID, err := uuid.Parse(fmt.Sprint(row["module_type_id"]))
	if err != nil {
		return nil, ipamInvalid("module_type_id must be a UUID")
	}
	var (
		bayAsset uuid.UUID
		bayName  string
		position sql.NullString
	)
	err = tx.QueryRowContext(ctx, `SELECT asset_id, name, position FROM module_bays
		WHERE tenant_id = $1 AND id = $2 AND status <> 'rejected' FOR UPDATE`, tenant, bayID).Scan(&bayAsset, &bayName, &position)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ipamInvalid("no such module bay %s", bayID)
	}
	if err != nil {
		return nil, err
	}
	if asset != nil && *asset != bayAsset {
		return nil, ipamInvalid("module bay %s is not on asset %s", bayName, *asset)
	}
	if err := visible(ctx, tx, "module_types", typeID.String()); err != nil {
		return nil, err
	}
	// NetBox refuses a placeholder it cannot fill rather than placing
	// `Te1/{module}/1` literally.
	if strings.TrimSpace(position.String) == "" {
		for _, t := range moduleTemplateTables {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.`+t+` WHERE module_type_id = $1 AND name LIKE '%{module}%'`, typeID).Scan(&n); err != nil {
				return nil, err
			}
			if n > 0 {
				return nil, ipamInvalid("module bay %s has no position, and the module type's templates name {module}; give the bay a position first", bayName)
			}
		}
	}

	res := &ModuleInstallResult{}
	var curID, curType uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT id, module_type_id FROM modules WHERE tenant_id = $1 AND module_bay_id = $2 AND status <> 'rejected'`,
		tenant, bayID).Scan(&curID, &curType)
	switch {
	case err == nil && curType != typeID:
		return nil, fmt.Errorf("%w: module bay %s already holds a module of another type; remove it first", ErrIPAMConflict, bayName)
	case err == nil:
		res.AlreadyInstalled = true
		if res.Module, err = getRow(ctx, tx, sp, curID, false); err != nil {
			return nil, err
		}
	case errors.Is(err, sql.ErrNoRows):
		if res.Module, err = s.eng.createTx(ctx, tx, sp, tenant, row, source); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	module := uuid.MustParse(fmt.Sprint(res.Module["id"]))
	pos := strings.TrimSpace(position.String)
	if res.Interfaces, err = s.instantiateModuleInterfacesTx(ctx, tx, tenant, bayAsset, typeID, module, pos, source); err != nil {
		return nil, err
	}
	if res.Components, err = s.comps.InstantiateModuleTemplatesTx(ctx, tx, tenant, bayAsset, typeID, module, pos); err != nil {
		return nil, err
	}
	return res, nil
}

// loadInterfaceTemplatesBy reads the interface templates of a device type or
// a module type (col names the parent column).
func loadInterfaceTemplatesBy(ctx context.Context, tx *sql.Tx, col string, parent uuid.UUID) ([]InterfaceTemplateSpec, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT t.name, COALESCE(t.label, ''), t.type, COALESCE(t.description, ''), t.enabled, t.mgmt_only,
		       COALESCE(t.poe_mode, ''), COALESCE(t.poe_type, ''), COALESCE(t.rf_role, ''), COALESCE(b.name, '')
		  FROM interface_templates t
		  LEFT JOIN interface_templates b ON b.id = t.bridge_id
		 WHERE t.`+col+` = $1
		 ORDER BY t.name`, parent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []InterfaceTemplateSpec
	for rows.Next() {
		var t InterfaceTemplateSpec
		if err := rows.Scan(&t.Name, &t.Label, &t.Type, &t.Description, &t.Enabled, &t.MgmtOnly,
			&t.PoEMode, &t.PoEType, &t.RFRole, &t.Bridge); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// instantiateModuleInterfacesTx places a module type's interface templates on
// the asset: `{module}` replaced by the bay position, names canonicalised with
// the asset's vendor (its device type's manufacturer, else the module type's),
// merged by canonical name with what the asset has. An existing interface is
// adopted into the module where no module claims it and filled where empty
// (InstantiateInterfaceTemplatesTx's fill: type where `other`, label, PoE);
// its measured fields are never touched.
func (s *HardwareService) instantiateModuleInterfacesTx(ctx context.Context, tx *sql.Tx, tenant, asset, moduleType, module uuid.UUID, position string, source changes.Source) (InstantiateInterfacesResult, error) {
	res := InstantiateInterfacesResult{Skipped: []string{}}
	ref := ModuleSourceRef(module)
	src := templateSource{module: &module, position: position}
	var vendor string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(
			(SELECT m.name FROM assets a JOIN device_types dt ON dt.id = a.device_type_id JOIN manufacturers m ON m.id = dt.manufacturer_id
			  WHERE a.tenant_id = $1 AND a.id = $2),
			(SELECT m.name FROM module_types mt JOIN manufacturers m ON m.id = mt.manufacturer_id WHERE mt.id = $3), '')`,
		tenant, asset, moduleType).Scan(&vendor); err != nil {
		return res, err
	}
	tpls, err := loadInterfaceTemplatesBy(ctx, tx, "module_type_id", moduleType)
	if err != nil {
		return res, err
	}
	existing := map[string]Interface{}
	rows, err := tx.QueryContext(ctx, "SELECT "+interfaceColumns+
		" FROM interfaces i WHERE i.tenant_id = $1 AND i.asset_id = $2 AND i.status <> 'rejected'", tenant, asset)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		i, err := ifaceScanInterface(rows)
		if err != nil {
			_ = rows.Close()
			return res, err
		}
		existing[i.Name] = i
	}
	_ = rows.Close()

	wanted := map[string]bool{}
	for _, t := range tpls {
		raw, ok := src.substitute(t.Name)
		if !ok {
			res.Skipped = append(res.Skipped, t.Name+": the module bay has no position to replace {module} with")
			continue
		}
		name, _ := ifnames.Canonical(vendor, raw)
		if name == "" || wanted[name] {
			continue
		}
		if len(name) > 64 {
			res.Skipped = append(res.Skipped, name+": name longer than 64 characters")
			continue
		}
		wanted[name] = true
		typ := t.Type
		if _, ok := dcim.ParseInterfaceType(typ); !ok {
			typ = "other"
		}
		t.Label, _ = src.substitute(t.Label)
		if cur, ok := existing[name]; ok {
			adopted := false
			if cur.ModuleID == nil {
				if _, err := tx.ExecContext(ctx, `UPDATE interfaces SET module_id = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
					tenant, cur.ID, module); err != nil {
					return res, err
				}
				adopted = true
			}
			filled, err := ifaceFillFromTemplate(ctx, tx, tenant, cur, typ, t, ref)
			if err != nil {
				return res, err
			}
			if !adopted && !filled {
				res.Unchanged++
				continue
			}
			after, err := ifaceGetInterfaceTx(ctx, tx, tenant, cur.ID)
			if err != nil {
				return res, err
			}
			if err := s.ifaces.record(ctx, tx, tenant, changes.ActionUpdate, cur.ID, cur, after, source); err != nil {
				return res, err
			}
			res.Updated++
			continue
		}
		id := uuid.New()
		poeMode, poeType, rfRole := t.PoEMode, t.PoEType, t.RFRole
		if _, ok := dcim.ParsePoEMode(poeMode); !ok {
			poeMode = ""
		}
		if _, ok := dcim.ParsePoEType(poeType); !ok {
			poeType = ""
		}
		if !strings.HasPrefix(typ, "ieee802.11") {
			rfRole = ""
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO interfaces (id, tenant_id, asset_id, module_id, name, label, type, enabled, mgmt_only,
				poe_mode, poe_type, rf_role, description, source_kind, source_ref, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'declared',$14,'active')`,
			id, tenant, asset, module, name, ifaceEmptyNil(t.Label), typ, t.Enabled, t.MgmtOnly,
			ifaceEmptyNil(poeMode), ifaceEmptyNil(poeType), ifaceEmptyNil(rfRole), ifaceEmptyNil(t.Description), ref); err != nil {
			return res, err
		}
		after, err := ifaceGetInterfaceTx(ctx, tx, tenant, id)
		if err != nil {
			return res, err
		}
		if err := s.ifaces.record(ctx, tx, tenant, changes.ActionCreate, id, nil, after, source); err != nil {
			return res, err
		}
		res.Created++
	}
	return res, nil
}

// moduleComponentTables are the tables a module's components live in, in the
// order removal judges them: dependants first (front ports before the rear
// ports they map to, outlets before the power ports that feed them), module
// bays last (a nested module has gone by then).
var moduleComponentTables = []string{"interfaces", "front_ports", "rear_ports", "console_ports", "console_server_ports",
	"power_outlets", "power_ports", "device_bays", "module_bays"}

// moduleRemovalKeep is, per table, what makes a module-declared component
// carry data the removal must not destroy.
var moduleRemovalKeep = map[string]string{
	"interfaces": `c.cable_id IS NOT NULL OR c.mark_connected OR c.mac_address IS NOT NULL
		OR EXISTS (SELECT 1 FROM mac_addresses m WHERE m.interface_id = c.id)
		OR EXISTS (SELECT 1 FROM ip_addresses ip WHERE ip.tenant_id = c.tenant_id AND ip.assigned_kind = 'interface' AND ip.assigned_id = c.id)
		OR EXISTS (SELECT 1 FROM interfaces o WHERE o.lag_id = c.id OR o.parent_id = c.id OR o.bridge_id = c.id)`,
	"front_ports":          `c.cable_id IS NOT NULL OR c.mark_connected`,
	"rear_ports":           `c.cable_id IS NOT NULL OR c.mark_connected OR EXISTS (SELECT 1 FROM front_ports f WHERE f.rear_port_id = c.id)`,
	"console_ports":        `c.cable_id IS NOT NULL OR c.mark_connected`,
	"console_server_ports": `c.cable_id IS NOT NULL OR c.mark_connected`,
	"power_outlets":        `c.cable_id IS NOT NULL OR c.mark_connected`,
	"power_ports":          `c.cable_id IS NOT NULL OR c.mark_connected OR EXISTS (SELECT 1 FROM power_outlets o WHERE o.power_port_id = c.id)`,
	"device_bays":          `c.cable_id IS NOT NULL OR c.mark_connected OR c.installed_asset_id IS NOT NULL`,
	"module_bays":          `EXISTS (SELECT 1 FROM modules m WHERE m.module_bay_id = c.id)`,
}

// beforeModuleDelete is the modules spec's BeforeDelete: RemoveModule's rule.
func beforeModuleDelete(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre map[string]any) error {
	id, err := uuid.Parse(fmt.Sprint(pre["id"]))
	if err != nil {
		return err
	}
	return releaseModuleTx(ctx, tx, tenant, id)
}

// releaseModuleTx empties a module before it is deleted: nested modules are
// removed (by this same rule), the components the module declared and nothing
// measured are deleted, and every other component keeps living on the asset
// with module_id cleared, so the FK's CASCADE finds nothing left to take.
func releaseModuleTx(ctx context.Context, tx *sql.Tx, tenant, module uuid.UUID) error {
	nested, err := jsonRows(ctx, tx, `SELECT to_jsonb(m) FROM modules m JOIN module_bays b ON b.id = m.module_bay_id
		WHERE m.tenant_id = $1 AND b.module_id = $2`, tenant, module)
	if err != nil {
		return err
	}
	for _, n := range nested {
		nid := uuid.MustParse(fmt.Sprint(n["id"]))
		if err := releaseModuleTx(ctx, tx, tenant, nid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM modules WHERE tenant_id = $1 AND id = $2`, tenant, nid); err != nil {
			return err
		}
		if err := recordRowChange(ctx, tx, tenant, dcim.ObjectKindModule, changes.ActionDelete, n, nil); err != nil {
			return err
		}
	}
	ref := ModuleSourceRef(module)
	for _, table := range moduleComponentTables {
		kind := dcim.ObjectKind(strings.TrimSuffix(table, "s"))
		gone, err := jsonRows(ctx, tx, fmt.Sprintf(`SELECT to_jsonb(c) FROM public.%s c
			WHERE c.tenant_id = $1 AND c.module_id = $2 AND c.source_kind = 'declared' AND c.source_ref = $3
			  AND c.observation_count = 0 AND NOT (%s)`, table, moduleRemovalKeep[table]), tenant, module, ref)
		if err != nil {
			return err
		}
		for _, r := range gone {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM public.%s WHERE tenant_id = $1 AND id = $2::uuid`, table), tenant, fmt.Sprint(r["id"])); err != nil {
				return err
			}
			if err := recordRowChange(ctx, tx, tenant, kind, changes.ActionDelete, r, nil); err != nil {
				return err
			}
		}
		kept, err := jsonRows(ctx, tx, fmt.Sprintf(`SELECT to_jsonb(c) FROM public.%s c WHERE c.tenant_id = $1 AND c.module_id = $2`, table), tenant, module)
		if err != nil {
			return err
		}
		for _, r := range kept {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE public.%s SET module_id = NULL, updated_at = now() WHERE tenant_id = $1 AND id = $2::uuid`, table),
				tenant, fmt.Sprint(r["id"])); err != nil {
				return err
			}
			post := map[string]any{}
			for k, v := range r {
				post[k] = v
			}
			post["module_id"] = nil
			if err := recordRowChange(ctx, tx, tenant, kind, changes.ActionUpdate, r, post); err != nil {
				return err
			}
		}
	}
	return nil
}

// jsonRows reads every `to_jsonb` row a query returns.
func jsonRows(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]map[string]any, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m map[string]any
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// recordRowChange records one change of a row read as JSON.
func recordRowChange(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, kind dcim.ObjectKind, action changes.Action, pre, post map[string]any) error {
	row := post
	if row == nil {
		row = pre
	}
	id, err := uuid.Parse(fmt.Sprint(row["id"]))
	if err != nil {
		return fmt.Errorf("hardware: row has no id: %w", err)
	}
	c := changes.Change{TenantID: tenant, Kind: kind, ID: id, Action: action}
	if pre != nil {
		c.Pre = pre
	}
	if post != nil {
		c.Post = post
	}
	return changes.InTx(tx).Record(ctx, c)
}

// ---------------------------------------------------------------------------
// Device bays (row 3.1's table): installing a child asset

// syncDeviceBayChild is the device-bays spec's AfterWrite: a bay's
// installed_asset_id and the child's own parent_asset_id / device_bay_id
// (row 2.3's columns) are one fact, kept in step on every write. Installing
// sets the child's pair to (the bay's asset, the bay); emptying, re-pointing or
// deleting the bay clears the previous child's. A child occupies no rack units
// (row 2.3's elevation skips it), so a RACKED asset is refused: unplace it
// first.
func syncDeviceBayChild(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	val := func(m map[string]any, k string) string {
		if m == nil || m[k] == nil {
			return ""
		}
		return fmt.Sprint(m[k])
	}
	oldChild, newChild := val(pre, "installed_asset_id"), val(post, "installed_asset_id")
	if oldChild == newChild {
		return nil
	}
	row := post
	if row == nil {
		row = pre
	}
	bay, parent := fmt.Sprint(row["id"]), fmt.Sprint(row["asset_id"])
	if oldChild != "" {
		if err := setAssetBay(ctx, tx, tenant, oldChild, nil, nil,
			`parent_asset_id = $5::uuid AND (device_bay_id IS NULL OR device_bay_id = $6::uuid)`, parent, bay); err != nil {
			return err
		}
	}
	if newChild == "" {
		return nil
	}
	var racked bool
	if err := tx.QueryRowContext(ctx, `SELECT position IS NOT NULL FROM assets WHERE tenant_id = $1 AND id = $2::uuid`, tenant, newChild).Scan(&racked); err != nil {
		return mapIPAMError(err, false)
	}
	if racked {
		return ipamInvalid("asset %s is placed in a rack; unplace it before installing it in a device bay", newChild)
	}
	return setAssetBay(ctx, tx, tenant, newChild, &parent, &bay, `true`)
}

// setAssetBay writes an asset's parent_asset_id / device_bay_id pair where
// cond holds, recording the change when a row changed.
func setAssetBay(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, asset string, parent, bay *string, cond string, condArgs ...any) error {
	var preParent, preBay sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT parent_asset_id::text, device_bay_id::text FROM assets WHERE tenant_id = $1 AND id = $2::uuid FOR UPDATE`,
		tenant, asset).Scan(&preParent, &preBay)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	// $3 parent, $4 bay; the condition's own arguments are $5 onwards.
	args := append([]any{tenant, asset, optText(parent), optText(bay)}, condArgs...)
	res, err := tx.ExecContext(ctx, `UPDATE assets SET parent_asset_id = $3::uuid, device_bay_id = $4::uuid, updated_at = now()
		WHERE tenant_id = $1 AND id = $2::uuid AND (`+cond+`)`, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	id := uuid.MustParse(asset)
	return changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: id, Action: changes.ActionUpdate,
		Pre:  map[string]any{"parent_asset_id": nullStringValue(preParent), "device_bay_id": nullStringValue(preBay)},
		Post: map[string]any{"parent_asset_id": optText(parent), "device_bay_id": optText(bay)},
	})
}

func optText(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullStringValue(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}
