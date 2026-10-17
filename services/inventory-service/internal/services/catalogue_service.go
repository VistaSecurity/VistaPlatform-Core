package services

// CatalogueService owns the device catalogue (DCIM BUILD_PLAN row 2.2;
// ADR-0010 D4; DATA_MODEL §2): manufacturers, device types, module types,
// device roles, platforms and their component templates, plus an asset's
// catalogue columns (device_type_id, device_role_id, platform_id, serial,
// asset_tag) and template instantiation.
//
// CRUD runs on the IPAM object engine (ipam_engine.go) over catalogueSpecs():
// one tenant-scoped transaction per call, RLS in force, every write recorded in
// object_changes, platform rows (tenant_id NULL) readable and refused with
// ErrIPAMReadOnly (403) on any write.

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
)

// CatalogueService is the device catalogue store.
type CatalogueService struct {
	db     *sql.DB
	eng    *IPAMService
	ifaces *InterfaceService
	comps  *ComponentService
}

// NewCatalogueService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewCatalogueService(db *sql.DB) *CatalogueService {
	return &CatalogueService{db: db, eng: newObjectEngine(db, catalogueSpecs()), ifaces: NewInterfaceService(db), comps: NewComponentService(db)}
}

// WithInterfaceService substitutes the interface store instantiation writes
// through (tests pass one with a memory recorder).
func (s *CatalogueService) WithInterfaceService(i *InterfaceService) *CatalogueService {
	if i != nil {
		s.ifaces = i
	}
	return s
}

// List returns one page of a top-level catalogue route.
func (s *CatalogueService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	if !isCatalogueObject(route) {
		return nil, 0, fmt.Errorf("%w: unknown catalogue object %q", ErrIPAMNotFound, route)
	}
	return s.eng.List(ctx, tenant, route, p)
}

// Get returns one catalogue object.
func (s *CatalogueService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	if !isCatalogueObject(route) {
		return nil, fmt.Errorf("%w: unknown catalogue object %q", ErrIPAMNotFound, route)
	}
	return s.eng.Get(ctx, tenant, route, id)
}

// Create creates a tenant catalogue object.
func (s *CatalogueService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if !isCatalogueObject(route) {
		return nil, fmt.Errorf("%w: unknown catalogue object %q", ErrIPAMNotFound, route)
	}
	return s.eng.Create(ctx, tenant, route, body)
}

// Update patches a tenant catalogue object (a platform row answers
// ErrIPAMReadOnly).
func (s *CatalogueService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	if !isCatalogueObject(route) {
		return nil, fmt.Errorf("%w: unknown catalogue object %q", ErrIPAMNotFound, route)
	}
	return s.eng.Update(ctx, tenant, route, id, body)
}

// Delete removes a tenant catalogue object. A device type an asset uses, or a
// manufacturer a type uses, answers ErrIPAMInUse.
func (s *CatalogueService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	if !isCatalogueObject(route) {
		return fmt.Errorf("%w: unknown catalogue object %q", ErrIPAMNotFound, route)
	}
	return s.eng.Delete(ctx, tenant, route, id)
}

func isCatalogueObject(route string) bool {
	for _, r := range CatalogueObjectRoutes() {
		if r == route {
			return true
		}
	}
	return false
}

// TemplateParent names the device type or module type a nested template route
// is under.
type TemplateParent struct {
	// Kind is "device-types" or "module-types".
	Kind string
	ID   uuid.UUID
}

func (p TemplateParent) column() (string, error) {
	switch p.Kind {
	case "device-types":
		return "device_type_id", nil
	case "module-types":
		return "module_type_id", nil
	}
	return "", fmt.Errorf("%w: unknown template parent %q", ErrIPAMNotFound, p.Kind)
}

func (s *CatalogueService) templateRoute(p TemplateParent, route string) (string, error) {
	col, err := p.column()
	if err != nil {
		return "", err
	}
	allowed := DeviceTypeTemplateRoutes()
	if col == "module_type_id" {
		allowed = ModuleTypeTemplateRoutes()
	}
	for _, r := range allowed {
		if r == route {
			return col, nil
		}
	}
	return "", fmt.Errorf("%w: unknown template kind %q", ErrIPAMNotFound, route)
}

// ListTemplates lists one parent's templates of one kind.
func (s *CatalogueService) ListTemplates(ctx context.Context, tenant uuid.UUID, p TemplateParent, route string, lp IPAMListParams) ([]json.RawMessage, int, error) {
	col, err := s.templateRoute(p, route)
	if err != nil {
		return nil, 0, err
	}
	if lp.Filters == nil {
		lp.Filters = map[string]string{}
	}
	delete(lp.Filters, "device_type_id")
	delete(lp.Filters, "module_type_id")
	lp.Filters[col] = p.ID.String()
	return s.eng.List(ctx, tenant, route, lp)
}

// templateOf reads a template and checks it is under p.
func (s *CatalogueService) templateOf(ctx context.Context, tenant uuid.UUID, p TemplateParent, route string, id uuid.UUID) (json.RawMessage, error) {
	col, err := s.templateRoute(p, route)
	if err != nil {
		return nil, err
	}
	raw, err := s.eng.Get(ctx, tenant, route, id)
	if err != nil {
		return nil, err
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	if fmt.Sprint(row[col]) != p.ID.String() {
		return nil, ErrIPAMNotFound
	}
	return raw, nil
}

// GetTemplate returns one template under p.
func (s *CatalogueService) GetTemplate(ctx context.Context, tenant uuid.UUID, p TemplateParent, route string, id uuid.UUID) (json.RawMessage, error) {
	return s.templateOf(ctx, tenant, p, route, id)
}

// templateBody refuses a body that names a parent (the path does) and returns
// it with the path's parent set.
func templateBody(body []byte, col string, parent *uuid.UUID) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, ipamInvalid("body must be a JSON object")
	}
	for _, k := range []string{"device_type_id", "module_type_id"} {
		if _, ok := m[k]; ok {
			return nil, ipamInvalid("%s is set by the path, not the body", k)
		}
	}
	if parent != nil {
		m[col], _ = json.Marshal(parent.String())
	}
	return json.Marshal(m)
}

// CreateTemplate adds a template to the tenant's own device or module type.
// A platform type's templates are platform rows: ErrIPAMReadOnly.
func (s *CatalogueService) CreateTemplate(ctx context.Context, tenant uuid.UUID, p TemplateParent, route string, body []byte) (json.RawMessage, error) {
	col, err := s.templateRoute(p, route)
	if err != nil {
		return nil, err
	}
	b, err := templateBody(body, col, &p.ID)
	if err != nil {
		return nil, err
	}
	return s.eng.Create(ctx, tenant, route, b)
}

// UpdateTemplate patches a template under p.
func (s *CatalogueService) UpdateTemplate(ctx context.Context, tenant uuid.UUID, p TemplateParent, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	col, err := s.templateRoute(p, route)
	if err != nil {
		return nil, err
	}
	b, err := templateBody(body, col, nil)
	if err != nil {
		return nil, err
	}
	if _, err := s.templateOf(ctx, tenant, p, route, id); err != nil {
		return nil, err
	}
	return s.eng.Update(ctx, tenant, route, id, b)
}

// DeleteTemplate removes a template under p.
func (s *CatalogueService) DeleteTemplate(ctx context.Context, tenant uuid.UUID, p TemplateParent, route string, id uuid.UUID) error {
	if _, err := s.templateOf(ctx, tenant, p, route, id); err != nil {
		return err
	}
	return s.eng.Delete(ctx, tenant, route, id)
}

// ------------------------------------------------------- asset hardware --

// ErrCatalogueAssetNotFound is an asset the tenant does not have.
var ErrCatalogueAssetNotFound = fmt.Errorf("%w: no such asset", ErrIPAMNotFound)

// AssetHardware is an asset's catalogue view: the Hardware card.
type AssetHardware struct {
	AssetID      uuid.UUID      `json:"asset_id"`
	ClassKey     string         `json:"class_key"`
	IsHardware   bool           `json:"is_hardware"`
	DeviceType   *HardwareRef   `json:"device_type"`
	Manufacturer *HardwareRef   `json:"manufacturer"`
	DeviceRole   *HardwareRef   `json:"device_role"`
	Platform     *HardwareRef   `json:"platform"`
	Serial       *string        `json:"serial"`
	AssetTag     *string        `json:"asset_tag"`
	Templates    map[string]int `json:"template_counts"`
}

// HardwareRef is a referenced catalogue row, summarised.
type HardwareRef struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Slug       string    `json:"slug"`
	PartNumber *string   `json:"part_number,omitempty"`
	UHeight    *float64  `json:"u_height,omitempty"`
	Color      *string   `json:"color,omitempty"`
}

func isHardwarePath(path string) bool {
	return path == "hardware" || strings.HasPrefix(path, "hardware.")
}

// Hardware returns the asset's catalogue view.
func (s *CatalogueService) Hardware(ctx context.Context, tenant, asset uuid.UUID) (*AssetHardware, error) {
	var out *AssetHardware
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		out, err = hardwareTx(ctx, tx, tenant, asset)
		return err
	})
	return out, err
}

func hardwareTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (*AssetHardware, error) {
	h := &AssetHardware{AssetID: asset, Templates: map[string]int{}}
	var (
		path                          string
		dtID, mID, roleID, platID     uuid.NullUUID
		dtModel, dtSlug, dtPart       sql.NullString
		mName, mSlug                  sql.NullString
		roleName, roleSlug, roleColor sql.NullString
		platName, platSlug            sql.NullString
		uHeight                       sql.NullFloat64
		serial, tag                   sql.NullString
	)
	err := tx.QueryRowContext(ctx, `
		SELECT a.class_key, a.class_path, a.serial, a.asset_tag,
		       dt.id, dt.model, dt.slug, dt.part_number, dt.u_height::float8,
		       m.id, m.name, m.slug,
		       r.id, r.name, r.slug, r.color,
		       p.id, p.name, p.slug
		  FROM assets a
		  LEFT JOIN device_types dt ON dt.id = a.device_type_id
		  LEFT JOIN manufacturers m ON m.id = dt.manufacturer_id
		  LEFT JOIN device_roles r ON r.id = a.device_role_id
		  LEFT JOIN platforms p ON p.id = a.platform_id
		 WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL`, tenant, asset).Scan(
		&h.ClassKey, &path, &serial, &tag,
		&dtID, &dtModel, &dtSlug, &dtPart, &uHeight,
		&mID, &mName, &mSlug,
		&roleID, &roleName, &roleSlug, &roleColor,
		&platID, &platName, &platSlug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCatalogueAssetNotFound
	}
	if err != nil {
		return nil, err
	}
	h.IsHardware = isHardwarePath(path)
	h.Serial, h.AssetTag = ifaceStrPtr(serial), ifaceStrPtr(tag)
	if dtID.Valid {
		r := &HardwareRef{ID: dtID.UUID, Name: dtModel.String, Slug: dtSlug.String, PartNumber: ifaceStrPtr(dtPart)}
		if uHeight.Valid {
			u := uHeight.Float64
			r.UHeight = &u
		}
		h.DeviceType = r
		for _, route := range DeviceTypeTemplateRoutes() {
			var n int
			table := strings.ReplaceAll(route, "-", "_")
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.`+table+` WHERE device_type_id = $1`, dtID.UUID).Scan(&n); err != nil {
				return nil, err
			}
			h.Templates[route] = n
		}
	}
	if mID.Valid {
		h.Manufacturer = &HardwareRef{ID: mID.UUID, Name: mName.String, Slug: mSlug.String}
	}
	if roleID.Valid {
		h.DeviceRole = &HardwareRef{ID: roleID.UUID, Name: roleName.String, Slug: roleSlug.String, Color: ifaceStrPtr(roleColor)}
	}
	if platID.Valid {
		h.Platform = &HardwareRef{ID: platID.UUID, Name: platName.String, Slug: platSlug.String}
	}
	return h, nil
}

// HardwarePatch is a partial update of an asset's catalogue columns. A field
// absent from the body is left alone; JSON null (or "") clears it.
type HardwarePatch map[string]json.RawMessage

var hardwareFields = map[string]string{
	"device_type_id": "device_types", "device_role_id": "device_roles", "platform_id": "platforms",
	"serial": "", "asset_tag": "",
}

// UpdateHardware writes an asset's device type, device role, platform, serial
// and asset tag. Setting a device type here does NOT instantiate its templates
// (that is ApplyDeviceType, the explicit "Apply templates" action).
func (s *CatalogueService) UpdateHardware(ctx context.Context, tenant, asset uuid.UUID, patch HardwarePatch) (*AssetHardware, error) {
	sets := map[string]any{}
	for k, raw := range patch {
		table, ok := hardwareFields[k]
		if !ok {
			return nil, ipamInvalid("unknown or read-only field %q", k)
		}
		var v *string
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, ipamInvalid("%s must be a string or null", k)
		}
		if v == nil || strings.TrimSpace(*v) == "" {
			sets[k] = nil
			continue
		}
		val := strings.TrimSpace(*v)
		if table != "" {
			if _, err := uuid.Parse(val); err != nil {
				return nil, ipamInvalid("%s must be a UUID", k)
			}
		} else if len(val) > 100 {
			return nil, ipamInvalid("%s is longer than 100 characters", k)
		}
		sets[k] = val
	}
	var out *AssetHardware
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre, err := lockAssetHardware(ctx, tx, tenant, asset)
		if err != nil {
			return err
		}
		for k, v := range sets {
			if table := hardwareFields[k]; table != "" && v != nil {
				if err := visible(ctx, tx, table, v); err != nil {
					return err
				}
				if k == "device_type_id" && !isHardwarePath(pre.classPath) {
					return ipamInvalid("a device type applies to hardware-class assets only (this asset is %s)", pre.classPath)
				}
			}
		}
		if err := writeAssetHardware(ctx, tx, tenant, asset, pre, sets); err != nil {
			return err
		}
		out, err = hardwareTx(ctx, tx, tenant, asset)
		return err
	})
	return out, mapIPAMError(err, false)
}

type assetHardwareRow struct {
	classPath string
	values    map[string]any
}

func lockAssetHardware(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (assetHardwareRow, error) {
	var (
		r              = assetHardwareRow{values: map[string]any{}}
		dt, role, plat uuid.NullUUID
		serial, tag    sql.NullString
	)
	err := tx.QueryRowContext(ctx, `
		SELECT class_path, device_type_id, device_role_id, platform_id, serial, asset_tag
		  FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`, tenant, asset).Scan(
		&r.classPath, &dt, &role, &plat, &serial, &tag)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrCatalogueAssetNotFound
	}
	if err != nil {
		return r, err
	}
	str := func(u uuid.NullUUID) any {
		if !u.Valid {
			return nil
		}
		return u.UUID.String()
	}
	ns := func(s sql.NullString) any {
		if !s.Valid {
			return nil
		}
		return s.String
	}
	r.values["device_type_id"], r.values["device_role_id"], r.values["platform_id"] = str(dt), str(role), str(plat)
	r.values["serial"], r.values["asset_tag"] = ns(serial), ns(tag)
	return r, nil
}

// writeAssetHardware writes the changed columns and records ONE asset change
// with the before/after of those columns.
func writeAssetHardware(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, pre assetHardwareRow, sets map[string]any) error {
	var (
		clauses []string
		args    = []any{tenant, asset}
		before  = map[string]any{}
		after   = map[string]any{}
	)
	for _, k := range []string{"device_type_id", "device_role_id", "platform_id", "serial", "asset_tag"} {
		v, ok := sets[k]
		if !ok || fmt.Sprint(v) == fmt.Sprint(pre.values[k]) {
			continue
		}
		args = append(args, v)
		cast := ""
		if hardwareFields[k] != "" {
			cast = "::uuid"
		}
		clauses = append(clauses, fmt.Sprintf("%s = $%d%s", k, len(args), cast))
		before[k], after[k] = pre.values[k], v
	}
	if len(clauses) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET `+strings.Join(clauses, ", ")+`, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, args...); err != nil {
		return err
	}
	if err := changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: asset, Action: changes.ActionUpdate,
		Pre: before, Post: after,
	}); err != nil {
		return err
	}
	if _, typeChanged := after["device_type_id"]; typeChanged {
		// A racked asset's height and depth come from its type (row 2.3): the
		// new type must still fit and overlap nothing, under the rack's lock.
		return RevalidatePlacementTx(ctx, tx, tenant, asset)
	}
	return nil
}

// ApplyDeviceTypeResult is what assigning and applying a device type did.
type ApplyDeviceTypeResult struct {
	DeviceTypeID uuid.UUID                   `json:"device_type_id"`
	Interfaces   InstantiateInterfacesResult `json:"interfaces"`
	// Components is what each other component kind did (row 3.1), keyed by
	// route segment: rear-ports, front-ports, console-ports,
	// console-server-ports, device-bays, power-ports, power-outlets, and
	// module-bays (row 2.4).
	Components InstantiateComponentsResult `json:"components"`
	// NotInstantiated counts the type's templates of kinds no table holds
	// yet. Empty since row 2.4 placed module bays; kept for API stability.
	NotInstantiated map[string]int `json:"not_instantiated"`
	Hardware        *AssetHardware `json:"hardware"`
}

// ApplyDeviceType assigns deviceType to the asset and instantiates its
// templates, in ONE transaction: the asset column, every component created or
// filled, every removal and every change record commit or roll back together.
// The merge and removal rules are InterfaceService.InstantiateInterfaceTemplatesTx's.
// Re-applying the same type is idempotent.
func (s *CatalogueService) ApplyDeviceType(ctx context.Context, tenant, asset, deviceType uuid.UUID) (*ApplyDeviceTypeResult, error) {
	res := &ApplyDeviceTypeResult{DeviceTypeID: deviceType, NotInstantiated: map[string]int{}}
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre, err := lockAssetHardware(ctx, tx, tenant, asset)
		if err != nil {
			return err
		}
		if !isHardwarePath(pre.classPath) {
			return ipamInvalid("a device type applies to hardware-class assets only (this asset is %s)", pre.classPath)
		}
		var vendor string
		err = tx.QueryRowContext(ctx, `SELECT m.name FROM device_types dt JOIN manufacturers m ON m.id = dt.manufacturer_id
			WHERE dt.id = $1`, deviceType).Scan(&vendor)
		if errors.Is(err, sql.ErrNoRows) {
			return ipamInvalid("no such device type %s", deviceType)
		}
		if err != nil {
			return err
		}
		if err := writeAssetHardware(ctx, tx, tenant, asset, pre, map[string]any{"device_type_id": deviceType.String()}); err != nil {
			return err
		}
		tpls, err := loadInterfaceTemplates(ctx, tx, deviceType)
		if err != nil {
			return err
		}
		res.Interfaces, err = s.ifaces.InstantiateInterfaceTemplatesTx(ctx, tx, tenant, asset, deviceType, vendor, tpls)
		if err != nil {
			return err
		}
		// Row 3.1's port kinds and row 2.4's module bays.
		res.Components, err = s.comps.InstantiateComponentTemplatesTx(ctx, tx, tenant, asset, deviceType)
		if err != nil {
			return err
		}
		res.Hardware, err = hardwareTx(ctx, tx, tenant, asset)
		return err
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return res, nil
}

func loadInterfaceTemplates(ctx context.Context, tx *sql.Tx, deviceType uuid.UUID) ([]InterfaceTemplateSpec, error) {
	return loadInterfaceTemplatesBy(ctx, tx, "device_type_id", deviceType)
}
