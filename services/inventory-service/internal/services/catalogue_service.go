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
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"

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
	// The commercial lifecycle (DCIM gap 4): the asset's declared commercial
	// columns, its device type's and platform's end-of-sale / end-of-support /
	// end-of-life dates each with where it came from, and the computed block.
	Commercial    models.AssetCommercial `json:"commercial"`
	DeviceTypeEOS *CatalogueEOS          `json:"device_type_eos"`
	PlatformEOS   *CatalogueEOS          `json:"platform_eos"`
	Lifecycle     models.AssetLifecycle  `json:"lifecycle"`
}

// CatalogueEOS is a device type's or platform's three lifecycle dates. A
// declared date wins; a NULL one falls back to the linked end-of-life catalogue
// entry (end_of_support ← eol_date, end_of_life ← extended_support_date; the
// catalogue has no end-of-sale date).
type CatalogueEOS struct {
	EndOfSale    EOSDate          `json:"end_of_sale"`
	EndOfSupport EOSDate          `json:"end_of_support"`
	EndOfLife    EOSDate          `json:"end_of_life"`
	EOLCatalogue *EOLCatalogueRef `json:"eol_catalogue"`
}

// EOSDate is one lifecycle date and its source: declared, catalogue, or none
// (Date nil).
type EOSDate struct {
	Date   *string `json:"date"`
	Source string  `json:"source"`
}

// EOLCatalogueRef summarises an end-of-life catalogue entry.
type EOLCatalogueRef struct {
	ID                  uuid.UUID `json:"id"`
	ProductKind         string    `json:"product_kind"`
	Vendor              *string   `json:"vendor"`
	Product             string    `json:"product"`
	Cycle               string    `json:"cycle"`
	EOLDate             *string   `json:"eol_date"`
	ExtendedSupportDate *string   `json:"extended_support_date"`
}

func eosDate(declared, catalogue sql.NullString) EOSDate {
	switch {
	case declared.Valid:
		v := declared.String
		return EOSDate{Date: &v, Source: models.EOSSourceDecl}
	case catalogue.Valid:
		v := catalogue.String
		return EOSDate{Date: &v, Source: models.EOSSourceCat}
	}
	return EOSDate{Source: models.EOSSourceNone}
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
	if err := loadHardwareLifecycle(ctx, tx, tenant, asset, h); err != nil {
		return nil, err
	}
	return h, nil
}

// loadHardwareLifecycle fills the view's commercial columns, the device type's
// and platform's dates with their sources, and the computed lifecycle block.
func loadHardwareLifecycle(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, h *AssetHardware) error {
	var (
		c        [11]sql.NullString
		dt, pl   [3]sql.NullString // declared end_of_sale, end_of_support, end_of_life
		dtE, plE struct {
			id                    uuid.NullUUID
			kind, vendor, product sql.NullString
			cycle, eol, extended  sql.NullString
		}
		hasDT, hasPL bool
	)
	err := tx.QueryRowContext(ctx, `
		SELECT a.purchase_date::text, a.warranty_start::text, a.warranty_end::text, a.purchase_cost::text,
		       a.purchase_currency::text, a.purchase_order, a.vendor, a.support_contract,
		       a.support_contract_end::text, a.installed_at::text, a.decommissioned_at::text,
		       dt.id IS NOT NULL, dt.end_of_sale::text, dt.end_of_support::text, dt.end_of_life::text,
		       dte.id, dte.product_kind, dte.vendor, dte.product, dte.cycle, dte.eol_date::text, dte.extended_support_date::text,
		       pl.id IS NOT NULL, pl.end_of_sale::text, pl.end_of_support::text, pl.end_of_life::text,
		       ple.id, ple.product_kind, ple.vendor, ple.product, ple.cycle, ple.eol_date::text, ple.extended_support_date::text
		  FROM assets a
		  LEFT JOIN device_types dt ON dt.id = a.device_type_id
		  LEFT JOIN eol_catalogue dte ON dte.id = dt.eol_catalogue_id
		  LEFT JOIN platforms pl ON pl.id = a.platform_id
		  LEFT JOIN eol_catalogue ple ON ple.id = pl.eol_catalogue_id
		 WHERE a.tenant_id = $1 AND a.id = $2`, tenant, asset).Scan(
		&c[0], &c[1], &c[2], &c[3], &c[4], &c[5], &c[6], &c[7], &c[8], &c[9], &c[10],
		&hasDT, &dt[0], &dt[1], &dt[2],
		&dtE.id, &dtE.kind, &dtE.vendor, &dtE.product, &dtE.cycle, &dtE.eol, &dtE.extended,
		&hasPL, &pl[0], &pl[1], &pl[2],
		&plE.id, &plE.kind, &plE.vendor, &plE.product, &plE.cycle, &plE.eol, &plE.extended)
	if err != nil {
		return err
	}
	h.Commercial = models.AssetCommercial{
		PurchaseDate: ifaceStrPtr(c[0]), WarrantyStart: ifaceStrPtr(c[1]), WarrantyEnd: ifaceStrPtr(c[2]),
		PurchaseCurrency: ifaceStrPtr(c[4]), PurchaseOrder: ifaceStrPtr(c[5]), Vendor: ifaceStrPtr(c[6]),
		SupportContract: ifaceStrPtr(c[7]), SupportContractEnd: ifaceStrPtr(c[8]), InstalledAt: ifaceStrPtr(c[9]),
		DecommissionedAt: ifaceStrPtr(c[10]),
	}
	if c[3].Valid {
		if f, err := strconv.ParseFloat(c[3].String, 64); err == nil {
			h.Commercial.PurchaseCost = &f
		}
	}
	build := func(d [3]sql.NullString, id uuid.NullUUID, kind, vendor, product, cycle, eol, extended sql.NullString) *CatalogueEOS {
		out := &CatalogueEOS{
			EndOfSale:    eosDate(d[0], sql.NullString{}),
			EndOfSupport: eosDate(d[1], eol),
			EndOfLife:    eosDate(d[2], extended),
		}
		if id.Valid {
			out.EOLCatalogue = &EOLCatalogueRef{ID: id.UUID, ProductKind: kind.String, Vendor: ifaceStrPtr(vendor),
				Product: product.String, Cycle: cycle.String, EOLDate: ifaceStrPtr(eol), ExtendedSupportDate: ifaceStrPtr(extended)}
		}
		return out
	}
	in := LifecycleInputs{WarrantyEnd: parseISODate(h.Commercial.WarrantyEnd)}
	if hasDT {
		h.DeviceTypeEOS = build(dt, dtE.id, dtE.kind, dtE.vendor, dtE.product, dtE.cycle, dtE.eol, dtE.extended)
		in.DeviceType = EOSCandidate{Declared: parseISODate(ifaceStrPtr(dt[1])), Catalogue: parseISODate(ifaceStrPtr(dtE.eol))}
	}
	if hasPL {
		h.PlatformEOS = build(pl, plE.id, plE.kind, plE.vendor, plE.product, plE.cycle, plE.eol, plE.extended)
		in.Platform = EOSCandidate{Declared: parseISODate(ifaceStrPtr(pl[1])), Catalogue: parseISODate(ifaceStrPtr(plE.eol))}
	}
	h.Lifecycle = ComputeAssetLifecycle(in, lifecycleNow())
	return nil
}

// HardwarePatch is a partial update of an asset's catalogue and commercial
// columns. A field absent from the body is left alone; JSON null (or "") clears
// it.
type HardwarePatch map[string]json.RawMessage

// hwKind is how a hardware-patch field is validated and cast.
type hwKind int

const (
	hwRef       hwKind = iota // a catalogue row id
	hwShortText               // ≤ 100 characters (serial, asset tag)
	hwText                    // ≤ 200 characters
	hwDate                    // YYYY-MM-DD
	hwMoney                   // non-negative, ≤ 12 integer digits and 2 decimals; string or number
	hwCurrency                // ISO 4217: three letters, stored upper-case
)

type hwField struct {
	table string // for hwRef
	kind  hwKind
}

// hardwareFields are the columns PATCH /dcim/assets/{id}/hardware writes: the
// device catalogue (row 2.2) and the commercial lifecycle (DCIM gap 4).
var hardwareFields = map[string]hwField{
	"device_type_id": {"device_types", hwRef}, "device_role_id": {"device_roles", hwRef}, "platform_id": {"platforms", hwRef},
	"serial": {kind: hwShortText}, "asset_tag": {kind: hwShortText},
	"purchase_date": {kind: hwDate}, "warranty_start": {kind: hwDate}, "warranty_end": {kind: hwDate},
	"purchase_cost": {kind: hwMoney}, "purchase_currency": {kind: hwCurrency}, "purchase_order": {kind: hwText},
	"vendor": {kind: hwText}, "support_contract": {kind: hwText}, "support_contract_end": {kind: hwDate},
	"installed_at": {kind: hwDate}, "decommissioned_at": {kind: hwDate},
}

// hardwareFieldOrder is the write and change-record order (and the SELECT in
// lockAssetHardware).
var hardwareFieldOrder = []string{
	"device_type_id", "device_role_id", "platform_id", "serial", "asset_tag",
	"purchase_date", "warranty_start", "warranty_end", "purchase_cost", "purchase_currency", "purchase_order",
	"vendor", "support_contract", "support_contract_end", "installed_at", "decommissioned_at",
}

// CommercialFields are the eleven commercial lifecycle columns, in order.
func CommercialFields() []string { return append([]string(nil), hardwareFieldOrder[5:]...) }

var moneyPattern = regexp.MustCompile(`^[0-9]{1,12}(\.[0-9]{1,2})?$`)

// parseHardwareValue validates one patch value; nil clears.
func parseHardwareValue(k string, f hwField, raw json.RawMessage) (any, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, ipamInvalid("%s is not valid JSON", k)
	}
	var str string
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		str = strings.TrimSpace(t)
	case json.Number:
		if f.kind != hwMoney {
			return nil, ipamInvalid("%s must be a string or null", k)
		}
		str = t.String()
	default:
		if f.kind == hwMoney {
			return nil, ipamInvalid("%s must be a number, a string or null", k)
		}
		return nil, ipamInvalid("%s must be a string or null", k)
	}
	if str == "" {
		return nil, nil
	}
	switch f.kind {
	case hwRef:
		if _, err := uuid.Parse(str); err != nil {
			return nil, ipamInvalid("%s must be a UUID", k)
		}
	case hwShortText:
		if len(str) > 100 {
			return nil, ipamInvalid("%s is longer than 100 characters", k)
		}
	case hwText:
		if len(str) > 200 {
			return nil, ipamInvalid("%s is longer than 200 characters", k)
		}
	case hwDate:
		d, err := time.Parse(isoDate, str)
		if err != nil {
			return nil, ipamInvalid("%s must be a date, YYYY-MM-DD", k)
		}
		str = d.Format(isoDate)
	case hwMoney:
		if !moneyPattern.MatchString(str) {
			return nil, ipamInvalid("%s must be a non-negative amount with at most two decimals", k)
		}
		r, _ := new(big.Rat).SetString(str)
		str = r.FloatString(2)
	case hwCurrency:
		str = strings.ToUpper(str)
		if len(str) != 3 || strings.Trim(str, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return nil, ipamInvalid("%s must be a three-letter ISO 4217 code", k)
		}
	}
	return str, nil
}

// UpdateHardware writes an asset's device type, device role, platform, serial,
// asset tag and commercial lifecycle columns. Setting a device type here does
// NOT instantiate its templates (that is ApplyDeviceType, the explicit "Apply
// templates" action).
func (s *CatalogueService) UpdateHardware(ctx context.Context, tenant, asset uuid.UUID, patch HardwarePatch) (*AssetHardware, error) {
	sets := map[string]any{}
	for k, raw := range patch {
		f, ok := hardwareFields[k]
		if !ok {
			return nil, ipamInvalid("unknown or read-only field %q", k)
		}
		v, err := parseHardwareValue(k, f, raw)
		if err != nil {
			return nil, err
		}
		sets[k] = v
	}
	var out *AssetHardware
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre, err := lockAssetHardware(ctx, tx, tenant, asset)
		if err != nil {
			return err
		}
		for k, v := range sets {
			if f := hardwareFields[k]; f.kind == hwRef && v != nil {
				if err := visible(ctx, tx, f.table, v); err != nil {
					return err
				}
				if k == "device_type_id" && !isHardwarePath(pre.classPath) {
					return ipamInvalid("a device type applies to hardware-class assets only (this asset is %s)", pre.classPath)
				}
			}
		}
		if err := checkCommercialOrder(pre, sets); err != nil {
			return err
		}
		if err := writeAssetHardware(ctx, tx, tenant, asset, pre, sets); err != nil {
			return err
		}
		out, err = hardwareTx(ctx, tx, tenant, asset)
		return err
	})
	return out, mapIPAMError(err, false)
}

// checkCommercialOrder refuses a warranty that ends before it starts, or a
// decommission before the installation, on the row as it will be after the
// patch. ISO dates compare as strings.
func checkCommercialOrder(pre assetHardwareRow, sets map[string]any) error {
	val := func(k string) string {
		v, ok := sets[k]
		if !ok {
			v = pre.values[k]
		}
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	}
	for _, pair := range [][2]string{{"warranty_start", "warranty_end"}, {"installed_at", "decommissioned_at"}} {
		a, b := val(pair[0]), val(pair[1])
		if a != "" && b != "" && b < a {
			return ipamInvalid("%s (%s) is before %s (%s)", pair[1], b, pair[0], a)
		}
	}
	return nil
}

type assetHardwareRow struct {
	classPath string
	values    map[string]any
}

func lockAssetHardware(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (assetHardwareRow, error) {
	r := assetHardwareRow{values: map[string]any{}}
	cols := make([]string, len(hardwareFieldOrder))
	vals := make([]sql.NullString, len(hardwareFieldOrder))
	dest := []any{&r.classPath}
	for i, k := range hardwareFieldOrder {
		cols[i] = k + "::text"
		dest = append(dest, &vals[i])
	}
	err := tx.QueryRowContext(ctx, `SELECT class_path, `+strings.Join(cols, ", ")+`
		  FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`, tenant, asset).Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrCatalogueAssetNotFound
	}
	if err != nil {
		return r, err
	}
	for i, k := range hardwareFieldOrder {
		if vals[i].Valid {
			r.values[k] = vals[i].String
		} else {
			r.values[k] = nil
		}
	}
	return r, nil
}

func (f hwField) cast() string {
	switch f.kind {
	case hwRef:
		return "::uuid"
	case hwDate:
		return "::date"
	case hwMoney:
		return "::numeric"
	}
	return ""
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
	for _, k := range hardwareFieldOrder {
		v, ok := sets[k]
		if !ok || fmt.Sprint(v) == fmt.Sprint(pre.values[k]) {
			continue
		}
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf("%s = $%d%s", k, len(args), hardwareFields[k].cast()))
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
