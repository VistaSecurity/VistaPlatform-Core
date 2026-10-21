package services

// The device catalogue as engine specs (DCIM BUILD_PLAN row 2.2; ADR-0010 D4;
// DATA_MODEL §2): manufacturers, device types, module types, device roles,
// platforms, and the nine component-template kinds. Column names are binding —
// they are the API property names, the OpenAPI schema properties
// (catalogue_contract_test.go) and the query-language fields.
//
// Every catalogue table has tenant_id NULL rows (platform-seeded, readable by
// every tenant, changed by none: the engine's refuseCatalogueRow answers 403)
// and tenant rows. A template's tenant_id is its parent's: a platform device
// type's templates are platform rows, and a tenant may add templates only to
// its own types (prepareTemplateParent).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// The nine template kinds, by route segment, in DATA_MODEL §2's order.
const (
	TemplateInterface         = "interface-templates"
	TemplateConsolePort       = "console-port-templates"
	TemplateConsoleServerPort = "console-server-port-templates"
	TemplateFrontPort         = "front-port-templates"
	TemplateRearPort          = "rear-port-templates"
	TemplateModuleBay         = "module-bay-templates"
	TemplateDeviceBay         = "device-bay-templates"
	TemplatePowerPort         = "power-port-templates"
	TemplatePowerOutlet       = "power-outlet-templates"
)

// CatalogueObjectRoutes are the top-level catalogue routes under /dcim.
func CatalogueObjectRoutes() []string {
	return []string{"manufacturers", "device-types", "module-types", "device-roles", "platforms"}
}

// DeviceTypeTemplateRoutes are the template kinds a device type carries.
func DeviceTypeTemplateRoutes() []string {
	return []string{TemplateInterface, TemplateConsolePort, TemplateConsoleServerPort, TemplateFrontPort,
		TemplateRearPort, TemplateModuleBay, TemplateDeviceBay, TemplatePowerPort, TemplatePowerOutlet}
}

// ModuleTypeTemplateRoutes are the template kinds a module type carries
// (NetBox has no device bay on a module type).
func ModuleTypeTemplateRoutes() []string {
	return []string{TemplateInterface, TemplateConsolePort, TemplateConsoleServerPort, TemplateFrontPort,
		TemplateRearPort, TemplateModuleBay, TemplatePowerPort, TemplatePowerOutlet}
}

var airflowValues = []string{"front-to-rear", "rear-to-front", "left-to-right", "right-to-left", "side-to-rear",
	"rear-to-side", "bottom-to-top", "top-to-bottom", "passive", "mixed"}

func oneOf(row map[string]any, col string, allowed []string) error {
	v, ok := row[col].(string)
	if !ok {
		return nil
	}
	if v == "" {
		row[col] = nil
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return ipamInvalid("%s %q is not one of %s", col, v, strings.Join(allowed, ", "))
}

// prepareModelSlug derives a device/module type's slug from its model.
func prepareModelSlug(row map[string]any) error {
	if isEmpty(row["slug"]) {
		model, _ := row["model"].(string)
		row["slug"] = Slugify(model)
	}
	if isEmpty(row["slug"]) {
		return ipamInvalid("slug is required (the model has no letters or digits)")
	}
	return nil
}

func normaliseColor(row map[string]any, col string) error {
	c, ok := row[col].(string)
	if !ok {
		return nil
	}
	c = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c), "#"))
	if c == "" {
		row[col] = nil
		return nil
	}
	if len(c) != 6 || strings.Trim(c, "0123456789abcdef") != "" {
		return ipamInvalid("%s must be six hex digits", col)
	}
	row[col] = c
	return nil
}

func prepareWeight(row map[string]any) error {
	if err := oneOf(row, "airflow", airflowValues); err != nil {
		return err
	}
	return oneOf(row, "weight_unit", []string{"kg", "g", "lb", "oz"})
}

func catalogueSpecs() []*ipamSpec {
	specs := []*ipamSpec{
		{
			Kind: dcim.ObjectKindManufacturer, Table: "manufacturers", Route: "manufacturers", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindDeviceType, Table: "device_types", Route: "device-types", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "manufacturer_id", Type: colUUID, Required: true},
				ipamCol{Name: "model", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "part_number", Type: colText},
				ipamCol{Name: "u_height", Type: colNumeric},
				ipamCol{Name: "exclude_from_utilization", Type: colBool},
				ipamCol{Name: "is_full_depth", Type: colBool},
				ipamCol{Name: "subdevice_role", Type: colText},
				ipamCol{Name: "airflow", Type: colText},
				ipamCol{Name: "weight", Type: colNumeric},
				ipamCol{Name: "weight_unit", Type: colText},
				ipamCol{Name: "default_platform_id", Type: colUUID},
				ipamCol{Name: "end_of_sale", Type: colDate},
				ipamCol{Name: "end_of_support", Type: colDate},
				ipamCol{Name: "end_of_life", Type: colDate},
				ipamCol{Name: "eol_catalogue_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "manufacturer_id", Column: "manufacturer_id", Type: colUUID},
				{Param: "slug", Column: "slug", Type: colText},
				{Param: "part_number", Column: "part_number", Type: colText},
				{Param: "default_platform_id", Column: "default_platform_id", Type: colUUID},
				{Param: "scope", Custom: scopeFilter},
			},
			Search: []string{"model", "part_number", "slug", "description"},
			Order:  "lower(m.name), lower(t.model), t.id",
			// The list carries the manufacturer's name and the template counts,
			// so the catalogue browse needs no second request per row.
			ListSelect: `to_jsonb(t) || jsonb_build_object(
				'eol_link_source', ` + eolLinkSourceSQL("device_type") + `,
				'manufacturer', jsonb_build_object('id', m.id, 'name', m.name, 'slug', m.slug),
				'interface_template_count', (SELECT count(*) FROM public.interface_templates it WHERE it.device_type_id = t.id))`,
			Join:       "JOIN public.manufacturers m ON m.id = t.manufacturer_id",
			AfterWrite: matchEOLAfterWrite(eolDeviceTypes),
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := prepareModelSlug(row); err != nil {
					return err
				}
				if err := oneOf(row, "subdevice_role", []string{"parent", "child"}); err != nil {
					return err
				}
				if err := prepareWeight(row); err != nil {
					return err
				}
				if err := visible(ctx, tx, "manufacturers", row["manufacturer_id"]); err != nil {
					return err
				}
				if err := eolCatalogueOfKind(ctx, tx, row["eol_catalogue_id"], "hardware"); err != nil {
					return err
				}
				return visible(ctx, tx, "platforms", row["default_platform_id"])
			},
		},
		{
			Kind: dcim.ObjectKindModuleType, Table: "module_types", Route: "module-types", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "manufacturer_id", Type: colUUID, Required: true},
				ipamCol{Name: "model", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "part_number", Type: colText},
				ipamCol{Name: "airflow", Type: colText},
				ipamCol{Name: "weight", Type: colNumeric},
				ipamCol{Name: "weight_unit", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "manufacturer_id", Column: "manufacturer_id", Type: colUUID},
				{Param: "slug", Column: "slug", Type: colText},
				{Param: "scope", Custom: scopeFilter},
			},
			Search: []string{"model", "part_number", "slug", "description"},
			Order:  "lower(t.model), t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := prepareModelSlug(row); err != nil {
					return err
				}
				if err := prepareWeight(row); err != nil {
					return err
				}
				return visible(ctx, tx, "manufacturers", row["manufacturer_id"])
			},
		},
		{
			Kind: dcim.ObjectKindDeviceRole, Table: "device_roles", Route: "device-roles", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "color", Type: colText},
				ipamCol{Name: "vm_role", Type: colBool},
				ipamCol{Name: "parent_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "slug", Column: "slug", Type: colText},
				{Param: "vm_role", Column: "vm_role", Type: colBool},
				{Param: "parent_id", Column: "parent_id", Type: colUUID},
				{Param: "scope", Custom: scopeFilter},
			},
			Search: []string{"name", "slug", "description"},
			Order:  "lower(t.name), t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, id uuid.UUID, row map[string]any) error {
				if err := prepareSlug(ctx, tx, uuid.Nil, id, row); err != nil {
					return err
				}
				if err := normaliseColor(row, "color"); err != nil {
					return err
				}
				if row["color"] == nil {
					delete(row, "color") // NOT NULL with a default: an absent colour keeps it
				}
				if p, ok := row["parent_id"].(string); ok && id != uuid.Nil && p == id.String() {
					return ipamInvalid("a device role cannot be its own parent")
				}
				return visible(ctx, tx, "device_roles", row["parent_id"])
			},
		},
		{
			Kind: dcim.ObjectKindPlatform, Table: "platforms", Route: "platforms", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "manufacturer_id", Type: colUUID},
				ipamCol{Name: "end_of_sale", Type: colDate},
				ipamCol{Name: "end_of_support", Type: colDate},
				ipamCol{Name: "end_of_life", Type: colDate},
				ipamCol{Name: "eol_catalogue_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "slug", Column: "slug", Type: colText},
				{Param: "manufacturer_id", Column: "manufacturer_id", Type: colUUID},
				{Param: "scope", Custom: scopeFilter},
			},
			Search:     []string{"name", "slug", "description"},
			Order:      "lower(t.name), t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object('eol_link_source', ` + eolLinkSourceSQL("platform") + `)`,
			AfterWrite: matchEOLAfterWrite(eolPlatforms),
			Prepare: func(ctx context.Context, tx *sql.Tx, _, id uuid.UUID, row map[string]any) error {
				if err := prepareSlug(ctx, tx, uuid.Nil, id, row); err != nil {
					return err
				}
				if err := eolCatalogueOfKind(ctx, tx, row["eol_catalogue_id"], "os"); err != nil {
					return err
				}
				return visible(ctx, tx, "manufacturers", row["manufacturer_id"])
			},
		},
	}
	specs[0].Filters = append(specs[0].Filters, ipamFilter{Param: "scope", Custom: scopeFilter})
	return append(specs, templateSpecs()...)
}

// eolCatalogueOfKind checks a device type's or platform's eol_catalogue_id
// (DCIM gap 4): the entry exists and is of the kind the object is — a device
// type's is a `hardware` entry, a platform's an `os` entry — so a platform
// cannot fall back to a hardware model's end-of-support date.
func eolCatalogueOfKind(ctx context.Context, tx *sql.Tx, id any, kind string) error {
	if id == nil || id == "" {
		return nil
	}
	var got string
	err := tx.QueryRowContext(ctx, `SELECT product_kind FROM public.eol_catalogue WHERE id = $1::uuid`, fmt.Sprint(id)).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("no such end-of-life catalogue entry %v", id)
	}
	if err != nil {
		return mapIPAMError(err, false)
	}
	if got != kind {
		return ipamInvalid("eol_catalogue_id must be a %s entry (this one is %s)", kind, got)
	}
	return nil
}

// scopeFilter is ?scope=platform|tenant: the platform-seeded rows or the
// tenant's own.
func scopeFilter(v string, _ int) (string, any, error) {
	switch v {
	case "platform":
		return "t.tenant_id IS NULL", nil, nil
	case "tenant":
		return "t.tenant_id IS NOT NULL", nil, nil
	}
	return "", nil, ipamInvalid("scope must be platform or tenant")
}

// templateCommon are the columns every template kind shares; the parent ids
// are written by the nested routes, never by a body (the handler sets them).
func templateCommon(kind ...ipamCol) []ipamCol {
	return append([]ipamCol{
		{Name: "device_type_id", Type: colUUID},
		{Name: "module_type_id", Type: colUUID},
		{Name: "name", Type: colText, Required: true},
		{Name: "label", Type: colText},
		{Name: "description", Type: colText},
	}, kind...)
}

func templateSpec(kind dcim.ObjectKind, route string, cols []ipamCol, prep func(ctx context.Context, tx *sql.Tx, table string, row map[string]any) error) *ipamSpec {
	table := strings.ReplaceAll(route, "-", "_")
	return &ipamSpec{
		Kind: kind, Table: table, Route: route, Catalogue: true, NoCreatedBy: true,
		Cols: cols,
		Filters: []ipamFilter{
			{Param: "device_type_id", Column: "device_type_id", Type: colUUID},
			{Param: "module_type_id", Column: "module_type_id", Type: colUUID},
			{Param: "name", Column: "name", Type: colText},
		},
		Search: []string{"name", "label", "description"},
		// Natural order (Gi1/0/2 before Gi1/0/10), as the interface list sorts.
		Order: `regexp_replace(t.name, '\d+', '#', 'g'),
			array(SELECT lpad(x[1], 12, '0') FROM regexp_matches(t.name, '(\d+)', 'g') AS x), t.name, t.id`,
		Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
			if err := prepareTemplateParent(ctx, tx, row); err != nil {
				return err
			}
			if prep != nil {
				return prep(ctx, tx, table, row)
			}
			return nil
		},
	}
}

// ErrCatalogueParentRequired is a template written without its parent.
var ErrCatalogueParentRequired = errors.New("a template belongs to exactly one device type or module type")

// prepareTemplateParent checks the template's parent is visible and is the
// tenant's own: templates of a platform-seeded type are platform rows too, and
// a tenant adds a template to a platform type by importing or copying the type,
// not by writing beside it.
func prepareTemplateParent(ctx context.Context, tx *sql.Tx, row map[string]any) error {
	dt, mt := row["device_type_id"], row["module_type_id"]
	if isEmpty(dt) == isEmpty(mt) {
		return fmt.Errorf("%w: %v", ErrIPAMInvalid, ErrCatalogueParentRequired)
	}
	table, id := "device_types", dt
	if isEmpty(dt) {
		table, id = "module_types", mt
	}
	var tenant sql.NullString
	err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT tenant_id::text FROM public.%s WHERE id = $1::uuid`, table), fmt.Sprint(id)).Scan(&tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("no such %s %v", strings.TrimSuffix(table, "s"), id)
	}
	if err != nil {
		return mapIPAMError(err, false)
	}
	if !tenant.Valid {
		return ErrIPAMReadOnly
	}
	return nil
}

// sameParent checks a reference to another template (bridge, rear port, power
// port) names one under the same parent.
func sameParent(ctx context.Context, tx *sql.Tx, table, col string, row map[string]any) error {
	ref := row[col]
	if isEmpty(ref) {
		return nil
	}
	var ok bool
	q := fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM public.%s WHERE id = $1::uuid
		AND device_type_id IS NOT DISTINCT FROM $2::uuid AND module_type_id IS NOT DISTINCT FROM $3::uuid)`, table)
	if err := tx.QueryRowContext(ctx, q, fmt.Sprint(ref), nullable(row["device_type_id"]), nullable(row["module_type_id"])).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("%s must name a template of the same device or module type", col)
	}
	return nil
}

func nullable(v any) any {
	if isEmpty(v) {
		return nil
	}
	return fmt.Sprint(v)
}

func validType(row map[string]any, col string, required bool, parse func(string) bool) error {
	v, _ := row[col].(string)
	if v == "" {
		if required {
			return ipamInvalid("%s is required", col)
		}
		row[col] = nil
		return nil
	}
	if !parse(v) {
		return ipamInvalid("%s %q is not a known type", col, v)
	}
	return nil
}

func templateSpecs() []*ipamSpec {
	consoleType := func(_ context.Context, _ *sql.Tx, _ string, row map[string]any) error {
		return validType(row, "type", false, func(s string) bool { _, ok := dcim.ParseConsolePortType(s); return ok })
	}
	return []*ipamSpec{
		templateSpec(dcim.ObjectKindInterfaceTemplate, TemplateInterface, templateCommon(
			ipamCol{Name: "type", Type: colText, Required: true},
			ipamCol{Name: "enabled", Type: colBool},
			ipamCol{Name: "mgmt_only", Type: colBool},
			ipamCol{Name: "bridge_id", Type: colUUID},
			ipamCol{Name: "poe_mode", Type: colText},
			ipamCol{Name: "poe_type", Type: colText},
			ipamCol{Name: "rf_role", Type: colText},
		), func(ctx context.Context, tx *sql.Tx, table string, row map[string]any) error {
			if err := validType(row, "type", true, func(s string) bool { _, ok := dcim.ParseInterfaceType(s); return ok }); err != nil {
				return err
			}
			if err := validType(row, "poe_mode", false, func(s string) bool { _, ok := dcim.ParsePoEMode(s); return ok }); err != nil {
				return err
			}
			if err := validType(row, "poe_type", false, func(s string) bool { _, ok := dcim.ParsePoEType(s); return ok }); err != nil {
				return err
			}
			if err := oneOf(row, "rf_role", []string{"ap", "station"}); err != nil {
				return err
			}
			return sameParent(ctx, tx, table, "bridge_id", row)
		}),
		templateSpec(dcim.ObjectKindConsolePortTemplate, TemplateConsolePort, templateCommon(
			ipamCol{Name: "type", Type: colText},
		), consoleType),
		templateSpec(dcim.ObjectKindConsoleServerPortTemplate, TemplateConsoleServerPort, templateCommon(
			ipamCol{Name: "type", Type: colText},
		), consoleType),
		templateSpec(dcim.ObjectKindFrontPortTemplate, TemplateFrontPort, templateCommon(
			ipamCol{Name: "type", Type: colText, Required: true},
			ipamCol{Name: "color", Type: colText},
			ipamCol{Name: "rear_port_id", Type: colUUID},
			ipamCol{Name: "rear_port_position", Type: colInt},
		), func(ctx context.Context, tx *sql.Tx, _ string, row map[string]any) error {
			if err := validType(row, "type", true, func(s string) bool { _, ok := dcim.ParsePortType(s); return ok }); err != nil {
				return err
			}
			if err := normaliseColor(row, "color"); err != nil {
				return err
			}
			return sameParent(ctx, tx, "rear_port_templates", "rear_port_id", row)
		}),
		templateSpec(dcim.ObjectKindRearPortTemplate, TemplateRearPort, templateCommon(
			ipamCol{Name: "type", Type: colText, Required: true},
			ipamCol{Name: "color", Type: colText},
			ipamCol{Name: "positions", Type: colInt},
		), func(_ context.Context, _ *sql.Tx, _ string, row map[string]any) error {
			if err := validType(row, "type", true, func(s string) bool { _, ok := dcim.ParsePortType(s); return ok }); err != nil {
				return err
			}
			return normaliseColor(row, "color")
		}),
		templateSpec(dcim.ObjectKindModuleBayTemplate, TemplateModuleBay, templateCommon(
			ipamCol{Name: "position", Type: colText},
		), nil),
		deviceBayTemplateSpec(),
		templateSpec(dcim.ObjectKindPowerPortTemplate, TemplatePowerPort, templateCommon(
			ipamCol{Name: "type", Type: colText},
			ipamCol{Name: "maximum_draw", Type: colInt},
			ipamCol{Name: "allocated_draw", Type: colInt},
		), func(_ context.Context, _ *sql.Tx, _ string, row map[string]any) error {
			return validType(row, "type", false, func(s string) bool { _, ok := dcim.ParsePowerPortType(s); return ok })
		}),
		templateSpec(dcim.ObjectKindPowerOutletTemplate, TemplatePowerOutlet, templateCommon(
			ipamCol{Name: "type", Type: colText},
			ipamCol{Name: "power_port_id", Type: colUUID},
			ipamCol{Name: "feed_leg", Type: colText},
		), func(ctx context.Context, tx *sql.Tx, _ string, row map[string]any) error {
			if err := validType(row, "type", false, func(s string) bool { _, ok := dcim.ParsePowerOutletType(s); return ok }); err != nil {
				return err
			}
			if err := oneOf(row, "feed_leg", []string{"A", "B", "C"}); err != nil {
				return err
			}
			return sameParent(ctx, tx, "power_port_templates", "power_port_id", row)
		}),
	}
}

// deviceBayTemplateSpec: a device bay belongs to a device type only (NetBox has
// no module_type on DeviceBayTemplate), so its table has no module_type_id.
func deviceBayTemplateSpec() *ipamSpec {
	sp := templateSpec(dcim.ObjectKindDeviceBayTemplate, TemplateDeviceBay, []ipamCol{
		{Name: "device_type_id", Type: colUUID},
		{Name: "name", Type: colText, Required: true},
		{Name: "label", Type: colText},
		{Name: "description", Type: colText},
	}, nil)
	sp.Filters = []ipamFilter{
		{Param: "device_type_id", Column: "device_type_id", Type: colUUID},
		{Param: "name", Column: "name", Type: colText},
	}
	return sp
}

// CatalogueObjects describes every catalogue object and template kind for the
// contract tests: table, vocabulary kind, writable and create-required columns.
func CatalogueObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range catalogueSpecs() {
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
