package services

// The tenant device-type import (DCIM BUILD_PLAN row 2.2): a tenant pastes or
// uploads one or more NetBox device-type library YAML documents and each
// becomes the TENANT's own device type with its templates — for a type the
// platform seed subset lacks. The YAML is untrusted and parsed by
// shared/dcim/devicetypelib, the same parser the seed generator uses.
//
// Everything is written through the catalogue engine (createTx), so every row
// is validated, RLS-scoped and change-recorded exactly as a person's create,
// in ONE transaction for the whole request: a request that fails anywhere
// leaves nothing behind.
//
// Not done here: elevation images. The import records the library's image
// paths in external_ids.library; uploading the image files to object storage
// (shared/storage) is not wired in inventory-service yet.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim/devicetypelib"
)

// ImportedDeviceType is what one imported document did.
type ImportedDeviceType struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	// Status is `created`, or `exists` when the tenant can already see a type
	// of that manufacturer and slug or model (its own or the platform's).
	Status              string    `json:"status"`
	DeviceTypeID        uuid.UUID `json:"device_type_id"`
	ManufacturerCreated bool      `json:"manufacturer_created"`
	Templates           int       `json:"templates"`
	Warnings            []string  `json:"warnings"`
}

// ImportDeviceTypes imports library YAML (one or more documents).
func (s *CatalogueService) ImportDeviceTypes(ctx context.Context, tenant uuid.UUID, data []byte) ([]ImportedDeviceType, error) {
	docs, err := devicetypelib.Parse(data)
	if err != nil {
		if errors.Is(err, devicetypelib.ErrTooLarge) {
			return nil, ipamInvalid("%v (at most %d bytes and %d documents)", err, devicetypelib.MaxDocumentBytes, devicetypelib.MaxDocuments)
		}
		return nil, ipamInvalid("not a device-type library document: %v", err)
	}
	var out []ImportedDeviceType
	err = shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		for _, d := range docs {
			r, err := s.importOne(ctx, tx, tenant, d)
			if err != nil {
				return fmt.Errorf("%s %s: %w", d.Manufacturer, d.Model, err)
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

func (s *CatalogueService) importOne(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, d devicetypelib.DeviceType) (ImportedDeviceType, error) {
	res := ImportedDeviceType{Manufacturer: d.Manufacturer, Model: d.Model, Warnings: d.Warnings}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	mslug := devicetypelib.Slugify(d.Manufacturer)
	var mid uuid.UUID
	// The tenant's own manufacturer first, then the platform's (RLS shows only
	// those two scopes).
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM public.manufacturers WHERE slug = $1 OR lower(name) = lower($2)
		 ORDER BY tenant_id NULLS LAST LIMIT 1`, mslug, d.Manufacturer).Scan(&mid)
	if errors.Is(err, sql.ErrNoRows) {
		row, err := s.eng.createTx(ctx, tx, s.eng.specs["manufacturers"], tenant, map[string]any{
			"name": d.Manufacturer, "slug": mslug, "source_kind": "imported", "source_ref": "devicetype-library",
		}, "")
		if err != nil {
			return res, err
		}
		if mid, err = uuid.Parse(fmt.Sprint(row["id"])); err != nil {
			return res, err
		}
		res.ManufacturerCreated = true
	} else if err != nil {
		return res, err
	}

	var existing uuid.UUID
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM public.device_types WHERE manufacturer_id = $1 AND (slug = $2 OR lower(model) = lower($3))
		 ORDER BY tenant_id NULLS LAST LIMIT 1`, mid, d.Slug, d.Model).Scan(&existing)
	if err == nil {
		// Two statements, not one: a string assigned on the same line as the
		// device-type id reads as a device_type literal to the collector-vocabulary
		// scanner (shared/assetclass device_type_literals_test.go).
		res.Status = "exists"
		res.DeviceTypeID = existing
		return res, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return res, err
	}

	front, rear := d.ImagePaths()
	lib := map[string]any{"slug": d.Slug}
	if front != "" {
		lib["front_image"] = front
	}
	if rear != "" {
		lib["rear_image"] = rear
	}
	row := map[string]any{
		"manufacturer_id": mid.String(), "model": d.Model, "slug": d.Slug,
		"u_height": strconv.FormatFloat(d.UHeight, 'f', -1, 64), "is_full_depth": d.IsFullDepth,
		"exclude_from_utilization": d.ExcludeFromUtilization,
		"external_ids":             map[string]any{"library": lib},
		"source_kind":              "imported", "source_ref": "devicetype-library",
	}
	opt := func(k, v string) {
		if v != "" {
			row[k] = v
		}
	}
	opt("part_number", d.PartNumber)
	opt("subdevice_role", d.SubdeviceRole)
	opt("airflow", d.Airflow)
	opt("description", d.Description)
	opt("comments", d.Comments)
	if d.Weight != nil {
		row["weight"] = strconv.FormatFloat(*d.Weight, 'f', -1, 64)
		row["weight_unit"] = d.WeightUnit
	}
	dtRow, err := s.eng.createTx(ctx, tx, s.eng.specs["device-types"], tenant, row, "")
	if err != nil {
		return res, err
	}
	dt := fmt.Sprint(dtRow["id"])
	if res.DeviceTypeID, err = uuid.Parse(dt); err != nil {
		return res, err
	}
	res.Status = "created"

	create := func(route string, r map[string]any) (string, error) {
		r["device_type_id"] = dt
		for k, v := range r {
			if v == "" {
				delete(r, k)
			}
		}
		post, err := s.eng.createTx(ctx, tx, s.eng.specs[route], tenant, r, "")
		if err != nil {
			return "", fmt.Errorf("%s %v: %w", strings.TrimSuffix(route, "s"), r["name"], err)
		}
		res.Templates++
		return fmt.Sprint(post["id"]), nil
	}
	ifaceIDs := map[string]string{}
	for _, i := range d.Interfaces {
		id, err := create(TemplateInterface, map[string]any{"name": i.Name, "label": i.Label, "type": i.Type,
			"enabled": i.Enabled, "mgmt_only": i.MgmtOnly, "poe_mode": i.PoEMode, "poe_type": i.PoEType,
			"rf_role": i.RFRole, "description": i.Description})
		if err != nil {
			return res, err
		}
		ifaceIDs[i.Name] = id
	}
	for _, i := range d.Interfaces {
		if i.Bridge == "" {
			continue
		}
		if _, err := s.eng.updateTx(ctx, tx, s.eng.specs[TemplateInterface], tenant, uuid.MustParse(ifaceIDs[i.Name]),
			map[string]any{"bridge_id": ifaceIDs[i.Bridge]}, ""); err != nil {
			return res, err
		}
	}
	for _, p := range d.ConsolePorts {
		if _, err := create(TemplateConsolePort, map[string]any{"name": p.Name, "label": p.Label, "type": p.Type, "description": p.Description}); err != nil {
			return res, err
		}
	}
	for _, p := range d.ConsoleServerPorts {
		if _, err := create(TemplateConsoleServerPort, map[string]any{"name": p.Name, "label": p.Label, "type": p.Type, "description": p.Description}); err != nil {
			return res, err
		}
	}
	rearIDs := map[string]string{}
	for _, p := range d.RearPorts {
		id, err := create(TemplateRearPort, map[string]any{"name": p.Name, "label": p.Label, "type": p.Type, "color": p.Color,
			"positions": p.Positions, "description": p.Description})
		if err != nil {
			return res, err
		}
		rearIDs[p.Name] = id
	}
	for _, p := range d.FrontPorts {
		if _, err := create(TemplateFrontPort, map[string]any{"name": p.Name, "label": p.Label, "type": p.Type, "color": p.Color,
			"rear_port_id": rearIDs[p.RearPort], "rear_port_position": p.RearPortPosition, "description": p.Description}); err != nil {
			return res, err
		}
	}
	for _, b := range d.ModuleBays {
		if _, err := create(TemplateModuleBay, map[string]any{"name": b.Name, "label": b.Label, "position": b.Position, "description": b.Description}); err != nil {
			return res, err
		}
	}
	for _, b := range d.DeviceBays {
		if _, err := create(TemplateDeviceBay, map[string]any{"name": b.Name, "label": b.Label, "description": b.Description}); err != nil {
			return res, err
		}
	}
	powerIDs := map[string]string{}
	for _, p := range d.PowerPorts {
		r := map[string]any{"name": p.Name, "label": p.Label, "type": p.Type, "description": p.Description}
		if p.MaximumDraw != nil {
			r["maximum_draw"] = *p.MaximumDraw
		}
		if p.AllocatedDraw != nil {
			r["allocated_draw"] = *p.AllocatedDraw
		}
		id, err := create(TemplatePowerPort, r)
		if err != nil {
			return res, err
		}
		powerIDs[p.Name] = id
	}
	for _, o := range d.PowerOutlets {
		if _, err := create(TemplatePowerOutlet, map[string]any{"name": o.Name, "label": o.Label, "type": o.Type,
			"power_port_id": powerIDs[o.PowerPort], "feed_leg": o.FeedLeg, "description": o.Description}); err != nil {
			return res, err
		}
	}
	return res, nil
}
