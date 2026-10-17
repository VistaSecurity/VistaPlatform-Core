package services

// ConfigContextService owns config contexts (DCIM BUILD_PLAN row 5.3). CRUD
// runs on the IPAM object engine over configContextSpecs(): one tenant-scoped
// transaction per call, RLS in force, every write recorded in object_changes.
// Render computes an asset's merged config (config_context_render.go).

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ConfigContextService is the config-context store.
type ConfigContextService struct {
	db  *sql.DB
	eng *IPAMService
}

// NewConfigContextService returns the store over db (the raw pool; RLS is set
// per transaction).
func NewConfigContextService(db *sql.DB) *ConfigContextService {
	return &ConfigContextService{db: db, eng: newObjectEngine(db, configContextSpecs())}
}

// List returns one page of config contexts.
func (s *ConfigContextService) List(ctx context.Context, tenant uuid.UUID, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.eng.List(ctx, tenant, RouteConfigContexts, p)
}

// Get returns one config context.
func (s *ConfigContextService) Get(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error) {
	return s.eng.Get(ctx, tenant, RouteConfigContexts, id)
}

// Create creates a config context.
func (s *ConfigContextService) Create(ctx context.Context, tenant uuid.UUID, body []byte) (json.RawMessage, error) {
	return s.eng.Create(ctx, tenant, RouteConfigContexts, body)
}

// Update patches a config context.
func (s *ConfigContextService) Update(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error) {
	return s.eng.Update(ctx, tenant, RouteConfigContexts, id, body)
}

// Delete removes a config context.
func (s *ConfigContextService) Delete(ctx context.Context, tenant, id uuid.UUID) error {
	return s.eng.Delete(ctx, tenant, RouteConfigContexts, id)
}

// Render returns the asset's merged config and the contexts that produced it.
// An asset the tenant cannot see (or a deleted one) is ErrIPAMNotFound.
func (s *ConfigContextService) Render(ctx context.Context, tenant, assetID uuid.UUID) (RenderedConfigContext, error) {
	var out RenderedConfigContext
	err := s.eng.tx(ctx, tenant, func(tx *sql.Tx) error {
		facts, err := loadAssetConfigFacts(ctx, tx, tenant, assetID)
		if err != nil {
			return err
		}
		rows, err := loadActiveContexts(ctx, tx, tenant)
		if err != nil {
			return err
		}
		out = RenderConfigContexts(facts, rows)
		return nil
	})
	return out, err
}

func loadAssetConfigFacts(ctx context.Context, tx *sql.Tx, tenant, assetID uuid.UUID) (AssetConfigFacts, error) {
	var f AssetConfigFacts
	var loc, dt, dr, pl, bu sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT location_id::text, device_type_id::text, device_role_id::text, platform_id::text, business_unit_id::text
		  FROM public.assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenant, assetID).
		Scan(&loc, &dt, &dr, &pl, &bu)
	if err == sql.ErrNoRows {
		return f, ErrIPAMNotFound
	}
	if err != nil {
		return f, err
	}
	f.DeviceTypeID, f.DeviceRoleID, f.PlatformID, f.BusinessUnitID = dt.String, dr.String, pl.String, bu.String
	if loc.Valid {
		// The location and every ancestor: a context assigned to a building
		// applies to the assets in its rooms.
		rows, err := tx.QueryContext(ctx, `
			WITH RECURSIVE up AS (
				SELECT id, parent_id, 1 AS depth FROM public.locations WHERE id = $1::uuid
				UNION ALL
				SELECT l.id, l.parent_id, up.depth + 1 FROM public.locations l JOIN up ON l.id = up.parent_id WHERE up.depth < 64
			) SELECT id::text FROM up`, loc.String)
		if err != nil {
			return f, err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return f, err
			}
			f.LocationIDs = append(f.LocationIDs, id)
		}
		if err := rows.Err(); err != nil {
			return f, err
		}
	}
	trows, err := tx.QueryContext(ctx, `SELECT tag_id::text FROM public.object_tags WHERE tenant_id = $1 AND object_kind = 'asset' AND object_id = $2`, tenant, assetID)
	if err != nil {
		return f, err
	}
	defer func() { _ = trows.Close() }()
	for trows.Next() {
		var id string
		if err := trows.Scan(&id); err != nil {
			return f, err
		}
		f.TagIDs = append(f.TagIDs, id)
	}
	return f, trows.Err()
}

func loadActiveContexts(ctx context.Context, tx *sql.Tx, tenant uuid.UUID) ([]ConfigContextRow, error) {
	q := `SELECT id::text, name, weight, data::text`
	for _, d := range configDimensions {
		q += ", " + d.Column + "::text[]"
	}
	q += ` FROM public.config_contexts WHERE tenant_id = $1 AND is_active`
	rows, err := tx.QueryContext(ctx, q, tenant)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ConfigContextRow
	for rows.Next() {
		c := ConfigContextRow{IsActive: true, Assignments: map[string][]string{}}
		var data string
		arrs := make([]pq.StringArray, len(configDimensions))
		dest := []any{&c.ID, &c.Name, &c.Weight, &data}
		for i := range arrs {
			dest = append(dest, &arrs[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		c.Data = decodeContextData([]byte(data))
		for i, d := range configDimensions {
			c.Assignments[d.Column] = []string(arrs[i])
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ConfigContextObjects lists the objects the engine serves, for the contract tests.
func ConfigContextObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range configContextSpecs() {
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
