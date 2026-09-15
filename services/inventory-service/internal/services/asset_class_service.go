// Package services: the class taxonomy as a read surface (ADR-0002 D2).
package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// AssetClass is one node of the taxonomy as the API returns it.
//
// The platform hierarchy comes from the GENERATED registry (`shared/assetclass`,
// built from `standards/asset-classes.yaml`) rather than from `asset_classes`.
// Both carry it — the table is seeded from the same generator — but reading the
// registry means the API and the identification engine cannot answer differently
// about what a class IS, and a class missing from a database because seeding was
// skipped cannot make the picker silently short.
//
// Tenant leaf subclasses are the part only the table knows, so they are read
// from it and merged in.
type AssetClass struct {
	Key                  string          `json:"key"`
	Parent               string          `json:"parent,omitempty"`
	Path                 string          `json:"path"`
	Label                string          `json:"label"`
	Description          string          `json:"description,omitempty"`
	Icon                 string          `json:"icon,omitempty"`
	CMDBCIType           string          `json:"cmdb_ci_type,omitempty"`
	CycloneDXType        string          `json:"cyclonedx_type,omitempty"`
	IdentifierPrecedence []string        `json:"identifier_precedence"`
	AttributeSchema      json.RawMessage `json:"attribute_schema,omitempty"`
	// IsFixed distinguishes a platform class from a tenant subclass. A tenant
	// may not edit a fixed class, and the picker says which is which rather
	// than presenting one flat list a user cannot reason about.
	IsFixed bool `json:"is_fixed"`
}

// AssetClassService reads the taxonomy.
type AssetClassService struct {
	db *database.DB
}

// NewAssetClassService constructs the service.
func NewAssetClassService(db *database.DB) *AssetClassService {
	return &AssetClassService{db: db}
}

// List returns the platform hierarchy plus this tenant's own leaf subclasses,
// parents always before children so a client can build the tree in one pass.
func (s *AssetClassService) List(ctx context.Context, tenantID uuid.UUID) ([]AssetClass, error) {
	out := make([]AssetClass, 0, len(assetclass.All))
	for _, c := range assetclass.All {
		entry := AssetClass{
			Key:                  string(c.Key),
			Parent:               string(c.Parent),
			Path:                 c.Path,
			Label:                c.Label,
			Icon:                 c.Icon,
			CMDBCIType:           c.CMDBCIType,
			CycloneDXType:        c.CycloneDXType,
			IdentifierPrecedence: c.IdentifierPrecedence,
			IsFixed:              true,
		}
		if schema, ok := assetclass.SchemaJSON(string(c.Key)); ok {
			entry.AttributeSchema = schema
		}
		out = append(out, entry)
	}

	// Tenant subclasses. A NULL tenant_id row is the platform copy of a fixed
	// class and is skipped: the registry above is the authority for those, and
	// returning both would put the same key in the list twice.
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.QueryContext(ctx, `
			SELECT key, COALESCE(parent_key, ''), path, label, COALESCE(description, ''),
			       COALESCE(icon, ''), COALESCE(cmdb_ci_type, ''), cyclonedx_type,
			       identifier_precedence, attribute_schema::text
			FROM asset_classes
			WHERE tenant_id = $1 AND is_fixed = false
			ORDER BY path`, tenantID)
		if e != nil {
			return fmt.Errorf("query tenant asset classes: %w", e)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var c AssetClass
			var precedence pq.StringArray
			var schema string
			if e := rows.Scan(&c.Key, &c.Parent, &c.Path, &c.Label, &c.Description,
				&c.Icon, &c.CMDBCIType, &c.CycloneDXType, &precedence, &schema); e != nil {
				return fmt.Errorf("scan tenant asset class: %w", e)
			}
			c.IdentifierPrecedence = []string(precedence)
			if c.IdentifierPrecedence == nil {
				c.IdentifierPrecedence = []string{}
			}
			if schema != "" {
				c.AttributeSchema = json.RawMessage(schema)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
