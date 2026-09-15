package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// SQL fragments for the asset read paths.
//
// # Two shapes, and when each is right
//
// A read that returns ONE asset, or a handful embedded in something else (a
// certificate's asset, a location's assets, an operational row), joins the
// asset's PRIMARY endpoint with `primaryEndpointJoin`: a correlated LATERAL
// that returns at most one row, so the asset is never multiplied by its
// endpoints. That is the display rule the phase-1 spec fixes for a list row —
// the most recently seen active endpoint, and a blank when there is none.
//
// A read that returns a PAGE of assets does not use it. It selects assets, then
// loads every endpoint and every identifier for the page's ids in ONE query
// each (`loadEndpointsForAssets`, `loadIdentifiersForAssets`) — four statements
// for a page of any size, rather than the lateral's one endpoint per asset plus
// a per-row query for the rest. The primary endpoint is then the first of the
// loaded ones, ordered by the same rule the lateral applies, so the two shapes
// agree on which endpoint is "the" one.
//
// The honest part of both, and the reason neither is a compatibility view: an
// asset with no endpoint yields NULL rather than a fabricated port. An at-rest
// cloud resource genuinely has no endpoint, which is exactly what retires the
// old "AT-REST" port sentinel, and an asset with five endpoints shows one in a
// list because a row has room for one — not because the other four stopped
// existing. The list payload carries all five in `endpoints[]`.
const primaryEndpointJoin = `
		LEFT JOIN LATERAL (
			SELECT e.id, e.address, e.fqdn, e.port, e.transport, e.protocol,
			       e.service_name, e.service_version, e.service_confidence,
			       e.service_identification_method, e.status,
			       e.first_seen_at, e.last_seen_at, e.last_scanned_at, e.last_scan_status
			  FROM asset_endpoints e
			 WHERE e.tenant_id = a.tenant_id AND e.asset_id = a.id
			 ORDER BY (e.status = 'active') DESC, e.last_seen_at DESC, e.port NULLS LAST
			 LIMIT 1
		) ep ON true`

// assetOperatingSystemSQL reads the OS off the class attributes, where it lives
// now (ADR-0002 D2: a server declares `operating_system`). It is spelled out
// here so the half-dozen queries that filter or project it agree on one
// expression.
const assetOperatingSystemSQL = `(a.attributes->>'operating_system')`

// setAssetOperatingSystem writes the OS back into the asset's attributes, which
// is where it lives now. Reading it out into a column-shaped local and putting
// it back keeps the projections above positional and legible; the attribute map
// is the storage.
func normalizeAssetCollections(a *models.Asset) {
	// A nil slice marshals as JSON null, and null vs [] is exactly the
	// distinction risk_assessed_by exists to carry: empty means NOT ASSESSED,
	// and a consumer should not have to know that null means the same thing.
	if a.RiskAssessedBy == nil {
		a.RiskAssessedBy = []string{}
	}
	if a.Attributes == nil {
		a.Attributes = map[string]interface{}{}
	}
}

// setMergedInto projects the tombstone pointer a merge wrote into
// `assets.metadata` onto the asset's own `merged_into` field.
//
// The STORAGE stays in metadata — the merge writes it there and no column was
// added — but the API shape does not, because a client has to be able to follow
// the pointer and nobody follows what they cannot find in a schema. Projecting
// on read rather than adding a column also keeps the two from disagreeing:
// there is one place it is written and one place it is read.
//
// It must be called AFTER `metadata` is unmarshalled, which is why it is its own
// function rather than a line inside normalizeAssetCollections: that helper runs
// at different points in different readers, and an ordering requirement hidden
// inside it would be nil here for a reason nobody could see.
//
// A value that is not a uuid is ignored rather than surfaced. Only the merge
// path writes this key, so a malformed one is corruption, and a tombstone
// pointing at a non-asset is worse than no pointer at all.
func setMergedInto(a *models.Asset) {
	raw, ok := a.Metadata["merged_into"].(string)
	if !ok || raw == "" {
		return
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return
	}
	a.MergedInto = &id
}

func setAssetOperatingSystem(a *models.Asset, os *string) {
	if os == nil || *os == "" {
		return
	}
	if a.Attributes == nil {
		a.Attributes = map[string]interface{}{}
	}
	a.Attributes["operating_system"] = *os
}

// attachPrimaryEndpoint records the endpoint a list row was rendered from, when
// there is one. Everything nil means the asset has no endpoint — a real answer,
// not a missing value — and PrimaryEndpoint stays nil to say so.
func attachPrimaryEndpoint(a *models.Asset, ep models.Endpoint) {
	if ep.Address == nil && ep.FQDN == nil && ep.Port == nil && ep.ServiceName == nil {
		return
	}
	e := ep
	if strings.TrimSpace(e.Transport) == "" {
		e.Transport = "none"
	}
	a.PrimaryEndpoint = &e
	if len(a.Endpoints) == 0 {
		a.Endpoints = []models.Endpoint{e}
	}
}

// GetAssetIdentifiers is the exported form of getAssetIdentifiers, for the
// `GET /assets/{id}/identifiers` sub-resource.
func (s *AssetService) GetAssetIdentifiers(tenantID, assetID uuid.UUID) ([]models.Identifier, error) {
	out, err := s.getAssetIdentifiers(tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		// An asset with no identifiers cannot exist — the engine refuses to
		// create one (ADR-0002 D3's floor) — but an empty array is still the
		// right shape for a collection endpoint, and null is not.
		out = []models.Identifier{}
	}
	return out, nil
}

// GetAssetEndpoints is the exported form of getAssetEndpoints, for the
// `GET /assets/{id}/endpoints` sub-resource.
//
// An empty array is a real answer: an at-rest cloud resource has no endpoint at
// all, which is what retired the "AT-REST" port sentinel.
func (s *AssetService) GetAssetEndpoints(tenantID, assetID uuid.UUID) ([]models.Endpoint, error) {
	out, err := s.getAssetEndpoints(tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []models.Endpoint{}
	}
	return out, nil
}

// getAssetIdentifiers returns every identifier observed for one asset, in
// precedence order so the strongest evidence reads first.
func (s *AssetService) getAssetIdentifiers(tenantID, assetID uuid.UUID) ([]models.Identifier, error) {
	var out []models.Identifier
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(`
			SELECT id, asset_id, kind, value, scope, source_kind, source_ref, confidence,
			       first_seen_at, last_seen_at
			FROM asset_identifiers
			WHERE tenant_id = $1 AND asset_id = $2
			ORDER BY array_position($3::text[], kind), value`,
			tenantID, assetID, identifierPrecedenceArray())
		if err != nil {
			return fmt.Errorf("query asset identifiers: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var i models.Identifier
			if err := rows.Scan(&i.ID, &i.AssetID, &i.Kind, &i.Value, &i.Scope,
				&i.SourceKind, &i.SourceRef, &i.Confidence, &i.FirstSeenAt, &i.LastSeenAt); err != nil {
				return fmt.Errorf("scan asset identifier: %w", err)
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// getAssetEndpoints returns every endpoint of one asset, most recently seen
// active first — the same order the primary-endpoint lateral picks from, so the
// list row and the asset page agree on which one is "the" endpoint.
func (s *AssetService) getAssetEndpoints(tenantID, assetID uuid.UUID) ([]models.Endpoint, error) {
	var out []models.Endpoint
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(`
			SELECT id, tenant_id, asset_id, host(address) AS address, fqdn, port, transport, protocol::text,
			       service_name, service_version, service_confidence, service_identification_method,
			       bound_local,
			       source_kind, source_ref, status, first_seen_at, last_seen_at,
			       last_scanned_at, last_scan_status
			FROM asset_endpoints
			WHERE tenant_id = $1 AND asset_id = $2
			ORDER BY `+endpointOrder,
			tenantID, assetID)
		if err != nil {
			return fmt.Errorf("query asset endpoints: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var e models.Endpoint
			if err := rows.Scan(&e.ID, &e.TenantID, &e.AssetID, &e.Address, &e.FQDN, &e.Port,
				&e.Transport, &e.Protocol, &e.ServiceName, &e.ServiceVersion, &e.ServiceConfidence,
				&e.ServiceIdentificationMethod, &e.BoundLocal, &e.SourceKind, &e.SourceRef, &e.Status,
				&e.FirstSeenAt, &e.LastSeenAt, &e.LastScannedAt, &e.LastScanStatus); err != nil {
				return fmt.Errorf("scan asset endpoint: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// endpointOrder is the one rule for "which endpoint is the asset's primary
// one": the most recently seen ACTIVE endpoint, ties broken by port so the
// answer is stable. It is spelled once because the lateral and the batched
// loader must agree — a list row showing port 443 while the asset page called
// 22 the primary is the kind of disagreement nothing would ever fail on.
const endpointOrder = `(status = 'active') DESC, last_seen_at DESC, port NULLS LAST`

// loadEndpointsForAssets returns every endpoint of every asset in ids, keyed by
// asset. ONE statement for a whole page — the alternative is a query per row,
// which is how a fifty-row list becomes fifty-one round trips.
func loadEndpointsForAssets(tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID][]models.Endpoint, error) {
	out := make(map[uuid.UUID][]models.Endpoint, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(`
		SELECT id, tenant_id, asset_id, host(address) AS address, fqdn, port, transport, protocol::text,
		       service_name, service_version, service_confidence, service_identification_method,
		       bound_local,
		       source_kind, source_ref, status, first_seen_at, last_seen_at,
		       last_scanned_at, last_scan_status
		FROM asset_endpoints
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])
		ORDER BY asset_id, `+endpointOrder,
		tenantID, pq.Array(uuidStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("query endpoints for assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e models.Endpoint
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AssetID, &e.Address, &e.FQDN, &e.Port,
			&e.Transport, &e.Protocol, &e.ServiceName, &e.ServiceVersion, &e.ServiceConfidence,
			&e.ServiceIdentificationMethod, &e.BoundLocal, &e.SourceKind, &e.SourceRef, &e.Status,
			&e.FirstSeenAt, &e.LastSeenAt, &e.LastScannedAt, &e.LastScanStatus); err != nil {
			return nil, fmt.Errorf("scan endpoint: %w", err)
		}
		out[e.AssetID] = append(out[e.AssetID], e)
	}
	return out, rows.Err()
}

// loadIdentifiersForAssets returns every identifier of every asset in ids,
// keyed by asset, in the display precedence order so the strongest evidence
// reads first. ONE statement, for the same reason.
func loadIdentifiersForAssets(tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID][]models.Identifier, error) {
	out := make(map[uuid.UUID][]models.Identifier, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(`
		SELECT id, asset_id, kind, value, scope, source_kind, source_ref, confidence,
		       first_seen_at, last_seen_at
		FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])
		ORDER BY asset_id, array_position($3::text[], kind), value`,
		tenantID, pq.Array(uuidStrings(ids)), identifierPrecedenceArray())
	if err != nil {
		return nil, fmt.Errorf("query identifiers for assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var i models.Identifier
		if err := rows.Scan(&i.ID, &i.AssetID, &i.Kind, &i.Value, &i.Scope,
			&i.SourceKind, &i.SourceRef, &i.Confidence, &i.FirstSeenAt, &i.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan identifier: %w", err)
		}
		out[i.AssetID] = append(out[i.AssetID], i)
	}
	return out, rows.Err()
}

// attachChildren hangs the batched endpoints and identifiers onto a page of
// assets and picks each one's primary endpoint from what was loaded.
//
// Nil stays nil for the children a caller did not ask for, but an asset with no
// endpoints gets an empty slice rather than being left to marshal as null:
// "this asset has no endpoints" is an answer, and a consumer should not have to
// know that null spells it.
func attachChildren(assets []models.Asset,
	endpoints map[uuid.UUID][]models.Endpoint,
	identifiers map[uuid.UUID][]models.Identifier) {
	for i := range assets {
		a := &assets[i]
		eps := endpoints[a.ID]
		if eps == nil {
			eps = []models.Endpoint{}
		}
		a.Endpoints = eps
		if len(eps) > 0 {
			primary := eps[0]
			a.PrimaryEndpoint = &primary
		} else {
			a.PrimaryEndpoint = nil
		}
		ids := identifiers[a.ID]
		if ids == nil {
			ids = []models.Identifier{}
		}
		a.Identifiers = ids
	}
}

// uuidStrings renders ids for pq.Array. The composite (tenant_id, id) key is
// uuid-typed on both sides; lib/pq has no uuid array encoder, and a text array
// compared against a uuid column is resolved by Postgres to the uuid type.
func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// classPathForKey resolves a class key to its materialised ancestry. A key the
// generated registry does not carry is a tenant leaf subclass, whose path is a
// runtime row; falling back to the key keeps class_path NOT NULL and keeps the
// prefix facet honest (it matches that key and nothing else) rather than
// inventing an ancestry the tenant did not declare.
func classPathForKey(key string) string {
	if c, ok := assetclass.Get(key); ok {
		return c.Path
	}
	return key
}

// identifierPrecedenceArray renders the ADR-0002 D3 default precedence as a
// Postgres text array, for ordering a display list. It is the DEFAULT order, not
// the per-class one the engine walks: this is presentation, and a reviewer
// reading an asset page wants the same shape on every asset.
func identifierPrecedenceArray() string {
	kinds := identity.DefaultPrecedenceList()
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, string(k))
	}
	return "{" + strings.Join(parts, ",") + "}"
}
