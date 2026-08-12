package entitlements

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ErrUnknownItem is returned when the requested item key has no row in
// billable_items (or the row is is_active=false). Callers can treat this
// as either "deny" or "log and skip" depending on whether the key was
// expected to exist.
var ErrUnknownItem = errors.New("entitlements: unknown billable item key")

// ErrUnknownTenant is returned when tenantID does not exist in tenants.
// Without this guard the resolution query would still return catalog
// default_value because tier and override CTEs are empty.
var ErrUnknownTenant = errors.New("entitlements: unknown tenant")

// Resolver returns the effective entitlement for a (tenant, item) pair.
//
// Implementations are expected to be safe for concurrent use. Callers
// should reuse a single Resolver per process rather than constructing one
// per request — the underlying *sql.DB pool does the right thing under
// concurrency.
type Resolver interface {
	// Resolve returns the effective entitlement for one item. Returns
	// ErrUnknownItem when itemKey does not correspond to an active row in
	// billable_items, or ErrUnknownTenant when tenantID is not in tenants.
	Resolve(ctx context.Context, tenantID uuid.UUID, itemKey string) (*EffectiveEntitlement, error)

	// ResolveMany resolves several item keys in a single round trip.
	// Missing/unknown keys are absent from the returned map — callers should
	// check before dereferencing.
	ResolveMany(ctx context.Context, tenantID uuid.UUID, itemKeys []string) (map[string]*EffectiveEntitlement, error)
}

// PostgresResolver is the production implementation. It reads from
// billable_items, tier_entitlements, and tenant_entitlements via a single
// query per resolution.
type PostgresResolver struct {
	db *sql.DB
}

// NewPostgresResolver wires a resolver to a *sql.DB. The pool must be
// ready when this is called.
func NewPostgresResolver(db *sql.DB) *PostgresResolver {
	return &PostgresResolver{db: db}
}

func (r *PostgresResolver) requireTenant(ctx context.Context, tenantID uuid.UUID) error {
	var exists int
	err := r.db.QueryRowContext(ctx, `SELECT 1 FROM tenants WHERE id = $1`, tenantID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownTenant
	}
	return err
}

// The resolution query is a single statement so the result is a consistent
// snapshot. Order of evaluation:
//
//  1. Look up the billable_items row by key (must be active).
//  2. Look up the most-recently-effective, non-expired tenant override.
//  3. Look up the tenant's tier and the matching tier_entitlements row.
//  4. COALESCE the three values: override > tier > default.
//
// We compute `source` by walking the same COALESCE order so callers can
// tell where the value came from without re-reading any of the inputs.
//
// $1 = tenant_id, $2 = item key
const resolveOneSQL = `
WITH item AS (
    SELECT id, key, kind, category, unit, default_value
    FROM billable_items
    WHERE key = $2 AND is_active = true
),
active_override AS (
    SELECT te.override_value, te.expires_at
    FROM tenant_entitlements te
    JOIN item ON item.id = te.item_id
    WHERE te.tenant_id = $1
      AND te.effective_from <= NOW()
      AND (te.expires_at IS NULL OR te.expires_at > NOW())
    ORDER BY te.effective_from DESC
    LIMIT 1
),
tier_value AS (
    SELECT ent.included_value, ent.overage_price_cents, ent.overage_unit_size
    FROM tenants t
    JOIN tier_entitlements ent ON ent.tier_id = t.subscription_tier_id
    JOIN item ON item.id = ent.item_id
    WHERE t.id = $1
)
SELECT
    item.id,
    item.key,
    item.kind,
    item.category,
    item.unit,
    COALESCE(active_override.override_value, tier_value.included_value, item.default_value) AS value,
    CASE
        WHEN active_override.override_value IS NOT NULL THEN 'override'
        WHEN tier_value.included_value IS NOT NULL THEN 'tier'
        ELSE 'default'
    END AS source,
    tier_value.overage_price_cents,
    tier_value.overage_unit_size,
    active_override.expires_at
FROM item
LEFT JOIN active_override ON TRUE
LEFT JOIN tier_value ON TRUE
`

// Resolve implements Resolver.
func (r *PostgresResolver) Resolve(ctx context.Context, tenantID uuid.UUID, itemKey string) (*EffectiveEntitlement, error) {
	if err := r.requireTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	var ent *EffectiveEntitlement
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, resolveOneSQL, tenantID, itemKey)
		var scanErr error
		ent, scanErr = scanEntitlement(row.Scan)
		return scanErr
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnknownItem
	}
	if err != nil {
		return nil, fmt.Errorf("entitlements: resolve %s for tenant %s: %w", itemKey, tenantID, err)
	}
	return ent, nil
}

// $1 = tenant_id, $2 = item keys (text[])
//
// Mirrors resolveOneSQL but produces one output row per matched item; uses
// ANY($2) on the WHERE clause to fan out. Unknown keys are silently
// absent from the result set (the calling helper builds a map and the
// missing keys remain unset).
const resolveManySQL = `
WITH items AS (
    SELECT id, key, kind, category, unit, default_value
    FROM billable_items
    WHERE key = ANY($2) AND is_active = true
),
active_overrides AS (
    SELECT DISTINCT ON (te.item_id)
        te.item_id,
        te.override_value,
        te.expires_at
    FROM tenant_entitlements te
    JOIN items ON items.id = te.item_id
    WHERE te.tenant_id = $1
      AND te.effective_from <= NOW()
      AND (te.expires_at IS NULL OR te.expires_at > NOW())
    ORDER BY te.item_id, te.effective_from DESC
),
tier_values AS (
    SELECT ent.item_id, ent.included_value, ent.overage_price_cents, ent.overage_unit_size
    FROM tenants t
    JOIN tier_entitlements ent ON ent.tier_id = t.subscription_tier_id
    JOIN items ON items.id = ent.item_id
    WHERE t.id = $1
)
SELECT
    items.id,
    items.key,
    items.kind,
    items.category,
    items.unit,
    COALESCE(ao.override_value, tv.included_value, items.default_value) AS value,
    CASE
        WHEN ao.override_value IS NOT NULL THEN 'override'
        WHEN tv.included_value IS NOT NULL THEN 'tier'
        ELSE 'default'
    END AS source,
    tv.overage_price_cents,
    tv.overage_unit_size,
    ao.expires_at
FROM items
LEFT JOIN active_overrides ao ON ao.item_id = items.id
LEFT JOIN tier_values tv ON tv.item_id = items.id
`

// ResolveMany implements Resolver.
func (r *PostgresResolver) ResolveMany(ctx context.Context, tenantID uuid.UUID, itemKeys []string) (map[string]*EffectiveEntitlement, error) {
	out := make(map[string]*EffectiveEntitlement, len(itemKeys))
	if len(itemKeys) == 0 {
		return out, nil
	}
	if err := r.requireTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, resolveManySQL, tenantID, pq.Array(itemKeys))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			ent, err := scanEntitlement(rows.Scan)
			if err != nil {
				return fmt.Errorf("scan resolve-many row: %w", err)
			}
			out[ent.Item.Key] = ent
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate resolve-many rows: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("entitlements: resolve many for tenant %s: %w", tenantID, err)
	}
	return out, nil
}

// scanEntitlement is a small helper so QueryRow.Scan and Rows.Scan can
// share the same column layout. The argument is a function with Scan's
// signature so both row types can plug in.
func scanEntitlement(scan func(...any) error) (*EffectiveEntitlement, error) {
	var (
		id       uuid.UUID
		key      string
		kind     string
		category string
		unit     sql.NullString
		valueRaw []byte
		source   string
		overage  sql.NullInt64
		unitSize sql.NullInt64
		expires  sql.NullTime
	)
	if err := scan(
		&id, &key, &kind, &category, &unit,
		&valueRaw, &source,
		&overage, &unitSize, &expires,
	); err != nil {
		return nil, err
	}

	ent := &EffectiveEntitlement{
		Item: BillableItem{
			ID:       id,
			Key:      key,
			Kind:     Kind(kind),
			Category: category,
		},
		Value:  json.RawMessage(valueRaw),
		Source: Source(source),
	}
	if unit.Valid {
		u := unit.String
		ent.Item.Unit = &u
	}
	if overage.Valid {
		v := int(overage.Int64)
		ent.OveragePriceCents = &v
	}
	if unitSize.Valid {
		v := int(unitSize.Int64)
		ent.OverageUnitSize = &v
	}
	if expires.Valid {
		t := expires.Time
		ent.ExpiresAt = &t
	}
	return ent, nil
}
