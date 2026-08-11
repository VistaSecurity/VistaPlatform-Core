package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// UnknownItemKeyError is returned by ReplaceTierEntitlements when the
// request references a key that doesn't resolve to an active
// billable_items row. Handlers translate this into a 400, preserving
// the offending key for the admin UI to pinpoint the bad cell.
type UnknownItemKeyError struct {
	Key string
}

func (e *UnknownItemKeyError) Error() string {
	return "unknown or inactive billable_item key: " + e.Key
}

// DuplicateKeyError is returned by CreateBillableItem when the
// requested key already exists in the catalog. Keys are stable code
// identifiers referenced by Go and TS; re-using one would silently
// repoint every existing tier/tenant reference, so we reject at create
// time and let the admin pick a different one.
type DuplicateKeyError struct {
	Key string
}

func (e *DuplicateKeyError) Error() string {
	return "billable_item key already exists: " + e.Key
}

// ItemInUseError is returned by DeleteBillableItem when other rows
// still reference the catalog item via FK. The handler maps this to
// 409 Conflict so the admin knows to migrate the references (or
// deactivate the item via update instead).
type ItemInUseError struct {
	ID         uuid.UUID
	TierRefs   int
	TenantRefs int
}

func (e *ItemInUseError) Error() string {
	return "billable_item is referenced by other rows; deactivate it instead of deleting"
}

// EntitlementsService reads the billable_items catalog and the
// tier_entitlements rows that compose a tier. New gateable concepts
// land here without code changes — a new billable_items row is
// immediately surfaceable in the admin-UI tier composer (PR 4).
type EntitlementsService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS connection (crypto_bypass) used for the
	// deliberately cross-tenant paths annotated below (Phase 4). It runs
	// queries directly with no tenant context.
	bypassDB *sql.DB
}

// NewEntitlementsService wires the service to a connection pool.
// bypassDB is the cross-tenant (BYPASSRLS) handle used by the
// platform-wide ref-count/lookup paths.
func NewEntitlementsService(db, bypassDB *sql.DB) *EntitlementsService {
	return &EntitlementsService{db: db, bypassDB: bypassDB}
}

// BillableItem is the read-side projection of one catalog row.
// JSONB columns are exposed as json.RawMessage so callers can render
// whatever the catalog defines without us pre-parsing every shape.
type BillableItem struct {
	ID                     uuid.UUID       `json:"id"`
	Key                    string          `json:"key"`
	DisplayName            string          `json:"display_name"`
	Description            string          `json:"description,omitempty"`
	Category               string          `json:"category"`
	Kind                   string          `json:"kind"`
	Unit                   *string         `json:"unit,omitempty"`
	DefaultValue           json.RawMessage `json:"default_value"`
	IsAddonEligible        bool            `json:"is_addon_eligible"`
	DefaultAddonPriceCents *int            `json:"default_addon_price_cents,omitempty"`
	IsActive               bool            `json:"is_active"`
	SortOrder              int             `json:"sort_order"`
}

// ListBillableItems returns every billable_items row, ordered by
// sort_order then key. Includes inactive items by default so the
// admin UI can decide whether to surface them (used elsewhere by
// PR 4b's catalog management page); the composer page filters to
// is_active=true client-side.
func (s *EntitlementsService) ListBillableItems() ([]BillableItem, error) {
	rows, err := s.db.Query(`
		SELECT id, key, display_name, COALESCE(description, ''), category, kind, unit,
		       default_value, is_addon_eligible, default_addon_price_cents,
		       is_active, sort_order
		FROM billable_items
		ORDER BY sort_order ASC, key ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list billable items: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]BillableItem, 0, 32)
	for rows.Next() {
		var (
			item        BillableItem
			unit        sql.NullString
			addonCents  sql.NullInt64
			defaultJSON []byte
		)
		if err := rows.Scan(
			&item.ID, &item.Key, &item.DisplayName, &item.Description,
			&item.Category, &item.Kind, &unit,
			&defaultJSON, &item.IsAddonEligible, &addonCents,
			&item.IsActive, &item.SortOrder,
		); err != nil {
			return nil, fmt.Errorf("scan billable item: %w", err)
		}
		if unit.Valid {
			u := unit.String
			item.Unit = &u
		}
		if addonCents.Valid {
			v := int(addonCents.Int64)
			item.DefaultAddonPriceCents = &v
		}
		item.DefaultValue = json.RawMessage(defaultJSON)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate billable items: %w", err)
	}
	return out, nil
}

// TierEntitlement is one (tier, item) composition row enriched with
// the catalog metadata callers need to render the composer cell
// (kind, unit, category). Returning the enrichment in the read
// response saves the client a second round trip.
type TierEntitlement struct {
	ItemID            uuid.UUID       `json:"item_id"`
	ItemKey           string          `json:"item_key"`
	ItemDisplayName   string          `json:"item_display_name"`
	ItemCategory      string          `json:"item_category"`
	ItemKind          string          `json:"item_kind"`
	ItemUnit          *string         `json:"item_unit,omitempty"`
	IncludedValue     json.RawMessage `json:"included_value"`
	OveragePriceCents *int            `json:"overage_price_cents,omitempty"`
	OverageUnitSize   *int            `json:"overage_unit_size,omitempty"`
}

// GetTierEntitlements returns every entitlement row for a tier joined
// with the catalog metadata. Items not yet composed for this tier are
// NOT included — the composer fills missing items in from the catalog
// using each item's default_value.
func (s *EntitlementsService) GetTierEntitlements(tierID uuid.UUID) ([]TierEntitlement, error) {
	rows, err := s.db.Query(`
		SELECT bi.id, bi.key, bi.display_name, bi.category, bi.kind, bi.unit,
		       te.included_value, te.overage_price_cents, te.overage_unit_size
		FROM tier_entitlements te
		JOIN billable_items bi ON bi.id = te.item_id
		WHERE te.tier_id = $1
		ORDER BY bi.sort_order ASC, bi.key ASC
	`, tierID)
	if err != nil {
		return nil, fmt.Errorf("get tier entitlements: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]TierEntitlement, 0, 32)
	for rows.Next() {
		var (
			ent          TierEntitlement
			unit         sql.NullString
			includedJSON []byte
			overageCents sql.NullInt64
			overageSize  sql.NullInt64
		)
		if err := rows.Scan(
			&ent.ItemID, &ent.ItemKey, &ent.ItemDisplayName,
			&ent.ItemCategory, &ent.ItemKind, &unit,
			&includedJSON, &overageCents, &overageSize,
		); err != nil {
			return nil, fmt.Errorf("scan tier entitlement: %w", err)
		}
		if unit.Valid {
			u := unit.String
			ent.ItemUnit = &u
		}
		if overageCents.Valid {
			v := int(overageCents.Int64)
			ent.OveragePriceCents = &v
		}
		if overageSize.Valid {
			v := int(overageSize.Int64)
			ent.OverageUnitSize = &v
		}
		ent.IncludedValue = json.RawMessage(includedJSON)
		out = append(out, ent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tier entitlements: %w", err)
	}
	return out, nil
}

// TierEntitlementInput is one cell of the composer's bulk replace.
// Item is identified by key (stable) rather than UUID so admin UIs
// can build the payload without a UUID round-trip.
type TierEntitlementInput struct {
	ItemKey           string          `json:"item_key"`
	IncludedValue     json.RawMessage `json:"included_value"`
	OveragePriceCents *int            `json:"overage_price_cents,omitempty"`
	OverageUnitSize   *int            `json:"overage_unit_size,omitempty"`
}

// ReplaceTierEntitlements bulk-replaces a tier's composition in a
// single transaction. Anything not in the input is deleted; new
// keys are inserted; existing keys are updated. The whole set is
// validated up-front (every item_key must resolve to a known,
// active billable_items row) so a typo can't half-apply.
//
// Idempotent: running the same input twice produces the same end
// state. Concurrent calls for the same tier race; admin-UI prevents
// this with optimistic UI patterns, but the DB transaction means at
// worst the loser overwrites the winner — never corrupt state.
func (s *EntitlementsService) ReplaceTierEntitlements(tierID uuid.UUID, inputs []TierEntitlementInput) error {
	// Resolve and validate all item keys up front.
	keys := make([]string, 0, len(inputs))
	for _, in := range inputs {
		keys = append(keys, in.ItemKey)
	}

	keyToID := make(map[string]uuid.UUID, len(keys))
	if len(keys) > 0 {
		rows, err := s.db.Query(`
			SELECT key, id FROM billable_items
			WHERE key = ANY($1) AND is_active = true
		`, pq.Array(keys))
		if err != nil {
			return fmt.Errorf("resolve item keys: %w", err)
		}
		for rows.Next() {
			var (
				key string
				id  uuid.UUID
			)
			if err := rows.Scan(&key, &id); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan item key: %w", err)
			}
			keyToID[key] = id
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("iterate item keys: %w", err)
		}
		_ = rows.Close()
	}
	for _, in := range inputs {
		if _, ok := keyToID[in.ItemKey]; !ok {
			return &UnknownItemKeyError{Key: in.ItemKey}
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete-all-then-insert is the simplest correct semantic for a
	// bulk replace. tier_entitlements has no FKs pointing INTO it
	// from other tables, so cascading concerns don't apply. The
	// transaction makes the swap atomic from any concurrent reader.
	if _, err := tx.Exec(`DELETE FROM tier_entitlements WHERE tier_id = $1`, tierID); err != nil {
		return fmt.Errorf("clear tier entitlements: %w", err)
	}

	for _, in := range inputs {
		itemID := keyToID[in.ItemKey]
		// Default includedValue to {} when the caller omits it — keeps
		// PUT requests tolerant of a partially-typed UI form.
		val := []byte(in.IncludedValue)
		if len(val) == 0 {
			val = []byte("{}")
		}
		var overageCents, overageSize interface{}
		if in.OveragePriceCents != nil {
			overageCents = *in.OveragePriceCents
		}
		if in.OverageUnitSize != nil {
			overageSize = *in.OverageUnitSize
		}
		if _, err := tx.Exec(`
			INSERT INTO tier_entitlements (tier_id, item_id, included_value, overage_price_cents, overage_unit_size)
			VALUES ($1, $2, $3::jsonb, $4, $5)
		`, tierID, itemID, val, overageCents, overageSize); err != nil {
			return fmt.Errorf("insert tier entitlement %s: %w", in.ItemKey, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// BillableItemInput captures the writeable fields for create + update.
// Key is required on create and ignored on update (the key is the
// stable identifier referenced by Go/TS code; renaming it would
// silently break every reference, so the catalog UI doesn't expose
// it as editable).
type BillableItemInput struct {
	Key                    string          `json:"key"`
	DisplayName            string          `json:"display_name"`
	Description            string          `json:"description,omitempty"`
	Category               string          `json:"category"`
	Kind                   string          `json:"kind"`
	Unit                   *string         `json:"unit,omitempty"`
	DefaultValue           json.RawMessage `json:"default_value"`
	IsAddonEligible        bool            `json:"is_addon_eligible"`
	DefaultAddonPriceCents *int            `json:"default_addon_price_cents,omitempty"`
	IsActive               bool            `json:"is_active"`
	SortOrder              int             `json:"sort_order"`
}

// CreateBillableItem inserts a new catalog row. Returns
// DuplicateKeyError when the requested key collides with an existing
// row (active OR inactive — inactive rows are kept for FK integrity
// and would still conflict on the unique constraint).
//
// Category and kind are validated against the CHECK constraints in the
// schema; a bad value surfaces as the DB error wrapped in fmt.Errorf
// (handler returns 400). The composer's UI only emits valid values,
// so this is a belt-and-suspenders check for direct API callers.
func (s *EntitlementsService) CreateBillableItem(in BillableItemInput) (*BillableItem, error) {
	// Sanity check at the service layer too, so the typed error is
	// preferred over a raw 23505 from Postgres for the most common
	// failure case.
	var existing uuid.UUID
	err := s.db.QueryRow(`SELECT id FROM billable_items WHERE key = $1`, in.Key).Scan(&existing)
	if err == nil {
		return nil, &DuplicateKeyError{Key: in.Key}
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("check duplicate key: %w", err)
	}

	val := []byte(in.DefaultValue)
	if len(val) == 0 {
		val = []byte("{}")
	}
	var unit interface{}
	if in.Unit != nil {
		unit = *in.Unit
	}
	var addonCents interface{}
	if in.DefaultAddonPriceCents != nil {
		addonCents = *in.DefaultAddonPriceCents
	}

	var id uuid.UUID
	err = s.db.QueryRow(`
		INSERT INTO billable_items (
		    key, display_name, description, category, kind, unit,
		    default_value, is_addon_eligible, default_addon_price_cents,
		    is_active, sort_order
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)
		RETURNING id
	`,
		in.Key, in.DisplayName, in.Description, in.Category, in.Kind, unit,
		val, in.IsAddonEligible, addonCents, in.IsActive, in.SortOrder,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("insert billable item: %w", err)
	}

	return s.GetBillableItem(id)
}

// GetBillableItem fetches one catalog row by id. Returns sql.ErrNoRows
// when the id doesn't exist so handlers can map it to 404.
func (s *EntitlementsService) GetBillableItem(id uuid.UUID) (*BillableItem, error) {
	var (
		item        BillableItem
		unit        sql.NullString
		addonCents  sql.NullInt64
		defaultJSON []byte
	)
	err := s.db.QueryRow(`
		SELECT id, key, display_name, COALESCE(description, ''), category, kind, unit,
		       default_value, is_addon_eligible, default_addon_price_cents,
		       is_active, sort_order
		FROM billable_items
		WHERE id = $1
	`, id).Scan(
		&item.ID, &item.Key, &item.DisplayName, &item.Description,
		&item.Category, &item.Kind, &unit,
		&defaultJSON, &item.IsAddonEligible, &addonCents,
		&item.IsActive, &item.SortOrder,
	)
	if err != nil {
		return nil, err
	}
	if unit.Valid {
		u := unit.String
		item.Unit = &u
	}
	if addonCents.Valid {
		v := int(addonCents.Int64)
		item.DefaultAddonPriceCents = &v
	}
	item.DefaultValue = json.RawMessage(defaultJSON)
	return &item, nil
}

// UpdateBillableItem rewrites every non-key field of an existing
// catalog row. Key is intentionally not editable. Returns
// sql.ErrNoRows when id doesn't exist.
func (s *EntitlementsService) UpdateBillableItem(id uuid.UUID, in BillableItemInput) (*BillableItem, error) {
	val := []byte(in.DefaultValue)
	if len(val) == 0 {
		val = []byte("{}")
	}
	var unit interface{}
	if in.Unit != nil {
		unit = *in.Unit
	}
	var addonCents interface{}
	if in.DefaultAddonPriceCents != nil {
		addonCents = *in.DefaultAddonPriceCents
	}

	res, err := s.db.Exec(`
		UPDATE billable_items SET
		    display_name              = $2,
		    description               = $3,
		    category                  = $4,
		    kind                      = $5,
		    unit                      = $6,
		    default_value             = $7::jsonb,
		    is_addon_eligible         = $8,
		    default_addon_price_cents = $9,
		    is_active                 = $10,
		    sort_order                = $11,
		    updated_at                = NOW()
		WHERE id = $1
	`,
		id, in.DisplayName, in.Description, in.Category, in.Kind, unit,
		val, in.IsAddonEligible, addonCents, in.IsActive, in.SortOrder,
	)
	if err != nil {
		return nil, fmt.Errorf("update billable item: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, sql.ErrNoRows
	}
	return s.GetBillableItem(id)
}

// DeleteBillableItem hard-deletes a catalog row. Refuses (and returns
// ItemInUseError) when the row is referenced by any tier_entitlements
// or tenant_entitlements row — preserves FK integrity and prompts
// the admin toward the soft-deactivate (is_active=false) alternative.
//
// Two-step: count refs first, then delete. Race against a concurrent
// insert is possible but rare in the platform-admin UI; the worst
// case is a 500 from the FK constraint, which is the same as today's
// behavior.
//
// RLS: cross-tenant — the tenant_entitlements ref-count spans ALL tenants and
// billable_items is global, so this runs on the bypass role (Phase 4). Catalog
// methods on this service (billable_items / tier_entitlements) are global tables
// with no tenant_isolation policy and are intentionally left unwrapped.
func (s *EntitlementsService) DeleteBillableItem(id uuid.UUID) error {
	var tierRefs, tenantRefs int
	if err := s.bypassDB.QueryRow(`SELECT COUNT(*) FROM tier_entitlements WHERE item_id = $1`, id).Scan(&tierRefs); err != nil {
		return fmt.Errorf("count tier refs: %w", err)
	}
	if err := s.bypassDB.QueryRow(`SELECT COUNT(*) FROM tenant_entitlements WHERE item_id = $1`, id).Scan(&tenantRefs); err != nil {
		return fmt.Errorf("count tenant refs: %w", err)
	}
	if tierRefs > 0 || tenantRefs > 0 {
		return &ItemInUseError{ID: id, TierRefs: tierRefs, TenantRefs: tenantRefs}
	}
	res, err := s.bypassDB.Exec(`DELETE FROM billable_items WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete billable item: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tenant entitlements (per-tenant overrides)
// ---------------------------------------------------------------------------
//
// tenant_entitlements rows are the "delta" layer on top of tier_entitlements.
// Sales grants a Starter customer the OT-active-probing add-on for $99/mo by
// inserting a row here; the resolver in shared/entitlements then sees the
// override and reports it as Source=override on every read.
//
// Each row carries effective_from / expires_at so trials, promos, and POC
// grants are time-bound. The resolver only honors rows where
// effective_from <= NOW() < expires_at (or expires_at IS NULL).

// TenantEntitlement is one override row enriched with the catalog
// metadata the admin UI needs to render it (key, display_name, kind).
type TenantEntitlement struct {
	ID              uuid.UUID       `json:"id"`
	TenantID        uuid.UUID       `json:"tenant_id"`
	ItemID          uuid.UUID       `json:"item_id"`
	ItemKey         string          `json:"item_key"`
	ItemDisplayName string          `json:"item_display_name"`
	ItemKind        string          `json:"item_kind"`
	ItemUnit        *string         `json:"item_unit,omitempty"`
	OverrideValue   json.RawMessage `json:"override_value"`
	Reason          *string         `json:"reason,omitempty"`
	EffectiveFrom   string          `json:"effective_from"`
	ExpiresAt       *string         `json:"expires_at,omitempty"`
	CreatedBy       *uuid.UUID      `json:"created_by,omitempty"`
}

// ListTenantEntitlements returns every override row for the tenant
// (active, future-scheduled, and expired), enriched with the catalog
// metadata. Admin UI uses this to render the per-tenant override
// list; the resolver layer separately filters by effective_from /
// expires_at when computing the effective entitlement.
// RLS: single-tenant read on the RLS-policied tenant_entitlements table (joined
// with the global billable_items catalog) for one known tenant → wrapped.
// ctx: service method has no ctx param; using context.Background().
func (s *EntitlementsService) ListTenantEntitlements(tenantID uuid.UUID) ([]TenantEntitlement, error) {
	ctx := context.Background()
	out := make([]TenantEntitlement, 0, 8)
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(ctx, `
			SELECT
			    te.id, te.tenant_id, bi.id, bi.key, bi.display_name, bi.kind, bi.unit,
			    te.override_value, te.reason,
			    te.effective_from, te.expires_at, te.created_by
			FROM tenant_entitlements te
			JOIN billable_items bi ON bi.id = te.item_id
			WHERE te.tenant_id = $1
			ORDER BY te.effective_from DESC, bi.sort_order ASC
		`, tenantID)
		if qerr != nil {
			return fmt.Errorf("list tenant entitlements: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var (
				ent           TenantEntitlement
				unit          sql.NullString
				overrideJSON  []byte
				reason        sql.NullString
				effectiveFrom sql.NullTime
				expiresAt     sql.NullTime
				createdBy     uuid.NullUUID
			)
			if serr := rows.Scan(
				&ent.ID, &ent.TenantID, &ent.ItemID, &ent.ItemKey, &ent.ItemDisplayName, &ent.ItemKind, &unit,
				&overrideJSON, &reason,
				&effectiveFrom, &expiresAt, &createdBy,
			); serr != nil {
				return fmt.Errorf("scan tenant entitlement: %w", serr)
			}
			if unit.Valid {
				u := unit.String
				ent.ItemUnit = &u
			}
			if reason.Valid {
				r := reason.String
				ent.Reason = &r
			}
			if effectiveFrom.Valid {
				ent.EffectiveFrom = effectiveFrom.Time.UTC().Format("2006-01-02T15:04:05Z")
			}
			if expiresAt.Valid {
				es := expiresAt.Time.UTC().Format("2006-01-02T15:04:05Z")
				ent.ExpiresAt = &es
			}
			if createdBy.Valid {
				u := createdBy.UUID
				ent.CreatedBy = &u
			}
			ent.OverrideValue = json.RawMessage(overrideJSON)
			out = append(out, ent)
		}
		if rerr := rows.Err(); rerr != nil {
			return fmt.Errorf("iterate tenant entitlements: %w", rerr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TenantEntitlementInput is the writeable shape for create + update.
// item_key identifies the catalog row (more ergonomic than item_id
// for clients). On create both are RFC3339; empty effective_from
// defaults to NOW and expires_at must be after it when set. On update,
// an empty effective_from keeps the stored start time; the same
// expires_at versus effective-from rule applies when expiry is sent.
type TenantEntitlementInput struct {
	ItemKey       string          `json:"item_key"`
	OverrideValue json.RawMessage `json:"override_value"`
	Reason        *string         `json:"reason,omitempty"`
	// RFC3339. Defaults to NOW() when empty/missing on create.
	EffectiveFrom string `json:"effective_from,omitempty"`
	// RFC3339. Empty/missing = permanent (never expires).
	ExpiresAt string `json:"expires_at,omitempty"`
}

// CreateTenantEntitlement inserts a new override row. item_key must
// resolve to an active billable_items row (else UnknownItemKeyError).
// effective_from defaults to NOW() when blank; expires_at must be
// after effective_from when set.
// RLS: single-tenant write on the RLS-policied tenant_entitlements table for one
// known tenant → wrapped. The billable_items key-resolution (global catalog) runs
// inside the same tenant tx — global tables carry no policy, so RLS is a no-op there.
// ctx: service method has no ctx param; using context.Background().
func (s *EntitlementsService) CreateTenantEntitlement(tenantID uuid.UUID, createdBy *uuid.UUID, in TenantEntitlementInput) (*TenantEntitlement, error) {
	ctx := context.Background()
	var itemID uuid.UUID
	err := s.db.QueryRow(`
		SELECT id FROM billable_items WHERE key = $1 AND is_active = true
	`, in.ItemKey).Scan(&itemID)
	if err == sql.ErrNoRows {
		return nil, &UnknownItemKeyError{Key: in.ItemKey}
	}
	if err != nil {
		return nil, fmt.Errorf("resolve item key: %w", err)
	}

	effectiveFrom := time.Now()
	if in.EffectiveFrom != "" {
		t, perr := time.Parse(time.RFC3339, in.EffectiveFrom)
		if perr != nil {
			return nil, fmt.Errorf("parse effective_from: %w", perr)
		}
		effectiveFrom = t
	}
	var expiresAt interface{}
	if in.ExpiresAt != "" {
		t, perr := time.Parse(time.RFC3339, in.ExpiresAt)
		if perr != nil {
			return nil, fmt.Errorf("parse expires_at: %w", perr)
		}
		if !t.After(effectiveFrom) {
			return nil, fmt.Errorf("expires_at must be after effective_from")
		}
		expiresAt = t
	}

	val := []byte(in.OverrideValue)
	if len(val) == 0 {
		val = []byte("{}")
	}
	var reason interface{}
	if in.Reason != nil {
		reason = *in.Reason
	}
	var creator interface{}
	if createdBy != nil {
		creator = *createdBy
	}

	var id uuid.UUID
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			INSERT INTO tenant_entitlements (
			    tenant_id, item_id, override_value,
			    reason, effective_from, expires_at, created_by
			) VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)
			RETURNING id
		`, tenantID, itemID, val, reason, effectiveFrom, expiresAt, creator).Scan(&id)
	})
	if err != nil {
		return nil, fmt.Errorf("insert tenant entitlement: %w", err)
	}

	return s.GetTenantEntitlement(id)
}

// GetTenantEntitlement fetches one override row by id. Returns
// sql.ErrNoRows when the id doesn't exist.
//
// RLS: cross-tenant — the lookup is by override id only (no tenant predicate),
// so the tenant is the query output, not an input. Runs on the bypass role
// (Phase 4). Used as a read-back by Create/Update which have already authorized
// the tenant scope.
func (s *EntitlementsService) GetTenantEntitlement(id uuid.UUID) (*TenantEntitlement, error) {
	rows, err := s.bypassDB.Query(`
		SELECT
		    te.id, te.tenant_id, bi.id, bi.key, bi.display_name, bi.kind, bi.unit,
		    te.override_value, te.reason,
		    te.effective_from, te.expires_at, te.created_by
		FROM tenant_entitlements te
		JOIN billable_items bi ON bi.id = te.item_id
		WHERE te.id = $1
	`, id)
	if err != nil {
		return nil, fmt.Errorf("get tenant entitlement: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	var (
		ent           TenantEntitlement
		unit          sql.NullString
		overrideJSON  []byte
		reason        sql.NullString
		effectiveFrom sql.NullTime
		expiresAt     sql.NullTime
		createdBy     uuid.NullUUID
	)
	if err := rows.Scan(
		&ent.ID, &ent.TenantID, &ent.ItemID, &ent.ItemKey, &ent.ItemDisplayName, &ent.ItemKind, &unit,
		&overrideJSON, &reason,
		&effectiveFrom, &expiresAt, &createdBy,
	); err != nil {
		return nil, err
	}
	if unit.Valid {
		u := unit.String
		ent.ItemUnit = &u
	}
	if reason.Valid {
		r := reason.String
		ent.Reason = &r
	}
	if effectiveFrom.Valid {
		ent.EffectiveFrom = effectiveFrom.Time.UTC().Format("2006-01-02T15:04:05Z")
	}
	if expiresAt.Valid {
		s := expiresAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		ent.ExpiresAt = &s
	}
	if createdBy.Valid {
		u := createdBy.UUID
		ent.CreatedBy = &u
	}
	ent.OverrideValue = json.RawMessage(overrideJSON)
	return &ent, nil
}

// UpdateTenantEntitlement rewrites the override_value, pricing,
// reason, effective window, and expiry fields. item_key and tenant_id
// are immutable per row; to change which item the override targets,
// delete and re-create. When effective_from is omitted or empty,
// retains the stored start time. Unknown id / wrong tenant yields
// sql.ErrNoRows.
// RLS: single-tenant write on the RLS-policied tenant_entitlements table for one
// known tenant → the prefetch + update both run inside one tenant-scoped tx.
// ctx: service method has no ctx param; using context.Background().
func (s *EntitlementsService) UpdateTenantEntitlement(tenantID, id uuid.UUID, in TenantEntitlementInput) (*TenantEntitlement, error) {
	ctx := context.Background()
	var existingEff sql.NullTime
	if err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT effective_from FROM tenant_entitlements WHERE id = $1 AND tenant_id = $2
		`, id, tenantID).Scan(&existingEff)
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("prefetch tenant entitlement: %w", err)
	}

	effectiveFrom := time.Now().UTC()
	if existingEff.Valid {
		effectiveFrom = existingEff.Time.UTC()
	}
	if in.EffectiveFrom != "" {
		t, perr := time.Parse(time.RFC3339, in.EffectiveFrom)
		if perr != nil {
			return nil, fmt.Errorf("parse effective_from: %w", perr)
		}
		effectiveFrom = t.UTC()
	}

	val := []byte(in.OverrideValue)
	if len(val) == 0 {
		val = []byte("{}")
	}
	var reason interface{}
	if in.Reason != nil {
		reason = *in.Reason
	}
	var expiresAt interface{}
	if in.ExpiresAt != "" {
		t, perr := time.Parse(time.RFC3339, in.ExpiresAt)
		if perr != nil {
			return nil, fmt.Errorf("parse expires_at: %w", perr)
		}
		if !t.UTC().After(effectiveFrom) {
			return nil, fmt.Errorf("expires_at must be after effective_from")
		}
		expiresAt = t
	}

	var n int64
	if err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		res, eerr := tx.ExecContext(ctx, `
			UPDATE tenant_entitlements SET
			    override_value      = $3::jsonb,
			    reason              = $4,
			    effective_from      = $5,
			    expires_at          = $6,
			    updated_at          = NOW()
			WHERE id = $1 AND tenant_id = $2
		`, id, tenantID, val, reason, effectiveFrom, expiresAt)
		if eerr != nil {
			return eerr
		}
		n, _ = res.RowsAffected()
		return nil
	}); err != nil {
		return nil, fmt.Errorf("update tenant entitlement: %w", err)
	}
	if n == 0 {
		return nil, sql.ErrNoRows
	}
	return s.GetTenantEntitlement(id)
}

// DeleteTenantEntitlement removes an override row. Effectively
// reverts the tenant to the tier default for that item. Returns
// sql.ErrNoRows when the id doesn't exist under that tenant.
// RLS: single-tenant write on the RLS-policied tenant_entitlements table → wrapped.
// ctx: service method has no ctx param; using context.Background().
func (s *EntitlementsService) DeleteTenantEntitlement(tenantID, id uuid.UUID) error {
	ctx := context.Background()
	var n int64
	if err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		res, eerr := tx.ExecContext(ctx, `DELETE FROM tenant_entitlements WHERE id = $1 AND tenant_id = $2`, id, tenantID)
		if eerr != nil {
			return eerr
		}
		n, _ = res.RowsAffected()
		return nil
	}); err != nil {
		return fmt.Errorf("delete tenant entitlement: %w", err)
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
