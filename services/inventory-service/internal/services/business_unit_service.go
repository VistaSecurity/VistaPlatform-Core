package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/customfields"
)

// maxBusinessUnitDepth is the deepest a Business Unit tree may go, counting the
// root as level 1 (DATA_MODEL section 1: "depth <= 4 enforced in service").
const maxBusinessUnitDepth = 4

// assetBusinessUnitSQL is the SELECT-list expression every asset reader uses for
// the `business_unit` object ({id, name, slug}, or NULL when unassigned). It
// reads the assets row as `a`. Scanning it into *models.BusinessUnitRef keeps a
// reader's scan shape identical to the old nullable text column.
const assetBusinessUnitSQL = `(SELECT jsonb_build_object('id', bu.id, 'name', bu.name, 'slug', bu.slug) FROM business_units bu WHERE bu.id = a.business_unit_id)`

// assetBusinessUnitNameSQL is the same unit's name, for sorting and for readers
// that want a plain string (the crypto-configuration's asset context).
const assetBusinessUnitNameSQL = `(SELECT bu.name FROM business_units bu WHERE bu.id = a.business_unit_id)`

var (
	// ErrBusinessUnitNotFound is returned when the unit does not exist for the tenant.
	ErrBusinessUnitNotFound = errors.New("business unit not found")
	// ErrBusinessUnitInvalid wraps every 4xx-shaped validation failure.
	ErrBusinessUnitInvalid = errors.New("invalid business unit")
	// ErrBusinessUnitSlugExists is returned when an explicit slug is taken.
	ErrBusinessUnitSlugExists = errors.New("a business unit with this slug already exists")
	// ErrBusinessUnitDepth is returned when a parent would push the tree past the cap.
	ErrBusinessUnitDepth = fmt.Errorf("%w: the hierarchy may be at most %d levels deep", ErrBusinessUnitInvalid, maxBusinessUnitDepth)
	// ErrBusinessUnitCycle is returned when a unit would become its own ancestor.
	ErrBusinessUnitCycle = fmt.Errorf("%w: a business unit cannot be its own ancestor", ErrBusinessUnitInvalid)
)

// BusinessUnitInUseError is returned by Delete when objects still reference the
// unit and no reassignment target was given. The handler maps it to 409.
type BusinessUnitInUseError struct{ Assets, Prefixes int }

func (e *BusinessUnitInUseError) Error() string {
	return fmt.Sprintf("business unit is still assigned to %d asset(s) and %d prefix(es); pass reassign_to to move them", e.Assets, e.Prefixes)
}

// ObjectChange is one recorded mutation of a DCIM object, in the vocabulary of
// this service; SubstrateChangeRecorder maps it onto shared/dcim/changes.
type ObjectChange struct {
	TenantID   uuid.UUID
	ActorID    uuid.UUID
	ObjectKind dcim.ObjectKind
	ObjectID   uuid.UUID
	// Action is create, update or delete.
	Action string
	// Before is nil on create; After is nil on delete (the pre-delete state is
	// Before).
	Before map[string]any
	After  map[string]any
	// Diff holds only the keys whose value moved, as {from, to}.
	Diff map[string][2]any
}

// ChangeRecorder records an ObjectChange on the SAME transaction as the write,
// so a change row exists if and only if the write committed.
type ChangeRecorder interface {
	Record(ctx context.Context, tx *sqlx.Tx, change ObjectChange) error
}

// SubstrateChangeRecorder writes object_changes through shared/dcim/changes
// (BUILD_PLAN row 0.3). The actor and source come from the request context
// (changes.Middleware); a write made with none - an import resolving a unit -
// is attributed to ObjectChange.ActorID as a UI change when there is one, and
// to the system otherwise, because a change nobody made must say so.
type SubstrateChangeRecorder struct{}

// Record implements ChangeRecorder.
func (SubstrateChangeRecorder) Record(ctx context.Context, tx *sqlx.Tx, c ObjectChange) error {
	if _, ok := changes.SourceFrom(ctx); !ok {
		if c.ActorID != uuid.Nil {
			ctx = changes.WithSource(changes.WithActor(ctx, changes.Actor{UserID: c.ActorID}), changes.SourceUI)
		} else {
			ctx = changes.System(ctx)
		}
	}
	ch := changes.Change{TenantID: c.TenantID, Kind: c.ObjectKind, ID: c.ObjectID, Action: changes.Action(c.Action)}
	if c.Before != nil {
		ch.Pre = c.Before
	}
	if c.After != nil {
		ch.Post = c.After
	}
	return changes.InTx(tx).Record(ctx, ch)
}

// BusinessUnitService owns the business_units table.
type BusinessUnitService struct {
	db       *database.DB
	recorder ChangeRecorder
}

// NewBusinessUnitService returns a service recording through the DCIM substrate.
func NewBusinessUnitService(db *database.DB) *BusinessUnitService {
	return &BusinessUnitService{db: db, recorder: SubstrateChangeRecorder{}}
}

// SetChangeRecorder replaces the recorder (tests). Nil restores the substrate one.
func (s *BusinessUnitService) SetChangeRecorder(r ChangeRecorder) {
	if r == nil {
		r = SubstrateChangeRecorder{}
	}
	s.recorder = r
}

const businessUnitColumns = `bu.id, bu.tenant_id, bu.name, bu.slug, bu.parent_id, bu.description, bu.comments,
	bu.external_ids::text, bu.source_kind, bu.source_ref, bu.custom_fields::text, bu.created_by, bu.created_at, bu.updated_at,
	(SELECT COUNT(*) FROM assets a WHERE a.business_unit_id = bu.id AND a.deleted_at IS NULL)`

type buScanner interface{ Scan(dest ...any) error }

func scanBusinessUnit(r buScanner) (*models.BusinessUnit, error) {
	var (
		u            models.BusinessUnit
		ext, custom  string
		parent, crtd uuid.NullUUID
	)
	if err := r.Scan(&u.ID, &u.TenantID, &u.Name, &u.Slug, &parent, &u.Description, &u.Comments,
		&ext, &u.SourceKind, &u.SourceRef, &custom, &crtd, &u.CreatedAt, &u.UpdatedAt, &u.AssetCount); err != nil {
		return nil, err
	}
	if parent.Valid {
		u.ParentID = &parent.UUID
	}
	if crtd.Valid {
		u.CreatedBy = &crtd.UUID
	}
	u.ExternalIDs, u.CustomFields = map[string]interface{}{}, map[string]interface{}{}
	_ = json.Unmarshal([]byte(ext), &u.ExternalIDs)
	_ = json.Unmarshal([]byte(custom), &u.CustomFields)
	return &u, nil
}

// List returns every unit of the tenant, parents before children by name, with
// the live-asset count each carries.
func (s *BusinessUnitService) List(ctx context.Context, tenantID uuid.UUID) ([]models.BusinessUnit, error) {
	out := []models.BusinessUnit{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+businessUnitColumns+` FROM business_units bu WHERE bu.tenant_id = $1 ORDER BY lower(bu.name), bu.id`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			u, err := scanBusinessUnit(rows)
			if err != nil {
				return err
			}
			out = append(out, *u)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one unit.
func (s *BusinessUnitService) Get(ctx context.Context, tenantID, id uuid.UUID) (*models.BusinessUnit, error) {
	var u *models.BusinessUnit
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		u, err = getBusinessUnitTx(ctx, tx, tenantID, id)
		return err
	})
	return u, err
}

func getBusinessUnitTx(ctx context.Context, tx *sqlx.Tx, tenantID, id uuid.UUID) (*models.BusinessUnit, error) {
	u, err := scanBusinessUnit(tx.QueryRowContext(ctx, `SELECT `+businessUnitColumns+` FROM business_units bu WHERE bu.tenant_id = $1 AND bu.id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrBusinessUnitNotFound
	}
	return u, err
}

var slugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// BusinessUnitSlug derives the default slug from a name: lowercase kebab.
func BusinessUnitSlug(name string) string {
	s := strings.Trim(slugNonAlnum.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-")
	if s == "" {
		return "unit"
	}
	return s
}

// validateBusinessUnitDepth is the depth cap: parentLevels is the number of
// levels from the root to the new parent inclusive (0 for no parent) and
// subtreeLevels the levels of the subtree being attached, the unit itself
// included (1 for a leaf).
func validateBusinessUnitDepth(parentLevels, subtreeLevels int) error {
	if parentLevels+subtreeLevels > maxBusinessUnitDepth {
		return ErrBusinessUnitDepth
	}
	return nil
}

// ancestorLevels returns the levels from the root down to id inclusive.
func ancestorLevels(ctx context.Context, tx *sqlx.Tx, id uuid.UUID) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `
		WITH RECURSIVE up(id, parent_id) AS (
			SELECT id, parent_id FROM business_units WHERE id = $1
			UNION
			SELECT b.id, b.parent_id FROM business_units b JOIN up ON b.id = up.parent_id
		) SELECT COUNT(*) FROM up`, id).Scan(&n)
	return n, err
}

// subtreeLevels returns the levels of the subtree rooted at id, id included.
func subtreeLevels(ctx context.Context, tx *sqlx.Tx, id uuid.UUID) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `
		WITH RECURSIVE down(id, lvl) AS (
			SELECT id, 1 FROM business_units WHERE id = $1
			UNION
			SELECT b.id, down.lvl + 1 FROM business_units b JOIN down ON b.parent_id = down.id WHERE down.lvl < 32
		) SELECT COALESCE(MAX(lvl), 1) FROM down`, id).Scan(&n)
	return n, err
}

func isDescendant(ctx context.Context, tx *sqlx.Tx, ancestor, candidate uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `
		WITH RECURSIVE down(id) AS (
			SELECT id FROM business_units WHERE id = $1
			UNION
			SELECT b.id FROM business_units b JOIN down ON b.parent_id = down.id
		) SELECT EXISTS (SELECT 1 FROM down WHERE id = $2)`, ancestor, candidate).Scan(&ok)
	return ok, err
}

func snapshot(u *models.BusinessUnit) map[string]any {
	if u == nil {
		return nil
	}
	m := map[string]any{
		"name": u.Name, "slug": u.Slug, "description": u.Description, "comments": u.Comments,
		"external_ids": u.ExternalIDs, "source_kind": u.SourceKind, "custom_fields": u.CustomFields,
	}
	if u.ParentID != nil {
		m["parent_id"] = u.ParentID.String()
	} else {
		m["parent_id"] = nil
	}
	return m
}

func diffSnapshots(before, after map[string]any) map[string][2]any {
	d := map[string][2]any{}
	keys := map[string]struct{}{}
	for k := range before {
		keys[k] = struct{}{}
	}
	for k := range after {
		keys[k] = struct{}{}
	}
	for k := range keys {
		b, _ := json.Marshal(before[k])
		a, _ := json.Marshal(after[k])
		if string(b) != string(a) {
			d[k] = [2]any{before[k], after[k]}
		}
	}
	return d
}

func (s *BusinessUnitService) record(ctx context.Context, tx *sqlx.Tx, tenantID, actor uuid.UUID, action string, id uuid.UUID, before, after *models.BusinessUnit) error {
	b, a := snapshot(before), snapshot(after)
	return s.recorder.Record(ctx, tx, ObjectChange{
		TenantID: tenantID, ActorID: actor, ObjectKind: dcim.ObjectKindBusinessUnit, ObjectID: id,
		Action: action, Before: b, After: a, Diff: diffSnapshots(b, a),
	})
}

// uniqueSlug returns base, or base-2, base-3, ... until the tenant has no unit
// (other than exceptID) holding it.
func uniqueSlug(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, base string, exceptID uuid.UUID) (string, error) {
	for i := 1; i < 1000; i++ {
		cand := base
		if i > 1 {
			cand = fmt.Sprintf("%s-%d", base, i)
		}
		var taken bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM business_units WHERE tenant_id = $1 AND slug = $2 AND id <> $3)`, tenantID, cand, exceptID).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return cand, nil
		}
	}
	return "", fmt.Errorf("%w: could not derive a free slug from %q", ErrBusinessUnitInvalid, base)
}

// Create adds a unit. Without an explicit slug one is derived from the name and
// made unique; an explicit slug that is taken is ErrBusinessUnitSlugExists.
func (s *BusinessUnitService) Create(ctx context.Context, tenantID, actor uuid.UUID, in models.BusinessUnitInput) (*models.BusinessUnit, error) {
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrBusinessUnitInvalid)
	}
	var out *models.BusinessUnit
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.createTx(ctx, tx, tenantID, actor, in, "declared", nil, true)
		return err
	})
	if isUniqueViolation(err) {
		return nil, ErrBusinessUnitSlugExists
	}
	return out, err
}

// CreateImported adds a unit a sync peer declared (source_kind `imported`,
// source_ref naming the peer object). The change source comes from ctx
// (changes.WithSource(sync:<peer>)), so the sync can tell its own writes from a
// person's on the next run.
func (s *BusinessUnitService) CreateImported(ctx context.Context, tenantID uuid.UUID, in models.BusinessUnitInput, sourceRef *string) (*models.BusinessUnit, error) {
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrBusinessUnitInvalid)
	}
	var out *models.BusinessUnit
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.createTx(ctx, tx, tenantID, uuid.Nil, in, "imported", sourceRef, true)
		return err
	})
	if isUniqueViolation(err) {
		return nil, ErrBusinessUnitSlugExists
	}
	return out, err
}

// explicit is false when the unit is created implicitly (named on an asset
// form or an import row): its required custom fields are then not enforced.
func (s *BusinessUnitService) createTx(ctx context.Context, tx *sqlx.Tx, tenantID, actor uuid.UUID, in models.BusinessUnitInput, sourceKind string, sourceRef *string, explicit bool) (*models.BusinessUnit, error) {
	name := strings.TrimSpace(*in.Name)
	// Custom fields (DCIM row 5.1): defaults filled, values checked.
	cf, err := validateCustomFieldsTx(ctx, tx, dcim.ObjectKindBusinessUnit, true, nil, in.CustomFields, explicit && enforcesRequired(ctx, ""))
	if err != nil {
		return nil, businessUnitCustomFieldError(err)
	}
	cfJSON, err := json.Marshal(cf)
	if err != nil {
		return nil, err
	}
	if in.ParentID != nil {
		if _, err := getBusinessUnitTx(ctx, tx, tenantID, *in.ParentID); err != nil {
			if errors.Is(err, ErrBusinessUnitNotFound) {
				return nil, fmt.Errorf("%w: parent not found", ErrBusinessUnitInvalid)
			}
			return nil, err
		}
		levels, err := ancestorLevels(ctx, tx, *in.ParentID)
		if err != nil {
			return nil, err
		}
		if err := validateBusinessUnitDepth(levels, 1); err != nil {
			return nil, err
		}
	}
	id := uuid.New()
	var slug string
	if in.Slug != nil && strings.TrimSpace(*in.Slug) != "" {
		slug = BusinessUnitSlug(*in.Slug)
		var taken bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM business_units WHERE tenant_id = $1 AND slug = $2)`, tenantID, slug).Scan(&taken); err != nil {
			return nil, err
		}
		if taken {
			return nil, ErrBusinessUnitSlugExists
		}
	} else {
		var err error
		if slug, err = uniqueSlug(ctx, tx, tenantID, BusinessUnitSlug(name), id); err != nil {
			return nil, err
		}
	}
	ext := in.ExternalIDs
	if ext == nil {
		ext = map[string]interface{}{}
	}
	extJSON, _ := json.Marshal(ext)
	var createdBy any
	if actor != uuid.Nil {
		createdBy = actor
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO business_units (id, tenant_id, name, slug, parent_id, description, comments, external_ids, source_kind, source_ref, created_by, custom_fields)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12::jsonb)`,
		id, tenantID, name, slug, in.ParentID, in.Description, in.Comments, string(extJSON), sourceKind, sourceRef, createdBy, string(cfJSON)); err != nil {
		return nil, err
	}
	created, err := getBusinessUnitTx(ctx, tx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, tx, tenantID, actor, "create", id, nil, created); err != nil {
		return nil, fmt.Errorf("record change: %w", err)
	}
	return created, nil
}

// Update patches a unit. A changed name leaves the slug alone unless the caller
// supplies one (slugs are stable identifiers; a rename must not break links).
func (s *BusinessUnitService) Update(ctx context.Context, tenantID, actor, id uuid.UUID, in models.BusinessUnitInput) (*models.BusinessUnit, error) {
	var out *models.BusinessUnit
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := getBusinessUnitTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		name, slug, parent := before.Name, before.Slug, before.ParentID
		if in.Name != nil {
			if strings.TrimSpace(*in.Name) == "" {
				return fmt.Errorf("%w: name cannot be empty", ErrBusinessUnitInvalid)
			}
			name = strings.TrimSpace(*in.Name)
		}
		if in.Slug != nil && strings.TrimSpace(*in.Slug) != "" {
			slug = BusinessUnitSlug(*in.Slug)
			var taken bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM business_units WHERE tenant_id = $1 AND slug = $2 AND id <> $3)`, tenantID, slug, id).Scan(&taken); err != nil {
				return err
			}
			if taken {
				return ErrBusinessUnitSlugExists
			}
		}
		if in.ParentSet {
			parent = in.ParentID
			if parent != nil {
				if *parent == id {
					return ErrBusinessUnitCycle
				}
				if _, err := getBusinessUnitTx(ctx, tx, tenantID, *parent); err != nil {
					if errors.Is(err, ErrBusinessUnitNotFound) {
						return fmt.Errorf("%w: parent not found", ErrBusinessUnitInvalid)
					}
					return err
				}
				cyc, err := isDescendant(ctx, tx, id, *parent)
				if err != nil {
					return err
				}
				if cyc {
					return ErrBusinessUnitCycle
				}
				up, err := ancestorLevels(ctx, tx, *parent)
				if err != nil {
					return err
				}
				down, err := subtreeLevels(ctx, tx, id)
				if err != nil {
					return err
				}
				if err := validateBusinessUnitDepth(up, down); err != nil {
					return err
				}
			}
		}
		desc, comments, ext := before.Description, before.Comments, before.ExternalIDs
		if in.Description != nil {
			desc = in.Description
		}
		if in.Comments != nil {
			comments = in.Comments
		}
		if in.ExternalIDs != nil {
			ext = in.ExternalIDs
		}
		extJSON, _ := json.Marshal(ext)
		// Custom fields (DCIM row 5.1): an update naming custom_fields changes
		// only those fields and is checked against the definitions.
		cf := before.CustomFields
		if in.CustomFields != nil {
			if cf, err = validateCustomFieldsTx(ctx, tx, dcim.ObjectKindBusinessUnit, false, before.CustomFields, in.CustomFields, enforcesRequired(ctx, "")); err != nil {
				return businessUnitCustomFieldError(err)
			}
		}
		if cf == nil {
			cf = map[string]interface{}{}
		}
		cfJSON, err := json.Marshal(cf)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE business_units SET name=$3, slug=$4, parent_id=$5, description=$6, comments=$7, external_ids=$8::jsonb, custom_fields=$9::jsonb, updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, tenantID, id, name, slug, parent, desc, comments, string(extJSON), string(cfJSON)); err != nil {
			return err
		}
		after, err := getBusinessUnitTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		if err := s.record(ctx, tx, tenantID, actor, "update", id, before, after); err != nil {
			return fmt.Errorf("record change: %w", err)
		}
		out = after
		return nil
	})
	if isUniqueViolation(err) {
		return nil, ErrBusinessUnitSlugExists
	}
	return out, err
}

// Delete removes a unit. When assets or prefixes still reference it the
// delete is refused (BusinessUnitInUseError) unless reassignTo names another
// unit, to which they are moved first. Children are re-parented to the deleted
// unit's own parent rather than orphaned to the top level.
func (s *BusinessUnitService) Delete(ctx context.Context, tenantID, actor, id uuid.UUID, reassignTo *uuid.UUID) error {
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := getBusinessUnitTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		var assets, prefixes int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND business_unit_id = $2 AND deleted_at IS NULL`, tenantID, id).Scan(&assets); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM prefixes WHERE tenant_id = $1 AND business_unit_id = $2 AND status <> 'rejected'`, tenantID, id).Scan(&prefixes); err != nil {
			return err
		}
		if (assets > 0 || prefixes > 0) && reassignTo == nil {
			return &BusinessUnitInUseError{Assets: assets, Prefixes: prefixes}
		}
		if reassignTo != nil {
			if *reassignTo == id {
				return fmt.Errorf("%w: reassign_to must be a different business unit", ErrBusinessUnitInvalid)
			}
			if _, err := getBusinessUnitTx(ctx, tx, tenantID, *reassignTo); err != nil {
				if errors.Is(err, ErrBusinessUnitNotFound) {
					return fmt.Errorf("%w: reassign_to not found", ErrBusinessUnitInvalid)
				}
				return err
			}
			// Soft-deleted assets keep the FK too, so they move with the rest.
			if _, err := tx.ExecContext(ctx, `UPDATE assets SET business_unit_id = $3, updated_at = now() WHERE tenant_id = $1 AND business_unit_id = $2`, tenantID, id, *reassignTo); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE prefixes SET business_unit_id = $3, updated_at = now() WHERE tenant_id = $1 AND business_unit_id = $2`, tenantID, id, *reassignTo); err != nil {
				return err
			}
		}
		kids, err := tx.QueryContext(ctx, `SELECT id FROM business_units WHERE tenant_id = $1 AND parent_id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		var childIDs []uuid.UUID
		for kids.Next() {
			var k uuid.UUID
			if err := kids.Scan(&k); err != nil {
				_ = kids.Close()
				return err
			}
			childIDs = append(childIDs, k)
		}
		_ = kids.Close()
		for _, k := range childIDs {
			kb, err := getBusinessUnitTx(ctx, tx, tenantID, k)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE business_units SET parent_id = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`, tenantID, k, before.ParentID); err != nil {
				return err
			}
			ka, err := getBusinessUnitTx(ctx, tx, tenantID, k)
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenantID, actor, "update", k, kb, ka); err != nil {
				return fmt.Errorf("record change: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM business_units WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
			return err
		}
		if err := s.record(ctx, tx, tenantID, actor, "delete", id, before, nil); err != nil {
			return fmt.Errorf("record change: %w", err)
		}
		return nil
	})
}

// ResolveID turns an asset-write reference into a business_unit_id.
//
//   - id non-nil: "" clears the assignment (set=true, nil id); otherwise it must
//     be a uuid naming an existing unit of the tenant.
//   - id nil, name non-nil: resolve-or-create by external id (extSystem/extID,
//     when given) then case-insensitive name (what an import supplies). A blank name is "not stated" (set=false): empty never
//     wins.
//
// set reports whether the caller expressed a value at all.
func (s *BusinessUnitService) ResolveID(ctx context.Context, tx *sqlx.Tx, tenantID, actor uuid.UUID, id, name *string, extSystem, extID, sourceKind string, sourceRef *string) (resolved *uuid.UUID, set bool, err error) {
	if id != nil {
		if strings.TrimSpace(*id) == "" {
			return nil, true, nil
		}
		u, perr := uuid.Parse(strings.TrimSpace(*id))
		if perr != nil {
			return nil, false, fmt.Errorf("%w: business_unit_id is not a uuid", ErrBusinessUnitInvalid)
		}
		if _, gerr := getBusinessUnitTx(ctx, tx, tenantID, u); gerr != nil {
			if errors.Is(gerr, ErrBusinessUnitNotFound) {
				return nil, false, fmt.Errorf("%w: business_unit_id does not exist", ErrBusinessUnitInvalid)
			}
			return nil, false, gerr
		}
		return &u, true, nil
	}
	if name == nil || strings.TrimSpace(*name) == "" {
		return nil, false, nil
	}
	var ext map[string]interface{}
	if extSystem != "" && extID != "" {
		ext = map[string]interface{}{extSystem: extID}
	}
	u, err := s.resolveOrCreateByNameTx(ctx, tx, tenantID, actor, strings.TrimSpace(*name), sourceKind, sourceRef, ext)
	if err != nil {
		return nil, false, err
	}
	return &u, true, nil
}

// ResolveOrCreateByName is ResolveID's name half on its own transaction, for
// callers (the import wizard's pre-resolution, tests) holding none.
func (s *BusinessUnitService) ResolveOrCreateByName(ctx context.Context, tenantID, actor uuid.UUID, name string) (uuid.UUID, error) {
	var out uuid.UUID
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.resolveOrCreateByNameTx(ctx, tx, tenantID, actor, strings.TrimSpace(name), "imported", nil, nil)
		return err
	})
	return out, err
}

// resolveOrCreateByNameTx matches by external id first (when given), then by
// case-insensitive name or slug, and creates the unit when nothing matches.
func (s *BusinessUnitService) resolveOrCreateByNameTx(ctx context.Context, tx *sqlx.Tx, tenantID, actor uuid.UUID, name, sourceKind string, sourceRef *string, externalIDs map[string]interface{}) (uuid.UUID, error) {
	for key, val := range externalIDs {
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM business_units WHERE tenant_id = $1 AND external_ids ->> $2 = $3 LIMIT 1`, tenantID, key, fmt.Sprint(val)).Scan(&id)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, err
		}
	}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM business_units WHERE tenant_id = $1 AND (lower(name) = lower($2) OR slug = $3) ORDER BY (lower(name) = lower($2)) DESC, created_at LIMIT 1`, tenantID, name, BusinessUnitSlug(name)).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, err
	}
	n := name
	u, err := s.createTx(ctx, tx, tenantID, actor, models.BusinessUnitInput{Name: &n, ExternalIDs: externalIDs}, sourceKind, sourceRef, false)
	if err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}

// ResolveByExternalID finds-or-creates the unit a third-party record maps to
// (NetBox tenant -> external_ids.netbox), then keeps its external id current.
func (s *BusinessUnitService) ResolveByExternalID(ctx context.Context, tx *sqlx.Tx, tenantID, actor uuid.UUID, system, externalID, name string, sourceRef *string) (uuid.UUID, error) {
	return s.resolveOrCreateByNameTx(ctx, tx, tenantID, actor, name, "imported", sourceRef, map[string]interface{}{system: externalID})
}

// businessUnitInputError maps a Business Unit validation failure onto the
// asset service's ErrInvalidInput so the asset handlers answer 400, not 500.
func businessUnitInputError(err error) error {
	if errors.Is(err, ErrBusinessUnitInvalid) {
		return fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
	}
	return err
}

// RecordAssetAssignment records, on the asset's Changes tab, that its Business
// Unit moved from old to next (either may be nil). It writes nothing when they
// are equal. Only the one field is imaged: the asset's other fields have their
// own history (asset_history) and are not DCIM-recorded yet.
func (s *BusinessUnitService) RecordAssetAssignment(ctx context.Context, tx *sqlx.Tx, tenantID, actor, assetID uuid.UUID, old, next *uuid.UUID) error {
	str := func(u *uuid.UUID) any {
		if u == nil {
			return nil
		}
		return u.String()
	}
	if str(old) == str(next) {
		return nil
	}
	b, a := map[string]any{"business_unit_id": str(old)}, map[string]any{"business_unit_id": str(next)}
	return s.recorder.Record(ctx, tx, ObjectChange{
		TenantID: tenantID, ActorID: actor, ObjectKind: dcim.ObjectKindAsset, ObjectID: assetID,
		Action: "update", Before: b, After: a, Diff: diffSnapshots(b, a),
	})
}

// businessUnitCustomFieldError maps a custom-field refusal onto
// ErrBusinessUnitInvalid (400).
func businessUnitCustomFieldError(err error) error {
	if errors.Is(err, customfields.ErrInvalid) {
		return fmt.Errorf("%w: %s", ErrBusinessUnitInvalid, customFieldMessage(err))
	}
	return err
}
