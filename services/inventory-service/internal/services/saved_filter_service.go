package services

// Saved Filters (DCIM BUILD_PLAN row 5.4; DATA_MODEL section 8 `saved_filters`):
// a named query-language predicate for one or more object kinds, personal or
// shared, offered as a preset on the lenses that have a query bar.
//
// Two rules are the point of the file:
//
//  1. The query is validated on write, against EVERY kind the filter names, by
//     the same validator the lens runs (CheckAssetQuery). A kind with no query
//     catalogue is refused rather than saved unchecked: a filter that cannot
//     run must not be savable.
//  2. Who may touch a row. A personal filter belongs to its owner and is
//     invisible to everyone else (404, not 403, so ids cannot be probed). A
//     shared filter is visible to the tenant, and creating, editing or
//     deleting one -- or turning a personal one shared -- needs the caller to
//     be allowed to share (settings.update, resolved by the handler).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// Errors a handler maps to 4xx.
var (
	ErrSavedFilterNotFound  = errors.New("saved filter not found")
	ErrSavedFilterForbidden = errors.New("sharing a filter needs permission to change organisation settings")
	ErrSavedFilterInvalid   = errors.New("saved filter invalid")
	ErrSavedFilterDuplicate = errors.New("a saved filter with that slug already exists")
)

// SavedFilter is one stored filter.
type SavedFilter struct {
	ID          uuid.UUID         `json:"id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	Description *string           `json:"description"`
	ObjectKinds []dcim.ObjectKind `json:"object_kinds"`
	Query       string            `json:"query"`
	UserID      *uuid.UUID        `json:"user_id"`
	Shared      bool              `json:"shared"`
	Weight      int               `json:"weight"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// SavedFilterInput is a create, or a full replacement on update.
type SavedFilterInput struct {
	Name        string
	Slug        string
	Description *string
	ObjectKinds []dcim.ObjectKind
	Query       string
	Shared      bool
	Weight      *int
}

// SavedFilterCaller is who is asking. CanShare is the handler's answer to "may
// this person publish to the organisation".
type SavedFilterCaller struct {
	UserID   uuid.UUID
	CanShare bool
}

// SavedFilterService stores and validates saved filters.
type SavedFilterService struct{ db *sql.DB }

// NewSavedFilterService returns the service over db (the app-role pool).
func NewSavedFilterService(db *sql.DB) *SavedFilterService { return &SavedFilterService{db: db} }

// SavedFilterKinds lists the object kinds a filter can be saved for: those with
// a query catalogue target that has rows to filter.
func SavedFilterKinds() []dcim.ObjectKind {
	var out []dcim.ObjectKind
	for _, t := range AssetQueryCatalog().Targets() {
		if t.InMemory {
			continue
		}
		if k, ok := dcim.ParseObjectKind(t.Name); ok {
			out = append(out, k)
		}
	}
	return out
}

var (
	savedFilterNonSlug = regexp.MustCompile(`[^a-z0-9]+`)
	savedFilterSlug    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

func savedFilterSlugify(name string) string {
	s := strings.Trim(savedFilterNonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-")
	if len(s) > 100 {
		s = strings.TrimRight(s[:100], "-")
	}
	return s
}

// normalizeSavedFilter validates in. The query goes through the real validator
// once per kind; the canonical form of the first kind is what is stored.
func normalizeSavedFilter(in SavedFilterInput) (SavedFilterInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return in, fmt.Errorf("%w: a name of 1 to 100 characters is required", ErrSavedFilterInvalid)
	}
	if in.Slug == "" {
		in.Slug = savedFilterSlugify(in.Name)
	}
	if !savedFilterSlug.MatchString(in.Slug) || len(in.Slug) > 100 {
		return in, fmt.Errorf("%w: slug must be lowercase letters, digits and hyphens", ErrSavedFilterInvalid)
	}
	if strings.TrimSpace(in.Query) == "" {
		return in, fmt.Errorf("%w: a filter needs a query", ErrSavedFilterInvalid)
	}
	if len(in.ObjectKinds) == 0 {
		return in, fmt.Errorf("%w: name at least one object kind", ErrSavedFilterInvalid)
	}
	allowed := map[dcim.ObjectKind]bool{}
	for _, k := range SavedFilterKinds() {
		allowed[k] = true
	}
	seen := map[dcim.ObjectKind]bool{}
	kinds := make([]dcim.ObjectKind, 0, len(in.ObjectKinds))
	canonical := ""
	for _, k := range in.ObjectKinds {
		if seen[k] {
			continue
		}
		seen[k] = true
		if !allowed[k] {
			return in, fmt.Errorf("%w: %q has no query catalogue yet; filters can be saved for %v", ErrSavedFilterInvalid, k, SavedFilterKinds())
		}
		c, err := CheckAssetQuery(in.Query, string(k))
		if err != nil {
			return in, err // a *QueryError: the handler renders its spans
		}
		if canonical == "" {
			canonical = c
		}
		kinds = append(kinds, k)
	}
	in.ObjectKinds, in.Query = kinds, canonical
	return in, nil
}

const savedFilterColumns = `id, name, slug, description, object_kinds, query, user_id, shared, weight, created_at, updated_at`

type savedFilterScanner interface{ Scan(dest ...any) error }

func scanSavedFilter(r savedFilterScanner) (SavedFilter, error) {
	var (
		f     SavedFilter
		kinds pq.StringArray
		desc  sql.NullString
		owner uuid.NullUUID
	)
	if err := r.Scan(&f.ID, &f.Name, &f.Slug, &desc, &kinds, &f.Query, &owner, &f.Shared, &f.Weight, &f.CreatedAt, &f.UpdatedAt); err != nil {
		return SavedFilter{}, err
	}
	if desc.Valid {
		f.Description = &desc.String
	}
	if owner.Valid {
		f.UserID = &owner.UUID
	}
	f.ObjectKinds = make([]dcim.ObjectKind, 0, len(kinds))
	for _, k := range kinds {
		f.ObjectKinds = append(f.ObjectKinds, dcim.ObjectKind(k))
	}
	return f, nil
}

// visibleFilter is the product rule: yours, or shared with the tenant. RLS has
// already narrowed to the tenant.
const visibleFilter = `(shared OR user_id = $2)`

// List returns the filters visible to the caller, optionally for one kind,
// shared ones first, then by weight and name.
func (s *SavedFilterService) List(ctx context.Context, tenant, user uuid.UUID, kind string) (out []SavedFilter, err error) {
	q := `SELECT ` + savedFilterColumns + ` FROM saved_filters WHERE tenant_id = $1 AND ` + visibleFilter
	args := []any{tenant, user}
	if kind = strings.TrimSpace(kind); kind != "" {
		args = append(args, kind)
		q += ` AND $3 = ANY(object_kinds)`
	}
	q += ` ORDER BY shared DESC, weight, lower(name), id`
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, q, args...)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()
		out = []SavedFilter{}
		for rows.Next() {
			f, e := scanSavedFilter(rows)
			if e != nil {
				return e
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

func getVisibleFilter(ctx context.Context, tx *sql.Tx, tenant, user, id uuid.UUID) (SavedFilter, error) {
	f, err := scanSavedFilter(tx.QueryRowContext(ctx,
		`SELECT `+savedFilterColumns+` FROM saved_filters WHERE tenant_id = $1 AND `+visibleFilter+` AND id = $3`, tenant, user, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SavedFilter{}, ErrSavedFilterNotFound
	}
	return f, err
}

func kindStringArray(ks []dcim.ObjectKind) pq.StringArray {
	out := make(pq.StringArray, 0, len(ks))
	for _, k := range ks {
		out = append(out, string(k))
	}
	return out
}

func savedFilterWriteErr(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505":
			return ErrSavedFilterDuplicate
		case "23514":
			return fmt.Errorf("%w: %s", ErrSavedFilterInvalid, pqErr.Constraint)
		}
	}
	return err
}

// uniqueFilterSlug keeps an AUTO-generated slug unique: two people may each call a
// personal filter "Mine", and the tenant-wide unique slug must not make the
// second one fail. A slug the caller chose is never altered.
func uniqueFilterSlug(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, slug string, exceptID uuid.UUID) (string, error) {
	cand := slug
	for i := 2; i < 1000; i++ {
		var taken bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM saved_filters WHERE tenant_id = $1 AND slug = $2 AND id <> $3)`,
			tenant, cand, exceptID).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return cand, nil
		}
		suffix := fmt.Sprintf("-%d", i)
		base := slug
		if len(base)+len(suffix) > 100 {
			base = strings.TrimRight(base[:100-len(suffix)], "-")
		}
		cand = base + suffix
	}
	return "", ErrSavedFilterDuplicate
}

// Create validates the query against each kind and stores the filter.
func (s *SavedFilterService) Create(ctx context.Context, tenant uuid.UUID, who SavedFilterCaller, in SavedFilterInput) (out SavedFilter, err error) {
	autoSlug := in.Slug == ""
	in, err = normalizeSavedFilter(in)
	if err != nil {
		return SavedFilter{}, err
	}
	if in.Shared && !who.CanShare {
		return SavedFilter{}, ErrSavedFilterForbidden
	}
	weight := 100
	if in.Weight != nil {
		weight = *in.Weight
	}
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if autoSlug {
			if in.Slug, err = uniqueFilterSlug(ctx, tx, tenant, in.Slug, uuid.Nil); err != nil {
				return err
			}
		}
		out, err = scanSavedFilter(tx.QueryRowContext(ctx, `
			INSERT INTO saved_filters (tenant_id, name, slug, description, object_kinds, query, user_id, shared, weight, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $7)
			RETURNING `+savedFilterColumns,
			tenant, in.Name, in.Slug, in.Description, kindStringArray(in.ObjectKinds), in.Query, who.UserID, in.Shared, weight))
		if err != nil {
			return savedFilterWriteErr(err)
		}
		return changes.InTx(tx).Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindSavedFilter, ID: out.ID, Action: changes.ActionCreate, Post: out})
	})
	return out, err
}

// mayEdit applies the owner rule to a row the caller can see.
func mayEdit(f SavedFilter, who SavedFilterCaller) error {
	if f.Shared {
		if !who.CanShare {
			return ErrSavedFilterForbidden
		}
		return nil
	}
	if f.UserID == nil || *f.UserID != who.UserID {
		return ErrSavedFilterNotFound // not yours: indistinguishable from absent
	}
	return nil
}

// Update replaces a filter the caller may edit.
func (s *SavedFilterService) Update(ctx context.Context, tenant uuid.UUID, who SavedFilterCaller, id uuid.UUID, in SavedFilterInput) (out SavedFilter, err error) {
	autoSlug := in.Slug == ""
	in, err = normalizeSavedFilter(in)
	if err != nil {
		return SavedFilter{}, err
	}
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre, e := getVisibleFilter(ctx, tx, tenant, who.UserID, id)
		if e != nil {
			return e
		}
		if e := mayEdit(pre, who); e != nil {
			return e
		}
		if in.Shared && !who.CanShare {
			return ErrSavedFilterForbidden
		}
		if autoSlug {
			in.Slug = pre.Slug // a rename does not move the slug anyone linked to
		}
		weight := pre.Weight
		if in.Weight != nil {
			weight = *in.Weight
		}
		out, e = scanSavedFilter(tx.QueryRowContext(ctx, `
			UPDATE saved_filters SET name = $3, slug = $4, description = $5, object_kinds = $6, query = $7,
			       shared = $8, weight = $9, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2
			RETURNING `+savedFilterColumns,
			tenant, id, in.Name, in.Slug, in.Description, kindStringArray(in.ObjectKinds), in.Query, in.Shared, weight))
		if e != nil {
			return savedFilterWriteErr(e)
		}
		return changes.InTx(tx).Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindSavedFilter, ID: id, Action: changes.ActionUpdate, Pre: pre, Post: out})
	})
	return out, err
}

// Delete removes a filter the caller may edit.
func (s *SavedFilterService) Delete(ctx context.Context, tenant uuid.UUID, who SavedFilterCaller, id uuid.UUID) error {
	return database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre, err := getVisibleFilter(ctx, tx, tenant, who.UserID, id)
		if err != nil {
			return err
		}
		if err := mayEdit(pre, who); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM saved_filters WHERE tenant_id = $1 AND id = $2`, tenant, id); err != nil {
			return err
		}
		return changes.InTx(tx).Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindSavedFilter, ID: id, Action: changes.ActionDelete, Pre: pre})
	})
}
