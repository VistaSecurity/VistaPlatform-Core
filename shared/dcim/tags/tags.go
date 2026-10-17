// Package tags is the tenant's tag vocabulary and the tag ↔ object link
// (`tags`, `object_tags`; asset-inventory ADR-0010 D5, DCIM DATA_MODEL §8).
//
// Every write records a change through shared/dcim/changes: creating, editing
// or deleting a tag is a change to the TAG (kind `tag`); setting an object's
// tags is a change to the OBJECT, with `tags` in changed_fields and the slug
// lists as the images — which is how NetBox records an m2m edit.
//
// Every function takes the caller's transaction, already scoped to the tenant
// with set_tenant_context, and also names the tenant in every predicate.
package tags

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// Tag is one tag in a tenant's vocabulary.
type Tag struct {
	ID          uuid.UUID         `json:"id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	Color       *string           `json:"color"`
	Description *string           `json:"description"`
	ObjectKinds []dcim.ObjectKind `json:"object_kinds"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Input is a create, or a full replacement on update. Slug is generated from
// Name when empty.
type Input struct {
	Name        string
	Slug        string
	Color       *string
	Description *string
	ObjectKinds []dcim.ObjectKind
}

// Errors a caller maps to 4xx.
var (
	ErrNotFound      = errors.New("tags: not found")
	ErrInvalid       = errors.New("tags: invalid")
	ErrDuplicate     = errors.New("tags: a tag with that name or slug already exists")
	ErrNotApplicable = errors.New("tags: tag is restricted to other object kinds")
)

var (
	slugPattern  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	colorPattern = regexp.MustCompile(`^[0-9a-f]{6}$`)
	nonSlug      = regexp.MustCompile(`[^a-z0-9]+`)
)

// Slugify is the slug generated from a name: lowercase kebab, the schema's
// shape.
func Slugify(name string) string {
	s := nonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	s = strings.Trim(s, "-")
	if len(s) > 100 {
		s = strings.TrimRight(s[:100], "-")
	}
	return s
}

// Normalize validates in and fills the generated slug.
func Normalize(in Input) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return in, fmt.Errorf("%w: name must be 1-100 characters", ErrInvalid)
	}
	if in.Slug == "" {
		in.Slug = Slugify(in.Name)
	}
	if !slugPattern.MatchString(in.Slug) || len(in.Slug) > 100 {
		return in, fmt.Errorf("%w: slug must be lowercase letters, digits and single hyphens", ErrInvalid)
	}
	if in.Color != nil {
		c := strings.TrimPrefix(strings.ToLower(*in.Color), "#")
		if c == "" {
			in.Color = nil
		} else if !colorPattern.MatchString(c) {
			return in, fmt.Errorf("%w: color must be six hex digits", ErrInvalid)
		} else {
			in.Color = &c
		}
	}
	if in.Description != nil {
		d := strings.TrimSpace(*in.Description)
		if d == "" {
			in.Description = nil
		} else {
			in.Description = &d
		}
	}
	seen := map[dcim.ObjectKind]bool{}
	kinds := []dcim.ObjectKind{}
	for _, k := range in.ObjectKinds {
		if _, ok := dcim.ParseObjectKind(string(k)); !ok {
			return in, fmt.Errorf("%w: unknown object kind %q", ErrInvalid, k)
		}
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	in.ObjectKinds = kinds
	return in, nil
}

// AppliesTo reports whether t may be attached to an object of kind k.
func (t Tag) AppliesTo(k dcim.ObjectKind) bool {
	if len(t.ObjectKinds) == 0 {
		return true
	}
	for _, ok := range t.ObjectKinds {
		if ok == k {
			return true
		}
	}
	return false
}

const tagColumns = `id, name, slug, color, description, object_kinds, created_at, updated_at`

func scanTag(row interface{ Scan(...any) error }) (Tag, error) {
	var (
		t     Tag
		kinds pq.StringArray
		color sql.NullString
		desc  sql.NullString
	)
	if err := row.Scan(&t.ID, &t.Name, &t.Slug, &color, &desc, &kinds, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return Tag{}, err
	}
	if color.Valid {
		t.Color = &color.String
	}
	if desc.Valid {
		t.Description = &desc.String
	}
	t.ObjectKinds = make([]dcim.ObjectKind, 0, len(kinds))
	for _, k := range kinds {
		t.ObjectKinds = append(t.ObjectKinds, dcim.ObjectKind(k))
	}
	return t, nil
}

func kindStrings(ks []dcim.ObjectKind) pq.StringArray {
	out := make(pq.StringArray, 0, len(ks))
	for _, k := range ks {
		out = append(out, string(k))
	}
	return out
}

func queryTags(ctx context.Context, tx changes.DBTX, q string, args ...any) ([]Tag, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Tag{}
	for rows.Next() {
		t, err := scanTag(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// List returns the tenant's tags ordered by name.
func List(ctx context.Context, tx changes.DBTX, tenant uuid.UUID) ([]Tag, error) {
	return queryTags(ctx, tx, `SELECT `+tagColumns+` FROM tags WHERE tenant_id = $1 ORDER BY lower(name), id`, tenant)
}

// Get returns one tag.
func Get(ctx context.Context, tx changes.DBTX, tenant, id uuid.UUID) (Tag, error) {
	t, err := scanTag(tx.QueryRowContext(ctx, `SELECT `+tagColumns+` FROM tags WHERE tenant_id = $1 AND id = $2`, tenant, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	return t, err
}

func mapWriteErr(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505":
			return ErrDuplicate
		case "23514":
			return fmt.Errorf("%w: %s", ErrInvalid, pqErr.Constraint)
		}
	}
	return err
}

// Create adds a tag and records its creation.
func Create(ctx context.Context, tx changes.DBTX, rec changes.Recorder, tenant uuid.UUID, in Input) (Tag, error) {
	in, err := Normalize(in)
	if err != nil {
		return Tag{}, err
	}
	var createdBy any
	if a, ok := changes.ActorFrom(ctx); ok {
		createdBy = a.UserID
	}
	t, err := scanTag(tx.QueryRowContext(ctx, `
		INSERT INTO tags (tenant_id, name, slug, color, description, object_kinds, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+tagColumns,
		tenant, in.Name, in.Slug, in.Color, in.Description, kindStrings(in.ObjectKinds), createdBy))
	if err != nil {
		return Tag{}, mapWriteErr(err)
	}
	if err := rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindTag, ID: t.ID, Action: changes.ActionCreate, Post: t}); err != nil {
		return Tag{}, err
	}
	return t, nil
}

// Update replaces a tag's fields and records the change.
func Update(ctx context.Context, tx changes.DBTX, rec changes.Recorder, tenant, id uuid.UUID, in Input) (Tag, error) {
	in, err := Normalize(in)
	if err != nil {
		return Tag{}, err
	}
	pre, err := Get(ctx, tx, tenant, id)
	if err != nil {
		return Tag{}, err
	}
	post, err := scanTag(tx.QueryRowContext(ctx, `
		UPDATE tags SET name = $3, slug = $4, color = $5, description = $6, object_kinds = $7, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2
		RETURNING `+tagColumns,
		tenant, id, in.Name, in.Slug, in.Color, in.Description, kindStrings(in.ObjectKinds)))
	if err != nil {
		return Tag{}, mapWriteErr(err)
	}
	if err := rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindTag, ID: id, Action: changes.ActionUpdate, Pre: pre, Post: post}); err != nil {
		return Tag{}, err
	}
	return post, nil
}

// Delete removes a tag (its object_tags rows cascade) and records the delete.
// The objects that carried it are not each recorded as changed: NetBox does
// not either, and the tag's own pre-image says what went.
func Delete(ctx context.Context, tx changes.DBTX, rec changes.Recorder, tenant, id uuid.UUID) error {
	pre, err := Get(ctx, tx, tenant, id)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE tenant_id = $1 AND id = $2`, tenant, id); err != nil {
		return err
	}
	return rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindTag, ID: id, Action: changes.ActionDelete, Pre: pre})
}

// ForObject returns the tags on one object, ordered by name.
func ForObject(ctx context.Context, tx changes.DBTX, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) ([]Tag, error) {
	return queryTags(ctx, tx, `
		SELECT t.id, t.name, t.slug, t.color, t.description, t.object_kinds, t.created_at, t.updated_at
		  FROM object_tags ot JOIN tags t ON t.tenant_id = ot.tenant_id AND t.id = ot.tag_id
		 WHERE ot.tenant_id = $1 AND ot.object_kind = $2 AND ot.object_id = $3
		 ORDER BY lower(t.name), t.id`, tenant, string(kind), id)
}

func slugs(ts []Tag) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Slug)
	}
	sort.Strings(out)
	return out
}

// SetForObject makes the object's tags exactly tagIDs, applying the
// difference, and records ONE change on the object when anything moved. Every
// id must be one of the tenant's tags and applicable to kind.
func SetForObject(ctx context.Context, tx changes.DBTX, rec changes.Recorder, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, tagIDs []uuid.UUID) ([]Tag, error) {
	if _, ok := dcim.ParseObjectKind(string(kind)); !ok {
		return nil, fmt.Errorf("%w: unknown object kind %q", ErrInvalid, kind)
	}
	before, err := ForObject(ctx, tx, tenant, kind, id)
	if err != nil {
		return nil, err
	}
	want := map[uuid.UUID]bool{}
	for _, tid := range tagIDs {
		if want[tid] {
			continue
		}
		t, err := Get(ctx, tx, tenant, tid)
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w: tag %s", ErrNotFound, tid)
		}
		if err != nil {
			return nil, err
		}
		if !t.AppliesTo(kind) {
			return nil, fmt.Errorf("%w: %q cannot be applied to a %s", ErrNotApplicable, t.Name, kind.Label())
		}
		want[tid] = true
	}
	have := map[uuid.UUID]bool{}
	for _, t := range before {
		have[t.ID] = true
		if !want[t.ID] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM object_tags WHERE tenant_id = $1 AND object_kind = $2 AND object_id = $3 AND tag_id = $4`,
				tenant, string(kind), id, t.ID); err != nil {
				return nil, err
			}
		}
	}
	var createdBy any
	if a, ok := changes.ActorFrom(ctx); ok {
		createdBy = a.UserID
	}
	for tid := range want {
		if have[tid] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO object_tags (tenant_id, object_kind, object_id, tag_id, created_by)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			tenant, string(kind), id, tid, createdBy); err != nil {
			return nil, mapWriteErr(err)
		}
	}
	after, err := ForObject(ctx, tx, tenant, kind, id)
	if err != nil {
		return nil, err
	}
	err = rec.Record(ctx, changes.Change{
		TenantID: tenant, Kind: kind, ID: id, Action: changes.ActionUpdate,
		Pre: map[string]any{"tags": slugs(before)}, Post: map[string]any{"tags": slugs(after)},
	})
	if err != nil {
		return nil, err
	}
	return after, nil
}
