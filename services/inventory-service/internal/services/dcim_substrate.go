package services

// The DCIM object substrate's read and edit surface (asset-inventory ADR-0010
// D5; DCIM BUILD_PLAN row 0.3): the change log, journals and tags of any
// object. The writers are shared/dcim's; this file owns the transaction (one
// per call, scoped to the tenant with set_tenant_context so RLS applies to the
// app role) and the "does this object exist for this tenant" check that keeps a
// journal or a tag from being hung on an id the tenant cannot see.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/journal"
	"github.com/vistasecurity/vistaplatform/shared/dcim/tags"
)

// ErrDcimObjectNotFound is returned when the object a journal or tag call names
// does not exist for the tenant — including a kind whose table has not shipped
// yet (the kind is valid vocabulary, there is just nothing of it to annotate).
var ErrDcimObjectNotFound = errors.New("object not found")

// TagPatch is a partial tag update; nil fields are left as they are.
type TagPatch struct {
	Name        *string
	Slug        *string
	Color       *string
	Description *string
	ObjectKinds *[]dcim.ObjectKind
}

// DcimSubstrateService implements handlers.DcimSubstrateStore over Postgres.
type DcimSubstrateService struct {
	db *sql.DB
}

// NewDcimSubstrateService returns the service over db (the app-role pool).
func NewDcimSubstrateService(db *sql.DB) *DcimSubstrateService {
	return &DcimSubstrateService{db: db}
}

func (s *DcimSubstrateService) tx(ctx context.Context, tenant uuid.UUID, fn func(*sql.Tx) error) error {
	return database.WithTenantTx(ctx, s.db, tenant, fn)
}

// objectExists reports whether kind/id is a row of kind's table for tenant.
// The table name comes from the generated vocabulary, never from the request.
func objectExists(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) error {
	table := kind.Table()
	if table == "" {
		return ErrDcimObjectNotFound
	}
	var present bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&present); err != nil {
		return err
	}
	if !present {
		return ErrDcimObjectNotFound
	}
	var exists bool
	q := fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM public.%s WHERE tenant_id = $1 AND id = $2)`, pq.QuoteIdentifier(table))
	if err := tx.QueryRowContext(ctx, q, tenant, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrDcimObjectNotFound
	}
	return nil
}

// ListChanges returns one page of the tenant's change log.
func (s *DcimSubstrateService) ListChanges(ctx context.Context, f changes.Filter) (out []changes.ObjectChange, total int, err error) {
	err = s.tx(ctx, f.TenantID, func(tx *sql.Tx) error {
		out, total, err = changes.List(ctx, tx, f)
		return err
	})
	return out, total, err
}

// GetChange returns one change of the tenant's log, or changes.ErrNotFound.
func (s *DcimSubstrateService) GetChange(ctx context.Context, tenant, id uuid.UUID) (out changes.ObjectChange, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		out, err = changes.Get(ctx, tx, tenant, id)
		return err
	})
	return out, err
}

// ListJournal returns one page of an object's journal.
func (s *DcimSubstrateService) ListJournal(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, limit, offset int) (out []journal.Entry, total int, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := objectExists(ctx, tx, tenant, kind, id); err != nil {
			return err
		}
		out, total, err = journal.List(ctx, tx, tenant, kind, id, limit, offset)
		return err
	})
	return out, total, err
}

// AddJournal writes an entry on an object, attributed to the context's actor.
func (s *DcimSubstrateService) AddJournal(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, entryKind journal.Kind, comments string) (e journal.Entry, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := objectExists(ctx, tx, tenant, kind, id); err != nil {
			return err
		}
		e, err = journal.Add(ctx, tx, changes.InTx(tx), tenant, kind, id, entryKind, comments)
		return err
	})
	return e, err
}

// ObjectTags returns the tags on an object.
func (s *DcimSubstrateService) ObjectTags(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) (out []tags.Tag, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := objectExists(ctx, tx, tenant, kind, id); err != nil {
			return err
		}
		out, err = tags.ForObject(ctx, tx, tenant, kind, id)
		return err
	})
	return out, err
}

// SetObjectTags makes an object's tags exactly tagIDs.
func (s *DcimSubstrateService) SetObjectTags(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, tagIDs []uuid.UUID) (out []tags.Tag, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := objectExists(ctx, tx, tenant, kind, id); err != nil {
			return err
		}
		out, err = tags.SetForObject(ctx, tx, changes.InTx(tx), tenant, kind, id, tagIDs)
		return err
	})
	return out, err
}

// ListTags returns the tenant's tags.
func (s *DcimSubstrateService) ListTags(ctx context.Context, tenant uuid.UUID) (out []tags.Tag, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		out, err = tags.List(ctx, tx, tenant)
		return err
	})
	return out, err
}

// CreateTag adds a tag.
func (s *DcimSubstrateService) CreateTag(ctx context.Context, tenant uuid.UUID, in tags.Input) (t tags.Tag, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		t, err = tags.Create(ctx, tx, changes.InTx(tx), tenant, in)
		return err
	})
	return t, err
}

// UpdateTag applies a partial update.
func (s *DcimSubstrateService) UpdateTag(ctx context.Context, tenant, id uuid.UUID, p TagPatch) (t tags.Tag, err error) {
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		cur, err := tags.Get(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		in := tags.Input{Name: cur.Name, Slug: cur.Slug, Color: cur.Color, Description: cur.Description, ObjectKinds: cur.ObjectKinds}
		if p.Name != nil {
			in.Name = *p.Name
			if p.Slug == nil && tags.Slugify(cur.Name) == cur.Slug {
				// The slug was the generated one: keep it generated.
				in.Slug = ""
			}
		}
		if p.Slug != nil {
			in.Slug = *p.Slug
		}
		if p.Color != nil {
			in.Color = p.Color
		}
		if p.Description != nil {
			in.Description = p.Description
		}
		if p.ObjectKinds != nil {
			in.ObjectKinds = *p.ObjectKinds
		}
		t, err = tags.Update(ctx, tx, changes.InTx(tx), tenant, id, in)
		return err
	})
	return t, err
}

// DeleteTag removes a tag and its links.
func (s *DcimSubstrateService) DeleteTag(ctx context.Context, tenant, id uuid.UUID) error {
	return s.tx(ctx, tenant, func(tx *sql.Tx) error {
		return tags.Delete(ctx, tx, changes.InTx(tx), tenant, id)
	})
}
