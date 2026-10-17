// Package journal is the dated, attributed comment log on any object
// (`journal_entries`; asset-inventory ADR-0010 D5, NetBox extras/journal-entry).
//
// Adding an entry records a change (kind `journal_entry`, action create)
// through shared/dcim/changes, so the change log and the journal agree about
// who wrote what and when.
package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// Kind is NetBox's JournalEntryKindChoices.
type Kind string

const (
	KindInfo    Kind = "info"
	KindSuccess Kind = "success"
	KindWarning Kind = "warning"
	KindDanger  Kind = "danger"
)

// Valid reports whether k is one of the four kinds.
func (k Kind) Valid() bool {
	return k == KindInfo || k == KindSuccess || k == KindWarning || k == KindDanger
}

// MaxComments bounds an entry's body (the schema CHECKs the same).
const MaxComments = 10000

// Entry is one journal entry.
type Entry struct {
	ID            uuid.UUID       `json:"id"`
	ObjectKind    dcim.ObjectKind `json:"object_kind"`
	ObjectID      uuid.UUID       `json:"object_id"`
	Kind          Kind            `json:"kind"`
	Comments      string          `json:"comments"`
	CreatedBy     *uuid.UUID      `json:"created_by"`
	CreatedByName *string         `json:"created_by_name"`
	CreatedAt     time.Time       `json:"created_at"`
}

// Errors a caller maps to 400.
var ErrInvalid = errors.New("journal: invalid entry")

// List returns one page of an object's entries, newest first, and the total.
func List(ctx context.Context, tx changes.DBTX, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, limit, offset int) ([]Entry, int, error) {
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM journal_entries WHERE tenant_id = $1 AND object_kind = $2 AND object_id = $3`,
		tenant, string(kind), id).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("journal: count: %w", err)
	}
	if limit <= 0 {
		limit = 50
	}
	// The author's display name comes from users (same tenant, same RLS scope);
	// a deleted user leaves the id and a NULL name, never a wrong one.
	rows, err := tx.QueryContext(ctx, `
		SELECT j.id, j.object_kind, j.object_id, j.kind, j.comments, j.created_by,
		       NULLIF(btrim(concat_ws(' ', u.first_name, u.last_name)), '') AS full_name, u.email, j.created_at
		  FROM journal_entries j
		  LEFT JOIN users u ON u.tenant_id = j.tenant_id AND u.id = j.created_by
		 WHERE j.tenant_id = $1 AND j.object_kind = $2 AND j.object_id = $3
		 ORDER BY j.created_at DESC, j.id
		 LIMIT $4 OFFSET $5`, tenant, string(kind), id, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("journal: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Entry{}
	for rows.Next() {
		var (
			e        Entry
			k, kd    string
			by       uuid.NullUUID
			fullName sql.NullString
			email    sql.NullString
		)
		if err := rows.Scan(&e.ID, &k, &e.ObjectID, &kd, &e.Comments, &by, &fullName, &email, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		e.ObjectKind, e.Kind = dcim.ObjectKind(k), Kind(kd)
		if by.Valid {
			id := by.UUID
			e.CreatedBy = &id
		}
		switch {
		case fullName.Valid:
			e.CreatedByName = &fullName.String
		case email.Valid:
			e.CreatedByName = &email.String
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Add writes an entry by the context's actor and records its creation.
func Add(ctx context.Context, tx changes.DBTX, rec changes.Recorder, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, entryKind Kind, comments string) (Entry, error) {
	if _, ok := dcim.ParseObjectKind(string(kind)); !ok {
		return Entry{}, fmt.Errorf("%w: unknown object kind %q", ErrInvalid, kind)
	}
	if entryKind == "" {
		entryKind = KindInfo
	}
	if !entryKind.Valid() {
		return Entry{}, fmt.Errorf("%w: kind must be info, success, warning or danger", ErrInvalid)
	}
	comments = strings.TrimSpace(comments)
	if comments == "" || len(comments) > MaxComments {
		return Entry{}, fmt.Errorf("%w: comments must be 1-%d characters", ErrInvalid, MaxComments)
	}
	e := Entry{ObjectKind: kind, ObjectID: id, Kind: entryKind, Comments: comments}
	var createdBy any
	if a, ok := changes.ActorFrom(ctx); ok {
		by := a.UserID
		e.CreatedBy = &by
		createdBy = by
		if a.UserName != "" {
			name := a.UserName
			e.CreatedByName = &name
		}
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO journal_entries (tenant_id, object_kind, object_id, kind, comments, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`,
		tenant, string(kind), id, string(entryKind), comments, createdBy).Scan(&e.ID, &e.CreatedAt); err != nil {
		return Entry{}, fmt.Errorf("journal: insert: %w", err)
	}
	post := map[string]any{
		"object_kind": e.ObjectKind, "object_id": e.ObjectID, "kind": e.Kind,
		"comments": e.Comments, "created_by": e.CreatedBy, "created_at": e.CreatedAt,
	}
	if err := rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindJournalEntry, ID: e.ID, Action: changes.ActionCreate, Post: post}); err != nil {
		return Entry{}, err
	}
	return e, nil
}
