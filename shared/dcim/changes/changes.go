// Package changes records every create, update and delete of a DCIM object in
// `object_changes` (asset-inventory ADR-0010 D5; DCIM DATA_MODEL §8).
//
// The record is written by the SERVICE LAYER, inside the transaction that made
// the change, never by a trigger: only the service knows who asked (the actor)
// and which request it was (the request id), and a trigger would record the
// connection's role instead of the person.
//
// Three rules the package enforces so callers cannot get them wrong:
//
//  1. The object kind is one of [dcim.AllObjectKinds]. The schema CHECKs the
//     same list; Go refuses first so the caller gets a named error, not a
//     constraint violation.
//  2. Somebody is accountable. A change made through the UI or the API needs an
//     actor in the context ([WithActor]); a change with nobody behind it must
//     SAY so — source `system`, `intake:<producer>` or `sync:<peer>` — rather
//     than arrive anonymously because a handler forgot to pass the user along.
//  3. Secrets never reach `prechange_data` / `postchange_data`. Both images go
//     through [shared/redact] ([Diff]); the field still appears in
//     `changed_fields`, so a rotated PSK is recorded as a change to `psk`
//     without either value.
package changes

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// DBTX is the slice of *sql.Tx (and *sqlx.Tx, which embeds it) the writers in
// shared/dcim need. Taking the caller's transaction is the point: the change
// record commits or rolls back with the change it describes.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Action is what happened to the object.
type Action string

const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// Valid reports whether a is one of the three actions.
func (a Action) Valid() bool {
	return a == ActionCreate || a == ActionUpdate || a == ActionDelete
}

// Source is where a change came from: `ui`, `api`, `system`,
// `intake:<producer>` or `sync:<peer>`.
type Source string

const (
	SourceUI     Source = "ui"
	SourceAPI    Source = "api"
	SourceSystem Source = "system"
)

var sourcePattern = regexp.MustCompile(`^(ui|api|system|intake:[a-z0-9_.-]+|sync:[a-z0-9_.-]+)$`)

// IntakeSource is the source of a change an intake producer made
// (`intake:lldp`, `intake:cloud`).
func IntakeSource(producer string) Source { return Source("intake:" + producer) }

// SyncSource is the source of a change a sync peer made (`sync:netbox`).
func SyncSource(peer string) Source { return Source("sync:" + peer) }

// Valid reports whether s has one of the five shapes the schema accepts.
func (s Source) Valid() bool { return sourcePattern.MatchString(string(s)) }

// RequiresActor reports whether a change from s must name a person. Only the
// two sources a person drives do.
func (s Source) RequiresActor() bool { return s == SourceUI || s == SourceAPI }

// Change is one create, update or delete of one object.
//
// Pre and Post are the object before and after, as anything that marshals to a
// JSON object (a struct with json tags, or a map). Create has no Pre, delete
// has no Post. ChangedFields is computed by [Diff] when left empty.
//
// Source may be left empty: the context's source ([WithSource], set per request
// by [Middleware]) is used, and failing that the change is refused.
type Change struct {
	TenantID      uuid.UUID
	Kind          dcim.ObjectKind
	ID            uuid.UUID
	Action        Action
	Pre           any
	Post          any
	ChangedFields []string
	Source        Source
	// Related is the object this one belongs to, so the parent's Changes tab
	// lists it (`include_related`). Leave nil to let the Postgres recorder
	// derive it from the images ([DeriveRelated]); set it for a kind the
	// derivation does not know.
	Related *Ref
}

// Ref names one object.
type Ref struct {
	Kind dcim.ObjectKind
	ID   uuid.UUID
}

// Recorder records changes. [InTx] is the Postgres implementation; tests use
// dcimtest.MemoryRecorder.
type Recorder interface {
	Record(ctx context.Context, c Change) error
}

// Errors a caller can branch on.
var (
	ErrUnknownKind   = errors.New("changes: unknown object kind")
	ErrInvalidAction = errors.New("changes: invalid action")
	ErrInvalidSource = errors.New("changes: invalid source")
	ErrNoActor       = errors.New("changes: a ui/api change needs an actor in the context; a change nobody made must say so with source system, intake:<producer> or sync:<peer>")
	ErrNoTenant      = errors.New("changes: tenant id is required")
	ErrNoObject      = errors.New("changes: object id is required")
	ErrImages        = errors.New("changes: create needs only a post-image, delete only a pre-image, update both")
)

// Row is a change ready to write: validated, diffed and redacted.
type Row struct {
	TenantID       uuid.UUID
	Kind           dcim.ObjectKind
	ObjectID       uuid.UUID
	Action         Action
	PrechangeData  json.RawMessage // nil for create
	PostchangeData json.RawMessage // nil for delete
	ChangedFields  []string
	UserID         *uuid.UUID
	UserName       string
	RequestID      *uuid.UUID
	Source         Source
	RelatedKind    dcim.ObjectKind // empty when the change has no parent
	RelatedID      *uuid.UUID
}

// Prepare applies every rule in the package doc and returns the row to write.
// skip is true for an update that changed nothing — there is nothing to record.
// Both implementations of [Recorder] go through it, so the rules cannot differ
// between the store a test uses and the one production uses.
func Prepare(ctx context.Context, c Change) (row Row, skip bool, err error) {
	if c.TenantID == uuid.Nil {
		return Row{}, false, ErrNoTenant
	}
	if c.ID == uuid.Nil {
		return Row{}, false, ErrNoObject
	}
	if _, ok := dcim.ParseObjectKind(string(c.Kind)); !ok {
		return Row{}, false, fmt.Errorf("%w: %q", ErrUnknownKind, c.Kind)
	}
	if !c.Action.Valid() {
		return Row{}, false, fmt.Errorf("%w: %q", ErrInvalidAction, c.Action)
	}
	switch c.Action {
	case ActionCreate:
		if c.Pre != nil || c.Post == nil {
			return Row{}, false, ErrImages
		}
	case ActionDelete:
		if c.Pre == nil || c.Post != nil {
			return Row{}, false, ErrImages
		}
	case ActionUpdate:
		if c.Pre == nil || c.Post == nil {
			return Row{}, false, ErrImages
		}
	}

	src := c.Source
	if src == "" {
		src, _ = SourceFrom(ctx)
	}
	if src == "" {
		// Not "default to ui": an unattributed write is exactly the bug rule 2
		// exists to catch.
		return Row{}, false, fmt.Errorf("%w (no source set)", ErrNoActor)
	}
	if !src.Valid() {
		return Row{}, false, fmt.Errorf("%w: %q", ErrInvalidSource, src)
	}
	actor, hasActor := ActorFrom(ctx)
	if src.RequiresActor() && !hasActor {
		return Row{}, false, ErrNoActor
	}

	changed, pre, post, err := Diff(c.Pre, c.Post)
	if err != nil {
		return Row{}, false, err
	}
	if len(c.ChangedFields) > 0 {
		changed = c.ChangedFields
	}
	if c.Action == ActionUpdate && len(changed) == 0 {
		return Row{}, true, nil
	}

	row = Row{
		TenantID: c.TenantID, Kind: c.Kind, ObjectID: c.ID, Action: c.Action,
		PrechangeData: pre, PostchangeData: post, ChangedFields: changed, Source: src,
	}
	if row.ChangedFields == nil {
		row.ChangedFields = []string{}
	}
	if c.Related != nil {
		if _, ok := dcim.ParseObjectKind(string(c.Related.Kind)); !ok || c.Related.ID == uuid.Nil {
			return Row{}, false, fmt.Errorf("%w: related %q", ErrUnknownKind, c.Related.Kind)
		}
		rid := c.Related.ID
		row.RelatedKind, row.RelatedID = c.Related.Kind, &rid
	}
	if hasActor {
		id := actor.UserID
		row.UserID = &id
		row.UserName = actor.UserName
	}
	if rid, ok := RequestIDFrom(ctx); ok {
		row.RequestID = &rid
	}
	return row, false, nil
}

// Tx is a DBTX that is a transaction: *sql.Tx and *sqlx.Tx satisfy it, a
// *sql.DB or *sqlx.DB pool does not (no Commit/Rollback). [InTx] takes it so a
// change record cannot be written on its own connection by mistake — it would
// commit even when the change it describes rolled back.
type Tx interface {
	DBTX
	Commit() error
	Rollback() error
}

// InTx returns the Postgres recorder writing through tx — the caller's own
// transaction, already scoped to the tenant with set_tenant_context.
func InTx(tx Tx) Recorder { return txRecorder{tx: tx} }

type txRecorder struct{ tx DBTX }

func (r txRecorder) Record(ctx context.Context, c Change) error {
	row, skip, err := Prepare(ctx, c)
	if err != nil || skip {
		return err
	}
	if row.RelatedID == nil {
		if rk, rid, ok := DeriveRelated(ctx, r.tx, row); ok {
			row.RelatedKind, row.RelatedID = rk, &rid
		}
	}
	var relKind any
	if row.RelatedID != nil {
		relKind = string(row.RelatedKind)
	}
	_, err = r.tx.ExecContext(ctx, `
		INSERT INTO object_changes
		    (tenant_id, object_kind, object_id, action, prechange_data, postchange_data,
		     changed_fields, user_id, user_name, request_id, source, related_kind, related_id)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, NULLIF($9, ''), $10, $11, $12, $13)`,
		row.TenantID, string(row.Kind), row.ObjectID, string(row.Action),
		nullJSON(row.PrechangeData), nullJSON(row.PostchangeData),
		stringArray(row.ChangedFields), row.UserID, row.UserName, row.RequestID, string(row.Source),
		relKind, row.RelatedID)
	if err != nil {
		return fmt.Errorf("changes: insert object_changes: %w", err)
	}
	// Tell the request's collector (if any) which object changed. Only the key:
	// the notifier re-reads the committed row, which is also how it knows the
	// transaction committed.
	collectorFrom(ctx).note(row)
	return nil
}

func nullJSON(b json.RawMessage) any {
	if b == nil {
		return nil
	}
	return string(b)
}
