package changes

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// ObjectChange is one stored change, as the change-log reader returns it.
type ObjectChange struct {
	ID             uuid.UUID        `json:"id"`
	ObjectKind     dcim.ObjectKind  `json:"object_kind"`
	ObjectID       uuid.UUID        `json:"object_id"`
	Action         Action           `json:"action"`
	PrechangeData  json.RawMessage  `json:"prechange_data"`
	PostchangeData json.RawMessage  `json:"postchange_data"`
	ChangedFields  []string         `json:"changed_fields"`
	UserID         *uuid.UUID       `json:"user_id"`
	UserName       *string          `json:"user_name"`
	RequestID      *uuid.UUID       `json:"request_id"`
	Source         Source           `json:"source"`
	RelatedKind    *dcim.ObjectKind `json:"related_kind"`
	RelatedID      *uuid.UUID       `json:"related_id"`
	// ObjectLabel is the object's name as the change recorded it (name,
	// hostname, address, …), so a table can say what changed without a join.
	ObjectLabel *string   `json:"object_label"`
	CreatedAt   time.Time `json:"created_at"`
}

// Filter narrows a change-log read. Zero values mean "any".
type Filter struct {
	TenantID   uuid.UUID
	ObjectKind dcim.ObjectKind
	ObjectID   uuid.UUID
	UserID     uuid.UUID
	Since      time.Time
	Until      time.Time
	Action     Action
	// Source matches exactly (`ui`), or a whole family when it ends in a colon
	// (`intake:`, `sync:`).
	Source Source
	// Query matches the object's recorded label, case-insensitively.
	Query string
	// UserQuery matches the acting user's recorded name or email, case-insensitively.
	UserQuery string
	// IncludeRelated also returns changes of objects that belong to ObjectID
	// (its interfaces, addresses, journal entries). Needs ObjectKind and ObjectID.
	IncludeRelated bool
	Limit          int
	Offset         int
}

// labelExpr is the object's name as the change recorded it.
const labelExpr = `COALESCE(
	postchange_data->>'name', prechange_data->>'name',
	postchange_data->>'hostname', prechange_data->>'hostname',
	postchange_data->>'address', prechange_data->>'address',
	postchange_data->>'prefix', prechange_data->>'prefix',
	postchange_data->>'cid', prechange_data->>'cid',
	postchange_data->>'slug', prechange_data->>'slug',
	postchange_data->>'label', prechange_data->>'label')`

const changeColumns = `id, object_kind, object_id, action, prechange_data, postchange_data, changed_fields,
		       user_id, user_name, request_id, source, related_kind, related_id, ` + labelExpr + `, created_at`

// where builds the predicate shared by List and the count.
func (f Filter) where() (string, []any) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.ObjectID != uuid.Nil && f.IncludeRelated && f.ObjectKind != "" {
		args = append(args, string(f.ObjectKind), f.ObjectID)
		n := len(args)
		where = append(where, fmt.Sprintf(
			"((object_kind = $%d AND object_id = $%d) OR (related_kind = $%d AND related_id = $%d))", n-1, n, n-1, n))
	} else {
		if f.ObjectKind != "" {
			add("object_kind = $%d", string(f.ObjectKind))
		}
		if f.ObjectID != uuid.Nil {
			add("object_id = $%d", f.ObjectID)
		}
	}
	if f.UserID != uuid.Nil {
		add("user_id = $%d", f.UserID)
	}
	if !f.Since.IsZero() {
		add("created_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("created_at < $%d", f.Until)
	}
	if f.Action != "" {
		add("action = $%d", string(f.Action))
	}
	if f.Source != "" {
		if strings.HasSuffix(string(f.Source), ":") {
			add("source LIKE $%d", string(f.Source)+"%")
		} else {
			add("source = $%d", string(f.Source))
		}
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		add("("+labelExpr+") ILIKE $%d", likeContains(q))
	}
	if q := strings.TrimSpace(f.UserQuery); q != "" {
		add("user_name ILIKE $%d", likeContains(q))
	}
	return strings.Join(where, " AND "), args
}

// likeContains is the ILIKE pattern for "contains s", with s's wildcards escaped.
func likeContains(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

// Get returns one change by id for tenant, or [ErrNotFound].
func Get(ctx context.Context, tx DBTX, tenant, id uuid.UUID) (ObjectChange, error) {
	if tenant == uuid.Nil {
		return ObjectChange{}, ErrNoTenant
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+changeColumns+` FROM object_changes WHERE tenant_id = $1 AND id = $2 LIMIT 1`, tenant, id)
	if err != nil {
		return ObjectChange{}, fmt.Errorf("changes: get: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out, err := scanChanges(rows)
	if err != nil {
		return ObjectChange{}, err
	}
	if len(out) == 0 {
		return ObjectChange{}, ErrNotFound
	}
	return out[0], nil
}

// ErrNotFound is returned by [Get] for an id the tenant has no change for.
var ErrNotFound = errors.New("changes: not found")

// List returns one page of tenant's changes, newest first, and the total that
// match. tx must already be scoped to the tenant (set_tenant_context); the
// explicit tenant predicate is the primary isolation layer, RLS the second.
func List(ctx context.Context, tx DBTX, f Filter) ([]ObjectChange, int, error) {
	if f.TenantID == uuid.Nil {
		return nil, 0, ErrNoTenant
	}
	cond, args := f.where()

	var total int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM object_changes WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("changes: count: %w", err)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s
		  FROM object_changes
		 WHERE %s
		 ORDER BY created_at DESC, id
		 LIMIT $%d OFFSET $%d`, changeColumns, cond, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("changes: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out, err := scanChanges(rows)
	return out, total, err
}

func scanChanges(rows *sql.Rows) ([]ObjectChange, error) {
	out := []ObjectChange{}
	for rows.Next() {
		var (
			oc       ObjectChange
			kind     string
			action   string
			source   string
			pre      []byte
			post     []byte
			fields   pq.StringArray
			userID   uuid.NullUUID
			userName sql.NullString
			reqID    uuid.NullUUID
			relKind  sql.NullString
			relID    uuid.NullUUID
			label    sql.NullString
		)
		if err := rows.Scan(&oc.ID, &kind, &oc.ObjectID, &action, &pre, &post, &fields,
			&userID, &userName, &reqID, &source, &relKind, &relID, &label, &oc.CreatedAt); err != nil {
			return nil, fmt.Errorf("changes: scan: %w", err)
		}
		oc.ObjectKind, oc.Action, oc.Source = dcim.ObjectKind(kind), Action(action), Source(source)
		if pre != nil {
			oc.PrechangeData = json.RawMessage(pre)
		}
		if post != nil {
			oc.PostchangeData = json.RawMessage(post)
		}
		oc.ChangedFields = []string(fields)
		if oc.ChangedFields == nil {
			oc.ChangedFields = []string{}
		}
		if userID.Valid {
			id := userID.UUID
			oc.UserID = &id
		}
		if userName.Valid {
			n := userName.String
			oc.UserName = &n
		}
		if reqID.Valid {
			id := reqID.UUID
			oc.RequestID = &id
		}
		if relKind.Valid && relID.Valid {
			k, id := dcim.ObjectKind(relKind.String), relID.UUID
			oc.RelatedKind, oc.RelatedID = &k, &id
		}
		if label.Valid {
			l := label.String
			oc.ObjectLabel = &l
		}
		out = append(out, oc)
	}
	return out, rows.Err()
}
