// Package services: saved views — named query strings (ADR-0006 D2).
package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// A saved view is a NAMED QUERY STRING and nothing else.
//
// That is the whole design (ADR-0006 D2): the facet rail writes a query, the
// user names it, and the name is how they get back to it. It is also the
// beginner's surface for the language — a user learns it by reading what their
// own views say, which is why the query is stored and shown rather than being
// decomposed into a filter object the UI reassembles.
//
// The query is validated at WRITE time and stored in canonical form. Validating
// on write rather than on read means a view cannot be saved that will fail when
// somebody opens it, and canonical form means two spellings of one predicate
// are one row a diff can match.

// SavedView is one stored view.
type SavedView struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description,omitempty" db:"description"`
	// Target is the collection the query is a predicate over (§4.1), carried
	// out of band because the URL and the endpoint already say it.
	Target string `json:"target" db:"target"`
	// Query is the canonical form of what the user saved.
	Query       string    `json:"query" db:"query"`
	OwnerUserID uuid.UUID `json:"owner_user_id" db:"owner_user_id"`
	// OwnerName is who to credit in the list. A shared view carried only an
	// owner UUID, so the rail could say "shared" and never by whom — and the
	// one question a person asks about a shared view they did not make is
	// whose it is. Empty when the user row is gone; nil-safe rather than
	// inventing a name.
	OwnerName string `json:"owner_name,omitempty" db:"owner_name"`
	IsShared  bool   `json:"is_shared" db:"is_shared"`
	CreatedAt string `json:"created_at" db:"created_at"`
	UpdatedAt string `json:"updated_at" db:"updated_at"`
}

// SavedViewInput is the create/update body.
type SavedViewInput struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
	Target      string  `json:"target"`
	Query       string  `json:"query"`
	IsShared    *bool   `json:"is_shared"`
}

// ErrSavedViewNotFound is returned when no view with that id is visible to the
// caller — which covers both "no such row" and "somebody else's private view".
// One error for both, so probing ids cannot tell the two apart.
var ErrSavedViewNotFound = errors.New("saved view not found")

// ErrSavedViewDuplicate is a name that is already taken.
//
// Which SCOPE it is taken in depends on the view: a private view's name has to
// be unique to its owner (two people may each keep one called "Mine"), and a
// SHARED view's has to be unique tenant-wide, because a shared view is a name
// everyone reads off one list and two "Production"s there are
// indistinguishable. The error text used to promise the tenant-wide rule for
// both while only the per-owner constraint existed.
var ErrSavedViewDuplicate = errors.New("a saved view with that name already exists")

// SavedViewService stores and validates saved views.
type SavedViewService struct {
	db *database.DB
}

// NewSavedViewService constructs the service.
func NewSavedViewService(db *database.DB) *SavedViewService {
	return &SavedViewService{db: db}
}

const savedViewColumns = `sv.id, sv.tenant_id, sv.name, sv.description, sv.target, sv.query,
	sv.owner_user_id, sv.is_shared,
	COALESCE(NULLIF(TRIM(CONCAT_WS(' ', u.first_name, u.last_name)), ''), u.email, '') AS owner_name,
	to_char(sv.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
	to_char(sv.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at`

// savedViewFrom joins the owner so a shared view can say WHOSE it is. LEFT, so
// a view whose owner has been deleted still lists — with an empty owner_name,
// which is honest, rather than vanishing.
const savedViewFrom = ` FROM saved_views sv LEFT JOIN users u ON u.id = sv.owner_user_id`

// visibleToUser is the product rule: a view is yours, or it is shared with the
// tenant. RLS has already narrowed to the tenant; this narrows within it, and
// is a WHERE rather than a policy because "mine" is a product decision and not
// an isolation control — conflating the two is how a product rule ends up
// looking like a security boundary nobody can audit.
const visibleToUser = `(sv.owner_user_id = $2 OR sv.is_shared = true)`

// List returns the views visible to one user for one target, shared ones
// included. An empty target lists every target.
func (s *SavedViewService) List(ctx context.Context, tenantID, userID uuid.UUID, target string) ([]SavedView, error) {
	q := `SELECT ` + savedViewColumns + savedViewFrom + ` WHERE sv.tenant_id = $1 AND ` + visibleToUser
	args := []any{tenantID, userID}
	if t := strings.TrimSpace(target); t != "" {
		args = append(args, strings.ToLower(t))
		q += fmt.Sprintf(" AND sv.target = $%d", len(args))
	}
	q += " ORDER BY sv.is_shared, sv.name"

	var out []SavedView
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.SelectContext(ctx, &out, q, args...)
	})
	if err != nil {
		return nil, fmt.Errorf("list saved views: %w", err)
	}
	if out == nil {
		out = []SavedView{}
	}
	return out, nil
}

// Get returns one view if the user may see it.
func (s *SavedViewService) Get(ctx context.Context, tenantID, userID, id uuid.UUID) (*SavedView, error) {
	var v SavedView
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.GetContext(ctx, &v,
			`SELECT `+savedViewColumns+savedViewFrom+`
			 WHERE sv.tenant_id = $1 AND `+visibleToUser+` AND sv.id = $3`,
			tenantID, userID, id)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSavedViewNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get saved view: %w", err)
	}
	return &v, nil
}

// Create validates the query and stores the view.
//
// The returned QueryError carries §10's diagnostics, so a caller can answer 400
// with the span and the suggestion rather than "invalid query".
func (s *SavedViewService) Create(ctx context.Context, tenantID, userID uuid.UUID, in SavedViewInput) (*SavedView, error) {
	target, canonical, err := normalizeSavedView(in)
	if err != nil {
		return nil, err
	}
	shared := in.IsShared != nil && *in.IsShared

	// RETURNING id, then read the row back through Get.
	//
	// The select list joins `users` for the owner's display name, and RETURNING
	// cannot join — so the alternative would be a SECOND column list here that
	// omits it, which is how the create path and the read path come to disagree
	// about a view's shape. One extra round trip on a write nobody does in a
	// loop, in exchange for one spelling.
	var id uuid.UUID
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.GetContext(ctx, &id, `
			INSERT INTO saved_views (tenant_id, name, description, target, query, owner_user_id, is_shared)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
			tenantID, strings.TrimSpace(in.Name), in.Description, target, canonical, userID, shared)
	})
	if isUniqueViolation(err) {
		return nil, ErrSavedViewDuplicate
	}
	if err != nil {
		return nil, fmt.Errorf("create saved view: %w", err)
	}
	return s.Get(ctx, tenantID, userID, id)
}

// Update rewrites a view the caller OWNS. A shared view is editable only by its
// owner: sharing is publishing, not handing over.
func (s *SavedViewService) Update(ctx context.Context, tenantID, userID, id uuid.UUID, in SavedViewInput) (*SavedView, error) {
	target, canonical, err := normalizeSavedView(in)
	if err != nil {
		return nil, err
	}

	var updated uuid.UUID
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.GetContext(ctx, &updated, `
			UPDATE saved_views
			   SET name = $4, description = $5, target = $6, query = $7,
			       is_shared = COALESCE($8, is_shared)
			 WHERE tenant_id = $1 AND owner_user_id = $2 AND id = $3
			 RETURNING id`,
			tenantID, userID, id, strings.TrimSpace(in.Name), in.Description, target, canonical, in.IsShared)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSavedViewNotFound
	}
	if isUniqueViolation(err) {
		return nil, ErrSavedViewDuplicate
	}
	if err != nil {
		return nil, fmt.Errorf("update saved view: %w", err)
	}
	return s.Get(ctx, tenantID, userID, updated)
}

// Delete removes a view the caller owns.
func (s *SavedViewService) Delete(ctx context.Context, tenantID, userID, id uuid.UUID) error {
	var n int64
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		res, e := tx.ExecContext(ctx,
			`DELETE FROM saved_views WHERE tenant_id = $1 AND owner_user_id = $2 AND id = $3`,
			tenantID, userID, id)
		if e != nil {
			return e
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete saved view: %w", err)
	}
	if n == 0 {
		return ErrSavedViewNotFound
	}
	return nil
}

// normalizeSavedView validates the target and the query and returns the target
// lowercased and the query in canonical form.
func normalizeSavedView(in SavedViewInput) (target, canonical string, err error) {
	if strings.TrimSpace(in.Name) == "" {
		return "", "", errors.New("a saved view needs a name")
	}
	target = strings.ToLower(strings.TrimSpace(in.Target))
	if target == "" {
		target = QueryTargetAsset
	}
	if !savedViewTargetExists(target) {
		return "", "", fmt.Errorf("unknown target %q: a saved view is a predicate over one of %s",
			target, strings.Join(savedViewTargets(), ", "))
	}
	canonical, err = CheckAssetQuery(in.Query, target)
	if err != nil {
		return "", "", err
	}
	return target, canonical, nil
}

// savedViewTargets lists the collections a view may be saved over.
//
// The table-less targets are excluded: `observation` is evaluated in the
// identification engine against an in-flight discovery and `measurement`
// against a scalar a compliance rule extracted, so neither names rows a view
// could open. Offering them would produce a view that validates and then has
// nothing to show.
func savedViewTargets() []string {
	var out []string
	for _, t := range AssetQueryCatalog().Targets() {
		if t.InMemory {
			continue
		}
		out = append(out, t.Name)
	}
	return out
}

func savedViewTargetExists(name string) bool {
	t, ok := catalog.FindTarget(AssetQueryCatalog(), name)
	return ok && !t.InMemory
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "23505")
}
