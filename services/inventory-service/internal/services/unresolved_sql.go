package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
)

// UnresolvedRepository is the Postgres unresolved.Repository over
// `unresolved_terminations` (ADR-0010 D6; DATA_MODEL §4). Every call is one
// tenant-scoped transaction on the RLS-subject pool.
//
// It is the first SQL repository for the substrate (row 0.3 shipped the
// contract and an in-memory one); the NetBox sync parks through it, and the
// intake rows reuse it.
type UnresolvedRepository struct{ db *sql.DB }

// NewUnresolvedRepository returns the repository over db.
func NewUnresolvedRepository(db *sql.DB) *UnresolvedRepository { return &UnresolvedRepository{db: db} }

const unresolvedColumns = `id, tenant_id, producer, origin_kind, origin_id, far_identity, intent, attributes,
	first_seen_at, last_seen_at, observation_count, expires_at`

func scanParked(r interface{ Scan(...any) error }) (unresolved.Parked, error) {
	var p unresolved.Parked
	var kind string
	var far, attrs []byte
	if err := r.Scan(&p.ID, &p.TenantID, &p.Producer, &kind, &p.OriginID, &far, &p.Intent, &attrs,
		&p.FirstSeenAt, &p.LastSeenAt, &p.ObservationCount, &p.ExpiresAt); err != nil {
		return p, err
	}
	p.OriginKind = dcim.ObjectKind(kind)
	if err := json.Unmarshal(far, &p.FarIdentity); err != nil {
		return p, err
	}
	if len(attrs) > 0 {
		if err := json.Unmarshal(attrs, &p.Attributes); err != nil {
			return p, err
		}
	}
	return p, nil
}

// Park implements unresolved.Repository: insert, or bump the existing row with
// the same producer, origin, intent and far identity.
func (r *UnresolvedRepository) Park(ctx context.Context, tenant uuid.UUID, t unresolved.Termination, seenAt time.Time) (unresolved.Parked, error) {
	var out unresolved.Parked
	if err := t.Validate(); err != nil {
		return out, err
	}
	if tenant == uuid.Nil {
		return out, unresolved.ErrInvalid
	}
	err := shareddb.WithTenantTx(ctx, r.db, tenant, func(tx *sql.Tx) error {
		var err error
		out, err = parkTx(ctx, tx, tenant, t, seenAt)
		return err
	})
	return out, err
}

// parkTx is Park on the caller's transaction (the cable intake parks inside
// its own, row 3.3).
func parkTx(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, t unresolved.Termination, seenAt time.Time) (unresolved.Parked, error) {
	if err := t.Validate(); err != nil {
		return unresolved.Parked{}, err
	}
	far, err := json.Marshal(t.FarIdentity)
	if err != nil {
		return unresolved.Parked{}, err
	}
	attrs := t.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	ab, err := json.Marshal(attrs)
	if err != nil {
		return unresolved.Parked{}, err
	}
	row := tx.QueryRowContext(ctx, `
		INSERT INTO public.unresolved_terminations AS u
			(tenant_id, producer, origin_kind, origin_id, far_identity, intent, attributes,
			 first_seen_at, last_seen_at, observation_count, expires_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8, $8, 1, $9)
		ON CONFLICT (tenant_id, producer, origin_kind, origin_id, intent, far_identity) DO UPDATE SET
			observation_count = u.observation_count + 1,
			last_seen_at = GREATEST(u.last_seen_at, EXCLUDED.last_seen_at),
			expires_at = GREATEST(u.last_seen_at, EXCLUDED.last_seen_at) + ($10 * interval '1 second'),
			attributes = EXCLUDED.attributes,
			updated_at = now()
		RETURNING `+unresolvedColumns,
		tenant, t.Producer, string(t.OriginKind), t.OriginID, string(far), t.Intent, string(ab),
		seenAt, seenAt.Add(unresolved.DefaultTTL), int64(unresolved.DefaultTTL/time.Second))
	return scanParked(row)
}

func (r *UnresolvedRepository) query(ctx context.Context, tenant uuid.UUID, q string, args ...any) ([]unresolved.Parked, error) {
	out := []unresolved.Parked{}
	err := shareddb.WithTenantTx(ctx, r.db, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			p, err := scanParked(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// ListByIdentityKeys implements unresolved.Repository.
func (r *UnresolvedRepository) ListByIdentityKeys(ctx context.Context, tenant uuid.UUID, keys []unresolved.IdentityKey) ([]unresolved.Parked, error) {
	if len(keys) == 0 {
		return []unresolved.Parked{}, nil
	}
	objs := make([]string, 0, len(keys))
	for _, k := range keys {
		b, err := json.Marshal(map[string]string{k.Key: k.Value})
		if err != nil {
			return nil, err
		}
		objs = append(objs, string(b))
	}
	return r.query(ctx, tenant, `SELECT `+unresolvedColumns+` FROM public.unresolved_terminations
		WHERE tenant_id = $1 AND far_identity @> ANY ($2::jsonb[])
		ORDER BY first_seen_at, id`, tenant, pq.Array(objs))
}

// List implements unresolved.Repository.
func (r *UnresolvedRepository) List(ctx context.Context, tenant uuid.UUID, after uuid.UUID, limit int) ([]unresolved.Parked, error) {
	if limit <= 0 {
		limit = 500
	}
	return r.query(ctx, tenant, `SELECT `+unresolvedColumns+` FROM public.unresolved_terminations
		WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`, tenant, after, limit)
}

// Delete implements unresolved.Repository.
func (r *UnresolvedRepository) Delete(ctx context.Context, tenant, id uuid.UUID) error {
	return shareddb.WithTenantTx(ctx, r.db, tenant, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM public.unresolved_terminations WHERE tenant_id = $1 AND id = $2`, tenant, id)
		return err
	})
}

// ExpireBefore implements unresolved.Repository.
func (r *UnresolvedRepository) ExpireBefore(ctx context.Context, tenant uuid.UUID, cutoff time.Time) (int, error) {
	n := 0
	err := shareddb.WithTenantTx(ctx, r.db, tenant, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM public.unresolved_terminations WHERE tenant_id = $1 AND expires_at < $2`, tenant, cutoff)
		if err != nil {
			return err
		}
		c, err := res.RowsAffected()
		n = int(c)
		return err
	})
	return n, err
}

var _ unresolved.Repository = (*UnresolvedRepository)(nil)
