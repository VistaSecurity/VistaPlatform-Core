package unresolved

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryRepository is the in-memory [Repository]: the reference
// implementation dcimtest.RunResolverContract is written against, and the one
// the resolver's own tests use. Safe for concurrent use.
type MemoryRepository struct {
	mu   sync.Mutex
	rows map[uuid.UUID]Parked
}

// NewMemoryRepository returns an empty repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{rows: map[uuid.UUID]Parked{}}
}

// identityKey is the uniqueness the SQL table's unique index states:
// producer, origin, intent and far identity, within a tenant.
func identityKey(tenant uuid.UUID, t Termination) string {
	far, _ := json.Marshal(t.FarIdentity) // map keys marshal sorted: canonical
	var b bytes.Buffer
	b.WriteString(tenant.String())
	for _, s := range []string{t.Producer, string(t.OriginKind), t.OriginID.String(), t.Intent, string(far)} {
		b.WriteByte(0)
		b.WriteString(s)
	}
	return b.String()
}

func clone(p Parked) Parked {
	p.FarIdentity = maps.Clone(p.FarIdentity)
	p.Attributes = maps.Clone(p.Attributes)
	return p
}

// Park implements [Repository].
func (r *MemoryRepository) Park(_ context.Context, tenant uuid.UUID, t Termination, seenAt time.Time) (Parked, error) {
	if err := t.Validate(); err != nil {
		return Parked{}, err
	}
	if tenant == uuid.Nil {
		return Parked{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := identityKey(tenant, t)
	for id, p := range r.rows {
		if identityKey(p.TenantID, p.Termination) != key {
			continue
		}
		p.ObservationCount++
		if seenAt.After(p.LastSeenAt) {
			p.LastSeenAt = seenAt
		}
		p.ExpiresAt = p.LastSeenAt.Add(DefaultTTL)
		p.Attributes = maps.Clone(t.Attributes)
		r.rows[id] = p
		return clone(p), nil
	}
	p := Parked{
		ID: uuid.New(), TenantID: tenant, Termination: t,
		FirstSeenAt: seenAt, LastSeenAt: seenAt, ObservationCount: 1, ExpiresAt: seenAt.Add(DefaultTTL),
	}
	p = clone(p)
	r.rows[p.ID] = p
	return clone(p), nil
}

func (r *MemoryRepository) sorted(tenant uuid.UUID, keep func(Parked) bool) []Parked {
	out := []Parked{}
	for _, p := range r.rows {
		if p.TenantID == tenant && keep(p) {
			out = append(out, clone(p))
		}
	}
	return out
}

// ListByIdentityKeys implements [Repository].
func (r *MemoryRepository) ListByIdentityKeys(_ context.Context, tenant uuid.UUID, keys []IdentityKey) ([]Parked, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sorted(tenant, func(p Parked) bool {
		for _, k := range keys {
			if v, ok := p.FarIdentity[k.Key]; ok && v == k.Value {
				return true
			}
		}
		return false
	})
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeenAt.Equal(out[j].FirstSeenAt) {
			return out[i].FirstSeenAt.Before(out[j].FirstSeenAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

// List implements [Repository].
func (r *MemoryRepository) List(_ context.Context, tenant uuid.UUID, after uuid.UUID, limit int) ([]Parked, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sorted(tenant, func(p Parked) bool { return after == uuid.Nil || p.ID.String() > after.String() })
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Delete implements [Repository].
func (r *MemoryRepository) Delete(_ context.Context, tenant, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.rows[id]; ok && p.TenantID == tenant {
		delete(r.rows, id)
	}
	return nil
}

// ExpireBefore implements [Repository].
func (r *MemoryRepository) ExpireBefore(_ context.Context, tenant uuid.UUID, cutoff time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, p := range r.rows {
		if p.TenantID == tenant && p.ExpiresAt.Before(cutoff) {
			delete(r.rows, id)
			n++
		}
	}
	return n, nil
}
