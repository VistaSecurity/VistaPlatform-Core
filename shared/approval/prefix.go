package approval

// Prefix classification for auto-approval (DCIM row 1.4, ADR-0010 D3).
//
// `prefixes.auto_approve_discoveries` is evaluated "on the prefix that
// contains the observation's address (longest match within the VRF)" —
// DATA_MODEL §5. This file answers which prefix that is, from one read per
// request, with shared/dcim/ipam.LongestMatch: the rule IPAM itself uses.

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
)

// Prefix is one IPAM prefix as auto-approval reads it.
type Prefix struct {
	ID     uuid.UUID
	VRFID  *uuid.UUID
	Prefix netip.Prefix
}

// PrefixSet is a tenant's prefixes in the global VRF, read once. An
// observation carries no VRF until intake does (row 1.5), so only the global
// table can contain its address.
type PrefixSet struct {
	prefixes []Prefix
	bySpan   map[netip.Prefix][]Prefix
	spans    []netip.Prefix
}

// Querier is the one method LoadPrefixSet needs; a tenant-scoped *sql.Tx.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// LoadPrefixSet reads the tenant's live global-VRF prefixes. q must already be
// scoped to the tenant (RLS); the predicate repeats the tenant as the control.
func LoadPrefixSet(ctx context.Context, q Querier, tenantID uuid.UUID) (*PrefixSet, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, prefix::text FROM public.prefixes
		 WHERE tenant_id = $1 AND vrf_id IS NULL AND status NOT IN ('rejected', 'archived')
		 ORDER BY created_at, id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("approval: read prefixes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ps []Prefix
	for rows.Next() {
		var (
			id  uuid.UUID
			txt string
		)
		if err := rows.Scan(&id, &txt); err != nil {
			return nil, fmt.Errorf("approval: scan prefix: %w", err)
		}
		p, err := ipam.ParsePrefix(txt)
		if err != nil {
			continue
		}
		ps = append(ps, Prefix{ID: id, Prefix: p})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return NewPrefixSet(ps), nil
}

// NewPrefixSet builds a set from prefixes already in hand.
func NewPrefixSet(ps []Prefix) *PrefixSet {
	s := &PrefixSet{prefixes: ps, bySpan: map[netip.Prefix][]Prefix{}}
	for _, p := range ps {
		n := ipam.Normalize(p.Prefix)
		if _, seen := s.bySpan[n]; !seen {
			s.spans = append(s.spans, n)
		}
		s.bySpan[n] = append(s.bySpan[n], p)
	}
	return s
}

// Match is the prefix containing the address, longest match first. Nil when
// the address is not one, is in no prefix, or the longest match is ambiguous
// (two prefixes with one CIDR in the global table — picking one would be a
// guess, and auto-approval does not guess).
func (s *PrefixSet) Match(address string) *Prefix {
	if s == nil || len(s.spans) == 0 {
		return nil
	}
	a, err := ipam.ParseAddr(strings.TrimSpace(address))
	if err != nil || !a.IsValid() {
		return nil
	}
	best, ok := ipam.LongestMatch(a, s.spans)
	if !ok {
		return nil
	}
	if m := s.bySpan[best]; len(m) == 1 {
		p := m[0]
		return &p
	}
	return nil
}

// Apply records the prefix containing the address on the classification.
func (c *Classification) Apply(p *Prefix) {
	if c == nil || p == nil {
		return
	}
	id := p.ID
	c.PrefixID = &id
	c.VRFID = p.VRFID
}
