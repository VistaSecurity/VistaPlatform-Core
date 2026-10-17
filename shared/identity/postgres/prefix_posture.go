package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// A prefix's DHCP posture, and who may state it (DCIM row 1.6).
//
// Identity reads one column of a prefix for it: `prefixes.dhcp_managed`
// (shared/identity/postgres/scope.go). NULL is "nobody has said". A person
// states it through the IPAM API, which writes the column directly; a
// collector — a controller that reported DHCP on a network, the inference from
// host observations — states it through [RecordPrefixPosture], which writes
// ONLY where nobody has said. The first statement stands, and a person who
// marked the network static is not overruled by the next run ( item 7).
//
// A prefix a person DECLARED but said nothing about DHCP on still takes a
// collector's statement ( C2): a controller that answered "this network
// hands out addresses" measured a fact the person did not, and leaving the
// prefix silent is how home networks ended up with leased addresses voting on
// identity.
//
// The 4.x segment kept each source's statement and an operator > measured >
// inferred precedence in a jsonb blob; a prefix has one column, and the
// first-statement rule is what it can carry without inventing state.

// PostureQuerier is the one method the writer needs. *sql.DB, *sql.Tx and
// *sqlx.Tx all satisfy it.
type PostureQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// RecordPrefixPosture states a prefix's DHCP posture on behalf of a collector.
// It reports whether the column was written: false when someone has already
// said, or when the tenant has no such prefix (not an error — the prefix may
// have been deleted since the caller resolved it).
func RecordPrefixPosture(ctx context.Context, q PostureQuerier, tenantID, prefixID string, dynamic bool) (bool, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE public.prefixes
		   SET dhcp_managed = $3, updated_at = now()
		 WHERE tenant_id = $1::uuid AND id::text = $2
		   AND dhcp_managed IS NULL`,
		tenantID, prefixID, dynamic)
	if err != nil {
		return false, fmt.Errorf("identity/postgres: record prefix posture: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
