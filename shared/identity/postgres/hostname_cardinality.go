package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// hostnameCardinalitySQL is the whole query, a constant so the index test
// EXPLAINs exactly what production runs.
const hostnameCardinalitySQL = `
	SELECT count(DISTINCT i.asset_id)
	FROM public.asset_identifiers i
	JOIN public.assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id
	WHERE i.tenant_id = $1 AND i.kind = 'hostname' AND i.value = $2
	  AND a.deleted_at IS NULL
	  AND a.asset_status NOT IN ('archived', 'denied')
	  AND NULLIF(a.metadata->>'merged_into', '') IS NULL`

// HostnameCardinality implements [identity.Repository]: the number of distinct
// live assets in the tenant carrying a `hostname` identifier with this value, in
// any scope ( B2).
//
// The argument is folded to the stored spelling in Go (lower case, one trailing
// dot dropped — what [identity.Normalize] writes for a hostname) and compared
// with plain equality rather than `lower(value) = $2`. That is what keeps the
// query on `asset_identifiers_value_uniq (tenant_id, kind, value,
// coalesce(scope, ”))`: tenant_id, kind and value are its first three columns,
// so the count is an index range scan over just the rows for this name, whatever
// the scope. A function on the column would turn it into a scan of every
// hostname the tenant has. No new index is needed.
//
// Live is the definition merge approvals use: not deleted, not archived, not
// denied, and not merged away. A retired record stops testifying that a name is
// common. The join is on the assets primary key.
func (r *Repository) HostnameCardinality(ctx context.Context, tenantID, value string) (int, error) {
	want := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if want == "" {
		return 0, nil
	}
	var n int
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, hostnameCardinalitySQL, tenantID, want).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("identity/postgres: hostname cardinality: %w", err)
	}
	return n, nil
}
