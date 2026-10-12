package dispatchguard

import (
	"context"
	"database/sql"
	"net/netip"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// collectorAddressesSQL is the ONE definition of "an address that belongs to a
// collector": every agent_addresses row of the named sensors, whatever its
// interface name or how stale its last report is. A collector's address stays
// its own when the interface is not a DNS interface (a Windows sensor reports
// none), when it is a docker bridge or a secondary NIC, and when the report has
// lapsed since the work was planned.
//
// The dispatch guard uses it to REFUSE a probe target, and the enrichment
// planner uses it (through CollectorAddresses) to avoid ever PLANNING one. They
// used to carry two copies of the rule, the planner's narrower, so the planner
// kept queueing probes the guard then refused, forever.
const collectorAddressesSQL = `SELECT address FROM agent_addresses WHERE sensor_id = ANY($1::uuid[])`

// CollectorAddressesQueryer is the read side CollectorAddresses needs; *sql.DB,
// *sql.Tx and *sqlx.Tx all satisfy it.
type CollectorAddressesQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// CollectorAddresses returns every address recorded for the given sensors, as
// host prefixes. Unparseable rows are skipped.
func CollectorAddresses(ctx context.Context, q CollectorAddressesQueryer, sensors ...uuid.UUID) ([]netip.Prefix, error) {
	if len(sensors) == 0 {
		return nil, nil
	}
	ids := make(pq.StringArray, len(sensors))
	for i, id := range sensors {
		ids[i] = id.String()
	}
	rows, err := q.QueryContext(ctx, `SELECT host(c.address) FROM (`+collectorAddressesSQL+`) c`, ids)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []netip.Prefix
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, rows.Err()
}

// TenantCollectorAddresses returns every address of every non-deleted sensor of
// the tenant, live or not.
//
// This is the planner's exclusion set, deliberately a SUPERSET of what the
// guard refuses (the guard checks only the dispatched executor and the
// observer, and the planner picks the executor after this runs): probing any
// of the tenant's own collectors is never what an unattended enrichment wants,
// and restricting to live ones would reopen the gap whenever a heartbeat lapses
// between planning and dispatch.
func TenantCollectorAddresses(ctx context.Context, q CollectorAddressesQueryer, tenant uuid.UUID) ([]netip.Prefix, error) {
	rows, err := q.QueryContext(ctx, `SELECT id FROM sensors WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	return CollectorAddresses(ctx, q, ids...)
}
