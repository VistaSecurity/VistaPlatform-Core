// Package agentcounts is the ONE place admin-service decides how many agents a
// tenant has, and of which kind.
//
// A tenant's `sensors` table holds two different things:
//
//   - sensors the customer deployed, and
//   - the rows the platform registers for every tenant (the tenant-create
//     trigger's Platform Discovery Sensor and Platform Device Interrogation
//     Agent) — the tenant's handle on an in-cluster service shared by every
//     tenant, not a deployment of theirs.
//
// Discovery agents are not in `sensors` at all; they are `device_agents` rows.
//
// Before this package every admin-service reader counted `sensors` its own
// way. The tenant drawer counted every live row, so a tenant with one sensor
// and one discovery agent read "3 sensors" (1 + the 2 platform rows, and the
// agent missing). The fleet-wide stats assumed `active tenants * 2` platform
// rows rather than counting them, and the onboarding checklist ticked
// "first sensor deployed" for a tenant that had deployed nothing, because the
// platform rows exist from the moment the tenant does.
//
// The platform-managed test is models.Sensor.IsPlatformManaged in
// sensor-manager and isPlatformManaged in frontend-v2's agent-fleet.ts:
// platform = 'platform' OR the 'system' tag. Either marker alone identifies
// the row, so they are ORed. `profile` is deliberately not consulted — a
// customer may legitimately deploy a sensor with the `discovery` or
// `device_interrogation` profile. `tags` is nullable, and 'system' = ANY(NULL)
// is NULL, which NOT keeps NULL — so an untagged customer sensor would drop out
// of BOTH buckets without the COALESCE.
//
// All counts are LIVE rows (deleted_at IS NULL) belonging to LIVE tenants.
// A tenant soft-delete does not cascade into sensors/device_agents, so every
// platform-wide arm must join tenants explicitly or retired organizations keep
// inflating the fleet totals forever.
package agentcounts

import (
	"context"
	"database/sql"
	"strings"
)

// PlatformManagedSQL is the SQL form of the platform-managed test over a
// `sensors` row aliased `s`. Callers that need the predicate inside a larger
// query (a status breakdown, the licence snapshot) concatenate it; everything
// that only needs the three counts uses PerTenantSQL / ForTenant / Totals.
const PlatformManagedSQL = `(s.platform = 'platform' OR 'system' = ANY(COALESCE(s.tags, '{}'::text[])))`

// perTenant builds the derived table. tenantFilter, when non-empty, is a
// placeholder (e.g. "$1") that narrows both arms to one tenant, so the
// single-tenant readers do not aggregate every tenant's rows to keep one.
func perTenant(tenantFilter string) string {
	sensorWhere, agentWhere := "", ""
	if tenantFilter != "" {
		sensorWhere = " AND s.tenant_id = " + tenantFilter
		agentWhere = " AND d.tenant_id = " + tenantFilter
	}
	q := `
	SELECT k.tenant_id,
	       SUM(k.customer_sensors)::int AS customer_sensors,
	       SUM(k.device_agents)::int    AS device_agents,
	       SUM(k.platform_managed)::int AS platform_managed
	FROM (
		SELECT s.tenant_id,
		       COUNT(*) FILTER (WHERE NOT ` + PlatformManagedSQL + `) AS customer_sensors,
		       0::bigint AS device_agents,
		       COUNT(*) FILTER (WHERE ` + PlatformManagedSQL + `) AS platform_managed
		FROM sensors s
		JOIN tenants t ON t.id = s.tenant_id AND t.deleted_at IS NULL
		WHERE s.deleted_at IS NULL{{S}}
		GROUP BY s.tenant_id
		UNION ALL
		SELECT d.tenant_id, 0::bigint, COUNT(*), 0::bigint
		FROM device_agents d
		JOIN tenants t ON t.id = d.tenant_id AND t.deleted_at IS NULL
		WHERE d.deleted_at IS NULL{{D}}
		GROUP BY d.tenant_id
	) k
	GROUP BY k.tenant_id`
	return strings.NewReplacer("{{S}}", sensorWhere, "{{D}}", agentWhere).Replace(q)
}

// PerTenantSQL is a derived table with one row per tenant that has any live
// sensor or discovery agent:
//
//	tenant_id, customer_sensors, device_agents, platform_managed
//
// LEFT JOIN it on tenant_id and COALESCE each column to 0 — a tenant with no
// rows at all is absent from it.
var PerTenantSQL = perTenant("")

// OneTenantSQL is PerTenantSQL narrowed to the tenant bound to $1.
var OneTenantSQL = perTenant("$1")

// Counts is one tenant's (or the platform's) agent estate.
type Counts struct {
	// CustomerSensors are the live sensors the customer deployed.
	CustomerSensors int
	// DeviceAgents are the live discovery (interrogation) agents — every
	// device_agents row is customer-deployed; the platform's in-cluster
	// interrogation agent is a `sensors` row and counts as PlatformManaged.
	DeviceAgents int
	// PlatformManaged are the live `sensors` rows the platform registered for
	// the tenant. Reported separately, never added to the customer's agents.
	PlatformManaged int
}

// CustomerAgents is what the customer deployed: sensors plus discovery agents
// ("agents" is the collective term). Platform-managed rows are not included.
func (c Counts) CustomerAgents() int { return c.CustomerSensors + c.DeviceAgents }

// rowQuerier is satisfied by *sql.DB and *sql.Tx.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ForTenant counts one tenant's live agents. Run it on a handle that can see
// the tenant's rows: a WithTenantTx transaction or the bypass pool.
func ForTenant(ctx context.Context, q rowQuerier, tenantID string) (Counts, error) {
	var c Counts
	err := q.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(c.customer_sensors), 0)::int,
		       COALESCE(SUM(c.device_agents), 0)::int,
		       COALESCE(SUM(c.platform_managed), 0)::int
		FROM (`+OneTenantSQL+`) c`, tenantID,
	).Scan(&c.CustomerSensors, &c.DeviceAgents, &c.PlatformManaged)
	return c, err
}

// Totals counts every live agent row across all tenants. Cross-tenant: run it
// on the bypass pool, or RLS narrows it to whatever tenant context is set.
func Totals(ctx context.Context, q rowQuerier) (Counts, error) {
	var c Counts
	err := q.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(c.customer_sensors), 0)::int,
		       COALESCE(SUM(c.device_agents), 0)::int,
		       COALESCE(SUM(c.platform_managed), 0)::int
		FROM (`+PerTenantSQL+`) c`,
	).Scan(&c.CustomerSensors, &c.DeviceAgents, &c.PlatformManaged)
	return c, err
}
