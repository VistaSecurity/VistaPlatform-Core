package dcimfixture

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// The circuits populator (DCIM BUILD_PLAN row 4.1).
//
// CircuitProviders providers, each with one provider network, and
// CircuitsPerSite circuits per site (cid CKT-<site>-<n>, round-robin over the
// providers and the platform circuit types seed.sql ships, falling back to a
// tenant type when the database is unseeded), each with an A end and a Z end
// on its provider's network. The A end has no target yet (a termination with
// no target is valid, as in NetBox); the sites row gives it one.
const (
	CircuitProviders = 5
	CircuitsPerSite  = 2
)

// Circuits is how many circuits the populator writes at scale s.
func Circuits(s Scale) int { return s.Sites * CircuitsPerSite }

func populateCircuits(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if e.Scale.Sites == 0 {
		return -1, nil
	}
	provs := make([]uuid.UUID, CircuitProviders)
	nets := make([]uuid.UUID, CircuitProviders)
	for p := 0; p < CircuitProviders; p++ {
		name := fmt.Sprintf("Fixture Provider %d", p+1)
		e.Witness(name)
		if err := tx.QueryRowContext(ctx, `INSERT INTO providers (tenant_id, name, slug, asns) VALUES ($1, $2, $3, ARRAY[$4::bigint])
			RETURNING id`, e.Tenant, name, fmt.Sprintf("fixture-provider-%d", p+1), 64500+p).Scan(&provs[p]); err != nil {
			return 0, err
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO provider_networks (tenant_id, provider_id, name) VALUES ($1, $2, $3) RETURNING id`,
			e.Tenant, provs[p], name+" core").Scan(&nets[p]); err != nil {
			return 0, err
		}
	}
	var types []uuid.UUID
	rows, err := tx.QueryContext(ctx, `SELECT id FROM circuit_types WHERE tenant_id IS NULL ORDER BY slug`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		types = append(types, id)
	}
	_ = rows.Close()
	if len(types) == 0 {
		var id uuid.UUID
		if err := tx.QueryRowContext(ctx, `INSERT INTO circuit_types (tenant_id, name, slug) VALUES ($1, 'Fixture Circuit Type', 'fixture-circuit-type') RETURNING id`,
			e.Tenant).Scan(&id); err != nil {
			return 0, err
		}
		types = append(types, id)
	}
	n := Circuits(e.Scale)
	ids := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		cid := fmt.Sprintf("CKT-%04d-%d", i/CircuitsPerSite, i%CircuitsPerSite+1)
		e.Witness(cid)
		if err := tx.QueryRowContext(ctx, `INSERT INTO circuits (tenant_id, cid, provider_id, type_id, commit_rate_kbps)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, e.Tenant, cid, provs[i%CircuitProviders], types[i%len(types)],
			int64(100000*(1+i%10))).Scan(&ids[i]); err != nil {
			return 0, err
		}
	}
	err = copyRows(ctx, tx, "circuit_terminations",
		[]string{"tenant_id", "circuit_id", "term_side", "termination_kind", "termination_id", "port_speed_kbps"}, 2*n,
		func(j int) []any {
			i := j / 2
			if j%2 == 0 {
				return []any{e.Tenant, ids[i], "A", nil, nil, int64(1000000)}
			}
			return []any{e.Tenant, ids[i], "Z", "provider_network", nets[i%CircuitProviders], int64(1000000)}
		})
	return n, err
}
