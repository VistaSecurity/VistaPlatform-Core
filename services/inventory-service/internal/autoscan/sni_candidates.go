package autoscan

// The names an asset is known by, offered to a scan as SNI candidates.
//
// A scan targets an ADDRESS, so it sends a TLS server no name; a server that
// routes by name (a reverse proxy, a virtual host) then ends the handshake with
// an alert and the scan records "TLS, handshake refused". When the asset behind
// the address is known, its names are the ones worth offering: the server names
// observed on its endpoints (the strongest evidence, they were seen on the
// wire), then its fully qualified identifiers, then its hostname.
//
// What this does NOT do: resolve a name, or let a name choose where the scan
// connects. The names ride along on a job whose target is the address; the
// engine presents them only to a TLS port that refused the nameless attempt
// (shared/discovery SNICandidates), at most MaxSNICandidates of them.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
)

// SNI name ranks: lower is offered first.
const (
	sniRankEndpoint  = 0 // a server name seen on one of the asset's endpoints
	sniRankFQDN      = 1 // a fully qualified identifier
	sniRankDotted    = 2 // the hostname, when it is dotted
	sniRankShortName = 3 // a single-label name: rarely what a server routes on
)

type sniName struct {
	name string
	rank int
}

// rankSNINames orders the names for one asset and reduces them to what a scan
// may present: synthetic names (a lease written as a name, a UUID, `none-3`)
// are left out, then SanitizeSNICandidates drops anything that is not a DNS
// name, removes duplicates and keeps the first MaxSNICandidates.
func rankSNINames(in []sniName) []string {
	sort.SliceStable(in, func(i, j int) bool { return in[i].rank < in[j].rank })
	names := make([]string, 0, len(in))
	for _, n := range in {
		if !hostnamequality.IsIdentityName(n.name) {
			continue
		}
		names = append(names, n.name)
	}
	return shareddisc.SanitizeSNICandidates(names)
}

// SNICandidates returns, per asset, the names to offer a TLS port that refuses
// a nameless handshake. An asset with none is absent from the map.
func (s *Store) SNICandidates(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	return LoadSNICandidates(ctx, s.db, tenantID, assetIDs)
}

// LoadSNICandidates is SNICandidates for a caller that holds only the pool.
func LoadSNICandidates(ctx context.Context, db *database.DB, tenantID uuid.UUID, assetIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	byAsset := map[uuid.UUID][]sniName{}
	// RLS-scoped read over assets, asset_identifiers and asset_endpoints.
	err := database.WithTenantTx(ctx, db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryxContext(ctx, `
			SELECT asset_id, name, rank FROM (
			  SELECT asset_id, unnest(sni) AS name, 0 AS rank
			    FROM asset_endpoints
			   WHERE tenant_id = $1 AND asset_id = ANY($2) AND sni IS NOT NULL AND status <> 'closed'
			  UNION ALL
			  SELECT asset_id, value, CASE kind WHEN 'fqdn' THEN 1 ELSE 3 END
			    FROM asset_identifiers
			   WHERE tenant_id = $1 AND asset_id = ANY($2) AND kind IN ('fqdn', 'hostname')
			  UNION ALL
			  SELECT id, hostname, 2
			    FROM assets
			   WHERE tenant_id = $1 AND id = ANY($2) AND hostname IS NOT NULL AND deleted_at IS NULL
			) n WHERE name IS NOT NULL AND name <> ''`,
			tenantID, pq.Array(assetIDs))
		if err != nil {
			return fmt.Errorf("read the asset names: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var n sniName
			if err := rows.Scan(&id, &n.name, &n.rank); err != nil {
				return fmt.Errorf("scan an asset name: %w", err)
			}
			// A short name ranks last whatever table it came from.
			if !strings.Contains(strings.TrimSuffix(n.name, "."), ".") && n.rank > sniRankEndpoint {
				n.rank = sniRankShortName
			}
			byAsset[id] = append(byAsset[id], n)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID][]string, len(byAsset))
	for id, names := range byAsset {
		if ranked := rankSNINames(names); len(ranked) > 0 {
			out[id] = ranked
		}
	}
	return out, nil
}

// MergeSNICandidates folds the names of several assets that share one address
// into the one list that address's target carries: in order, deduplicated,
// bounded. Pure, so the bound is pinned by a test.
func MergeSNICandidates(lists ...[]string) []string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	return shareddisc.SanitizeSNICandidates(all)
}
