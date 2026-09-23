package services

// The tenant-wide network map (feature spec `network-crypto-map`).
//
// The data behind Inventory → Map → Network: one row per asset, placed by site
// and network segment, carrying a SUMMARY of the crypto its services serve —
// enough to colour a device and to group devices by a shared crypto trait, and
// no more. The per-service detail the exploded view shows is read on demand from
// the asset's own endpoints / crypto configurations / certificates reads, so
// this response never grows a second copy of those shapes.
//
// It is the sibling of GetTopology (asset_topology.go) and follows the same
// rules: one `database.WithTenantTx` with explicit tenant predicates on top of
// RLS, a hard cap reported as `truncated` beside an INDEPENDENT total, and the
// site expression shared through topologySiteSQL so the map, the topology tree
// and the `site` facet can never name a site differently.
//
// # No second opinion about an algorithm
//
// The crypto summary is the `algorithms` catalogue's assessment (strength,
// is_pqc) of the components linked to the asset's configurations, plus the
// partition the ONE PQC classifier (cryptoassess.PQCClassCTE + pqcPartitionSQL)
// computes. The map never ships raw algorithm strings for the client to judge.
//
// # Unknown is not zero
//
// `risk_assessed` travels beside `risk_score`. A stored 0 with an empty
// `risk_assessed_by` means nothing has assessed the asset, not that it is safe,
// and the map draws it neutral rather than green (spec D4).

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// NetworkMapAssetCap bounds the assets one network-map response carries.
//
// A REFUSAL TO GUESS rather than a tuning knob, like TopologyNodeCap: past the
// cap the answer reports itself truncated with the real total, never silently
// shortened. The order is risk first, so what a capped map loses is the
// low-risk tail — and 5000 device tiles is already past what any of the four
// views can draw legibly on one screen.
const NetworkMapAssetCap = 5000

// networkMapStatuses are the lifecycle states drawn on the map (spec D5):
// pending-approval assets are drawn (dashed), archived and denied are not.
var networkMapStatuses = []string{"monitoring", "pending_approval"}

// NetworkMapSegment is one active network segment.
type NetworkMapSegment struct {
	SegmentID   uuid.UUID `json:"segment_id" db:"segment_id"`
	Name        string    `json:"name" db:"name"`
	Value       string    `json:"value" db:"value"`
	SegmentType string    `json:"segment_type" db:"segment_type"`
}

// NetworkMapComponent is one DISTINCT catalogue component linked to any of an
// asset's live crypto configurations.
type NetworkMapComponent struct {
	AlgorithmType string `json:"algorithm_type" db:"algorithm_type"`
	Name          string `json:"name" db:"name"`
	// Strength is the catalogue strength; "" when the row records none — the
	// same rule as CryptoComponentAssessment.strength.
	Strength string `json:"strength" db:"strength"`
	IsPQC    bool   `json:"is_pqc" db:"is_pqc"`
	// Observed is true when at least one configuration USES it (a junction
	// link with is_inferred false); false when it is only offered or derived.
	Observed bool `json:"observed" db:"observed"`
}

// NetworkMapPQC is the asset's live configurations partitioned by the one PQC
// classifier. The four counts sum to the asset's live configuration count.
type NetworkMapPQC struct {
	NeedsMigration int `json:"needs_migration" db:"needs_migration"`
	PQCReady       int `json:"pqc_ready" db:"pqc_ready"`
	SymmetricSafe  int `json:"symmetric_safe" db:"symmetric_safe"`
	Unclassified   int `json:"unclassified" db:"unclassified"`
}

// NetworkMapCrypto summarises the crypto the asset's live configurations carry.
type NetworkMapCrypto struct {
	// Components is sorted by algorithm_type then name, and never nil. Empty
	// means nothing resolved against the catalogue — not assessed, not clean.
	Components []NetworkMapComponent `json:"components"`
	PQC        NetworkMapPQC         `json:"pqc"`
	// CertsExpiring90d counts distinct certificates referenced by the asset's
	// live configurations whose not_after is within 90 days — expired included.
	CertsExpiring90d int `json:"certs_expiring_90d"`
}

// NetworkMapAsset is one device on the map.
type NetworkMapAsset struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName string    `json:"display_name"`
	ClassKey    string    `json:"class_key"`
	// Address is the primary address without a prefix length; omitted when none.
	Address string `json:"address,omitempty"`
	// SegmentID is null for an unsegmented asset. Always present on the wire.
	SegmentID   *uuid.UUID `json:"segment_id"`
	Site        string     `json:"site"`
	AssetStatus string     `json:"asset_status"`
	RiskScore   int        `json:"risk_score"`
	// RiskAssessed is false when nothing has assessed the asset. A 0 score with
	// this false is "not assessed", never "safe".
	RiskAssessed       bool             `json:"risk_assessed"`
	CloudAccount       string           `json:"cloud_account,omitempty"`
	CloudRegion        string           `json:"cloud_region,omitempty"`
	ServiceCount       int              `json:"service_count"`
	CryptoServiceCount int              `json:"crypto_service_count"`
	Crypto             NetworkMapCrypto `json:"crypto"`
}

// NetworkMap is the whole answer.
type NetworkMap struct {
	Segments []NetworkMapSegment `json:"segments"`
	Assets   []NetworkMapAsset   `json:"assets"`
	// TotalAssets is counted INDEPENDENTLY of the capped list, so a truncated
	// map says how much it is not showing.
	TotalAssets int  `json:"total_assets"`
	Truncated   bool `json:"truncated"`
	AssetCap    int  `json:"asset_cap"`
}

// networkMapAssetRow is one asset as the capped query returns it.
type networkMapAssetRow struct {
	AssetID      uuid.UUID  `db:"asset_id"`
	DisplayName  string     `db:"display_name"`
	ClassKey     string     `db:"class_key"`
	Address      *string    `db:"address"`
	SegmentID    *uuid.UUID `db:"segment_id"`
	Site         string     `db:"site"`
	AssetStatus  string     `db:"asset_status"`
	RiskScore    int        `db:"risk_score"`
	RiskAssessed bool       `db:"risk_assessed"`
}

// networkMapServiceRow is one asset's endpoint counts.
type networkMapServiceRow struct {
	AssetID            uuid.UUID `db:"asset_id"`
	ServiceCount       int       `db:"service_count"`
	CryptoServiceCount int       `db:"crypto_service_count"`
}

// networkMapComponentRow is one (asset, component) pair from the grouped read.
type networkMapComponentRow struct {
	AssetID uuid.UUID `db:"asset_id"`
	NetworkMapComponent
}

// networkMapPQCRow is one asset's PQC partition.
type networkMapPQCRow struct {
	AssetID uuid.UUID `db:"asset_id"`
	NetworkMapPQC
}

// networkMapCertRow is one asset's expiring-certificate count.
type networkMapCertRow struct {
	AssetID          uuid.UUID `db:"asset_id"`
	CertsExpiring90d int       `db:"certs_expiring_90d"`
}

// networkMapAggregates is everything the per-asset reads return, for the pure
// merge.
type networkMapAggregates struct {
	Services   []networkMapServiceRow
	Components []networkMapComponentRow
	PQC        []networkMapPQCRow
	Certs      []networkMapCertRow
	// Unbound holds the assets carrying live configurations that no LIVE
	// endpoint accounts for (no endpoint, or a closed one). Each such asset
	// gets one extra crypto service: the exploded view shows those
	// configurations as a single "not tied to a service" group, and without it
	// a device whose only crypto is at rest would read as having none.
	Unbound map[uuid.UUID]bool
	Scopes  map[uuid.UUID]assetCloudScope
}

// networkMapAssetWhere is the population the map draws. Shared by the count
// and the capped list, so `total_assets` and `assets` are the same question.
const networkMapAssetWhere = `a.tenant_id = $1 AND a.deleted_at IS NULL AND a.asset_status = ANY($2)`

// networkMapConfigurationsSQL is the PQC classifier's population for the map:
// the LIVE configurations of the capped assets. $1 tenant, $2 asset ids.
//
// Not MonitoredConfigurationsSQL: that one is the tenant-wide denominator and
// is monitoring-only, while the map also draws pending-approval assets (D5),
// and each asset's partition must cover the configurations that asset has.
const networkMapConfigurationsSQL = `
    SELECT ci.id, ci.tenant_id
      FROM crypto_implementations ci
     WHERE ci.tenant_id = $1 AND ci.asset_id = ANY($2) AND ci.deleted_at IS NULL`

// GetNetworkMap returns every live asset placed by site and segment, with a
// crypto summary, plus every active segment — for one tenant.
func (s *AssetService) GetNetworkMap(ctx context.Context, tenantID uuid.UUID) (*NetworkMap, error) {
	return s.getNetworkMap(ctx, tenantID, NetworkMapAssetCap)
}

// getNetworkMap is GetNetworkMap with the cap as a parameter, so the
// integration test can prove truncation without writing 5000 assets.
func (s *AssetService) getNetworkMap(ctx context.Context, tenantID uuid.UUID, assetCap int) (*NetworkMap, error) {
	out := &NetworkMap{
		Segments: []NetworkMapSegment{},
		Assets:   []NetworkMapAsset{},
		AssetCap: assetCap,
	}
	statuses := pq.Array(networkMapStatuses)

	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// Every ACTIVE segment, including ones no returned asset sits in, so an
		// empty network is drawn as empty rather than missing.
		if err := tx.SelectContext(ctx, &out.Segments, `
			SELECT ns.id AS segment_id, ns.name, ns.value, ns.segment_type
			  FROM network_segments ns
			 WHERE ns.tenant_id = $1 AND ns.is_active = true
			 ORDER BY ns.name ASC, ns.id ASC`, tenantID); err != nil {
			return fmt.Errorf("network map segments: %w", err)
		}
		if out.Segments == nil {
			out.Segments = []NetworkMapSegment{}
		}

		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM assets a WHERE `+networkMapAssetWhere,
			tenantID, statuses).Scan(&out.TotalAssets); err != nil {
			return fmt.Errorf("network map total: %w", err)
		}

		var rows []networkMapAssetRow
		// ORDER BY ends in the id so the ordering is TOTAL: risk and name tie
		// constantly, and LIMIT over a partial ordering picks a different
		// subset per run.
		if err := tx.SelectContext(ctx, &rows, `
			SELECT a.id                                                AS asset_id,
			       COALESCE(NULLIF(a.display_name, ''), NULLIF(a.hostname, ''),
			                host(a.primary_address), '')               AS display_name,
			       a.class_key,
			       host(a.primary_address)                             AS address,
			       a.network_segment_id                                AS segment_id,
			       `+topologySiteSQL+`                                 AS site,
			       a.asset_status,
			       COALESCE(a.risk_score, 0)                           AS risk_score,
			       COALESCE(cardinality(a.risk_assessed_by), 0) > 0    AS risk_assessed
			  FROM assets a
			 WHERE `+networkMapAssetWhere+`
			 ORDER BY risk_score DESC, display_name ASC, a.id ASC
			 LIMIT $3`, tenantID, statuses, assetCap); err != nil {
			return fmt.Errorf("network map assets: %w", err)
		}
		out.Truncated = out.TotalAssets > len(rows)
		if len(rows) == 0 {
			return nil
		}

		ids := make([]uuid.UUID, len(rows))
		for i, r := range rows {
			ids[i] = r.AssetID
		}
		agg, err := readNetworkMapAggregates(ctx, tx, tenantID, ids)
		if err != nil {
			return err
		}
		out.Assets = assembleNetworkMapAssets(rows, agg)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readNetworkMapAggregates runs the per-asset reads SET-BASED over the capped
// ids — a fixed number of grouped queries however many assets, never one per
// asset.
func readNetworkMapAggregates(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) (networkMapAggregates, error) {
	var agg networkMapAggregates
	idArr := pq.Array(ids)

	// Live endpoints: `status <> 'closed'`, the convention the drift, hygiene
	// and configuration producers use. `closed` is a host's authoritative "this
	// socket is gone"; `stale` only means nobody has looked for a while, and
	// dropping those would shrink a device's service count because a collector
	// went quiet. asset_endpoints is hash-partitioned by tenant, so every
	// predicate carries tenant_id.
	if err := tx.SelectContext(ctx, &agg.Services, `
		SELECT e.asset_id,
		       count(*) AS service_count,
		       count(*) FILTER (WHERE EXISTS (
		           SELECT 1 FROM crypto_implementations ci
		            WHERE ci.tenant_id = e.tenant_id
		              AND ci.endpoint_id = e.id
		              AND ci.deleted_at IS NULL)) AS crypto_service_count
		  FROM asset_endpoints e
		 WHERE e.tenant_id = $1
		   AND e.asset_id = ANY($2)
		   AND e.status <> 'closed'
		 GROUP BY e.asset_id`, tenantID, idArr); err != nil {
		return agg, fmt.Errorf("network map services: %w", err)
	}

	var unbound []uuid.UUID
	if err := tx.SelectContext(ctx, &unbound, `
		SELECT DISTINCT ci.asset_id
		  FROM crypto_implementations ci
		 WHERE ci.tenant_id = $1
		   AND ci.asset_id = ANY($2)
		   AND ci.deleted_at IS NULL
		   AND NOT EXISTS (
		       SELECT 1 FROM asset_endpoints e
		        WHERE e.tenant_id = ci.tenant_id
		          AND e.id = ci.endpoint_id
		          AND e.status <> 'closed')`, tenantID, idArr); err != nil {
		return agg, fmt.Errorf("network map unbound crypto: %w", err)
	}
	agg.Unbound = make(map[uuid.UUID]bool, len(unbound))
	for _, id := range unbound {
		agg.Unbound[id] = true
	}

	// Catalogue components across every LIVE configuration on the asset,
	// endpoint-bound or not (an at-rest cloud resource has none). Column
	// handling mirrors componentAssessmentsQuery: strength '' when absent,
	// is_pqc false when absent, is_inferred NULL read as not inferred. The
	// junction has no tenant_id or RLS of its own; the join through
	// crypto_implementations (RLS + explicit tenant predicate) is the boundary.
	if err := tx.SelectContext(ctx, &agg.Components, `
		SELECT ci.asset_id,
		       cia.algorithm_type::text                          AS algorithm_type,
		       al.name::text                                     AS name,
		       COALESCE(al.strength::text, '')                   AS strength,
		       COALESCE(al.is_pqc, false)                        AS is_pqc,
		       bool_or(NOT COALESCE(cia.is_inferred, false))     AS observed
		  FROM crypto_implementations ci
		  JOIN crypto_implementation_algorithms cia ON cia.crypto_implementation_id = ci.id
		  JOIN algorithms al ON al.id = cia.algorithm_id
		 WHERE ci.tenant_id = $1
		   AND ci.asset_id = ANY($2)
		   AND ci.deleted_at IS NULL
		 GROUP BY 1, 2, 3, 4, 5`, tenantID, idArr); err != nil {
		return agg, fmt.Errorf("network map components: %w", err)
	}

	// The PQC partition: the one classifier, grouped per asset by joining
	// impl_class back to its configuration.
	if err := tx.SelectContext(ctx, &agg.PQC, `
		WITH `+cryptoassess.PQCClassCTE(networkMapConfigurationsSQL, "$3", "$4")+`
		SELECT ci.asset_id,
		       `+pqcPartitionSQL+`
		  FROM impl_class
		  JOIN crypto_implementations ci ON ci.id = impl_class.impl_id AND ci.tenant_id = $1
		 GROUP BY ci.asset_id`,
		tenantID, idArr, pq.Array(pqcComponentRoles), pq.Array(quantumVulnerablePrimitives)); err != nil {
		return agg, fmt.Errorf("network map pqc: %w", err)
	}

	// Certificates: the configuration's leaf. `certificates` is not
	// soft-deleted, so there is no deleted_at to filter.
	if err := tx.SelectContext(ctx, &agg.Certs, `
		SELECT ci.asset_id,
		       count(DISTINCT c.id) AS certs_expiring_90d
		  FROM crypto_implementations ci
		  JOIN certificates c ON c.id = ci.certificate_id AND c.tenant_id = ci.tenant_id
		 WHERE ci.tenant_id = $1
		   AND ci.asset_id = ANY($2)
		   AND ci.deleted_at IS NULL
		   AND c.not_after < now() + interval '90 days'
		 GROUP BY ci.asset_id`, tenantID, idArr); err != nil {
		return agg, fmt.Errorf("network map certificates: %w", err)
	}

	scopes, err := loadCloudScopes(ctx, tx, tenantID, ids)
	if err != nil {
		return agg, err
	}
	agg.Scopes = scopes
	return agg, nil
}

// assembleNetworkMapAssets merges the per-asset aggregates onto the capped rows,
// preserving the query's order.
//
// Pure, so the merge is unit-testable: an asset with no endpoints or no crypto
// must still come out with zero counts and an EMPTY (not null) component list,
// and an aggregate row for an asset outside the capped set must not add one.
func assembleNetworkMapAssets(rows []networkMapAssetRow, agg networkMapAggregates) []NetworkMapAsset {
	svcBy := make(map[uuid.UUID]networkMapServiceRow, len(agg.Services))
	for _, s := range agg.Services {
		svcBy[s.AssetID] = s
	}
	compBy := make(map[uuid.UUID][]NetworkMapComponent)
	for _, c := range agg.Components {
		compBy[c.AssetID] = append(compBy[c.AssetID], c.NetworkMapComponent)
	}
	pqcBy := make(map[uuid.UUID]NetworkMapPQC, len(agg.PQC))
	for _, p := range agg.PQC {
		pqcBy[p.AssetID] = p.NetworkMapPQC
	}
	certBy := make(map[uuid.UUID]int, len(agg.Certs))
	for _, c := range agg.Certs {
		certBy[c.AssetID] = c.CertsExpiring90d
	}

	out := make([]NetworkMapAsset, 0, len(rows))
	for _, r := range rows {
		a := NetworkMapAsset{
			AssetID:      r.AssetID,
			DisplayName:  r.DisplayName,
			ClassKey:     r.ClassKey,
			SegmentID:    r.SegmentID,
			Site:         r.Site,
			AssetStatus:  r.AssetStatus,
			RiskScore:    r.RiskScore,
			RiskAssessed: r.RiskAssessed,
			Crypto: NetworkMapCrypto{
				Components:       sortNetworkMapComponents(compBy[r.AssetID]),
				PQC:              pqcBy[r.AssetID],
				CertsExpiring90d: certBy[r.AssetID],
			},
		}
		if r.Address != nil {
			a.Address = *r.Address
		}
		if sc, ok := agg.Scopes[r.AssetID]; ok {
			a.CloudAccount = sc.AccountID
			a.CloudRegion = sc.Region
		}
		if s, ok := svcBy[r.AssetID]; ok {
			a.ServiceCount = s.ServiceCount
			a.CryptoServiceCount = s.CryptoServiceCount
		}
		if agg.Unbound[r.AssetID] {
			a.CryptoServiceCount++
		}
		out = append(out, a)
	}
	return out
}

// sortNetworkMapComponents returns a non-nil copy sorted by algorithm_type,
// then name, then the remaining fields so the order is TOTAL. Sorted here
// rather than in SQL so the wire order is bytewise and does not follow the
// database collation.
func sortNetworkMapComponents(in []NetworkMapComponent) []NetworkMapComponent {
	out := make([]NetworkMapComponent, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.AlgorithmType != b.AlgorithmType {
			return a.AlgorithmType < b.AlgorithmType
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Strength != b.Strength {
			return a.Strength < b.Strength
		}
		if a.IsPQC != b.IsPQC {
			return !a.IsPQC
		}
		return !a.Observed && b.Observed
	})
	return out
}
